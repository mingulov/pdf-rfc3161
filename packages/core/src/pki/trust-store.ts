import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { TimestampError, TimestampErrorCode } from "../types.js";
import { toArrayBuffer } from "../utils.js";
import { snapshotDateMs } from "../utils/date.js";

/**
 * Parses DER-encoded certificate bytes, returning undefined when they do
 * not decode: truncated framing, undecodable content such as corrupted
 * GeneralizedTime (asn1js throws a plain Error), or schema mismatch
 * (pkijs throws a plain Error). Callers map undefined to the coded
 * error for their input kind; BER acceptance of the framing itself is
 * unchanged (see the boundary pins in trust-store.test.ts).
 */
function parseTrustStoreCertificate(bytes: Uint8Array): pkijs.Certificate | undefined {
    try {
        const asn1 = asn1js.fromBER(toArrayBuffer(bytes));
        if (asn1.offset !== bytes.length) return undefined;
        return new pkijs.Certificate({ schema: asn1.result });
    } catch {
        return undefined;
    }
}

/**
 * Trust Store for Certificate Chain Validation
 *
 * This module provides TrustStore and SimpleTrustStore for certificate chain validation.
 *
 * NOTE: chain validation is caller-owned trust policy, not a default. RFC 3161
 * timestamp verification without a trust store checks cryptographic integrity of the
 * timestamp token itself, not the TSA's certificate chain. (The TLS connection
 * to a TSA authenticates only the endpoint's TLS certificate; it says nothing
 * about the token signer's chain.)
 * 1. Trust validation requirements vary significantly between jurisdictions (e.g., eIDAS, FIPS)
 * 2. Users may have custom trust requirements (private PKI, specific CAs, etc.)
 *
 * If you need chain validation, you can:
 * 1. Use the TrustStore API directly: `trustStore.verifyChain(chain)`
 * 2. Pass a TrustStore to verifyTimestamp()/verifyPdfTimestamps() options
 * 3. Implement custom validation logic using pkijs
 *
 * `verifyChain` verifies `chain[0]`; every other entry is an untrusted
 * path-building candidate. Callers must place the selected signer first.
 *
 * Example usage:
 * ```typescript
 * import { SimpleTrustStore } from "./pki/trust-store.js";
 *
 * const trustStore = new SimpleTrustStore();
 * trustStore.addCertificate( rootCaCert );
 *
 * // Use for custom validation: verifies certChain[0], others are candidates
 * const isTrusted = await trustStore.verifyChain(certChain);
 * ```
 */

/**
 * interface for a store of trusted certificates
 */
export interface TrustStore {
    /**
     * Adds a trusted certificate to the store
     * @param cert DER-encoded certificate or pkijs.Certificate object
     */
    addCertificate(cert: Uint8Array | pkijs.Certificate): void;

    /**
     * Verifies that the first certificate chains back to a trusted root.
     *
     * First-certificate target semantics: `chain[0]` is the verified trust
     * target and every other entry is an untrusted path-building candidate,
     * never an additional trusted root. Candidate order and duplicates
     * cannot change the verdict for a fixed target. An empty store verifies
     * nothing.
     *
     * @param chain List of certificates (DER-encoded or pkijs.Certificate objects)
     * @returns True if `chain[0]` chains back to a trusted root
     */
    verifyChain(chain: (Uint8Array | pkijs.Certificate)[]): Promise<boolean>;

    /**
     * Verifies `chain[0]` as of `checkDate` (same target semantics as
     * `verifyChain`). Optional capability: stores without it stay valid
     * for current-time calls, while explicit historical requests against
     * them fail instead of silently validating at the wrong date.
     * Historical path trust alone establishes neither historical
     * revocation nor archival qualification. `checkDate` must be finite.
     *
     * @param chain List of certificates (DER-encoded or pkijs.Certificate objects)
     * @param checkDate Moment the path must have been valid at
     * @returns True if `chain[0]` chained back to a trusted root then
     */
    verifyChainAtTime?(
        chain: (Uint8Array | pkijs.Certificate)[],
        checkDate: Date
    ): Promise<boolean>;
}

/**
 * Compares two byte strings for exact equality.
 */
function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
    if (left.length !== right.length) return false;
    for (let index = 0; index < left.length; index++) {
        if (left[index] !== right[index]) return false;
    }
    return true;
}

/**
 * A certificate with the encodings this adapter compares, computed once.
 *
 * Target identity is bound by exact DER bytes, while pkijs conflates engine
 * inputs by TBS bytes when it deduplicates. Both views are precomputed per
 * call so comparisons never re-encode.
 */
interface PreparedCertificate {
    cert: pkijs.Certificate;
    der: Uint8Array;
    tbs: Uint8Array;
}

function prepareCertificate(cert: pkijs.Certificate): PreparedCertificate {
    return {
        cert,
        der: new Uint8Array(cert.toSchema().toBER(false)),
        tbs:
            cert.tbsView.length > 0
                ? cert.tbsView
                : new Uint8Array(cert.encodeTBS().toBER()),
    };
}

/**
 * A simple in-memory implementation of a Trust Store
 */
export class SimpleTrustStore implements TrustStore {
    private trustedCerts: pkijs.Certificate[] = [];

    /**
     * Adds a trusted certificate (e.g. Root CA) to the store
     * @param cert DER-encoded certificate or pkijs.Certificate
     */
    addCertificate(cert: Uint8Array | pkijs.Certificate): void {
        if (cert instanceof pkijs.Certificate) {
            this.trustedCerts.push(cert);
        } else {
            const parsed = parseTrustStoreCertificate(cert);
            if (!parsed) {
                throw new TimestampError(
                    TimestampErrorCode.INVALID_RESPONSE,
                    "Failed to parse trusted certificate"
                );
            }
            this.trustedCerts.push(parsed);
        }
    }

    /**
     * Verifies that `chain[0]` chains back to a trusted root using pkijs.
     *
     * The pkijs path engine selects its own leaf (the last local
     * certificate), so the adapter reorders and deduplicates the engine
     * input internally without changing the public caller order, then
     * checks that the returned path begins with the intended target.
     * Verdict time is captured once per call; the engine takes one more discarded reading.
     */
    async verifyChain(chain: (Uint8Array | pkijs.Certificate)[]): Promise<boolean> {
        return this.verifyChainAtTime(chain, new Date());
    }

    /**
     * Verifies that `chain[0]` chained back to a trusted root as of
     * `checkDate`. Same target binding as `verifyChain`; the verdict
     * follows only `checkDate` (the engine takes one discarded reading).
     */
    async verifyChainAtTime(
        chain: (Uint8Array | pkijs.Certificate)[],
        checkDate: Date
    ): Promise<boolean> {
        // Snapshot before any await: the caller keeps the reference.
        const checkMs = snapshotDateMs(checkDate);
        if (!Number.isFinite(checkMs)) {
            throw new TimestampError(
                TimestampErrorCode.INVALID_ARGUMENT,
                "verifyChainAtTime checkDate must be a finite date"
            );
        }
        if (chain.length === 0) return false;
        if (this.trustedCerts.length === 0) return false;

        // Convert input chain to pkijs.Certificate objects
        const certChain = chain.map((c) => {
            if (c instanceof pkijs.Certificate) return c;
            const parsed = parseTrustStoreCertificate(c);
            if (!parsed) {
                throw new TimestampError(
                    TimestampErrorCode.INVALID_RESPONSE,
                    "Failed to parse chain certificate"
                );
            }
            return parsed;
        });

        // Encode each input once; every step below reuses these views.
        const preparedChain = certChain.map((cert) => prepareCertificate(cert));
        const preparedAnchors = this.trustedCerts.map((cert) => prepareCertificate(cert));

        // Deduplicate by exact DER bytes, keeping the caller's first
        // occurrence: chain[0] is the verified target and must survive.
        const uniqueChain = preparedChain.filter(
            (candidate, index) =>
                preparedChain.findIndex((other) => bytesEqual(candidate.der, other.der)) ===
                index
        );
        const target = uniqueChain[0];
        if (target === undefined) return false;

        // Exclude candidate aliases the engine would conflate with the
        // target: pkijs deduplicates by TBS bytes and could otherwise drop
        // the caller's exact target in favor of a different signature over
        // the same TBS. The target object itself is always retained.
        const candidates = uniqueChain
            .slice(1)
            .filter((candidate) => !bytesEqual(candidate.tbs, target.tbs));

        // Place the target last: pkijs builds its path from the last local
        // certificate, while every other entry stays an untrusted candidate.
        // A self-signed target that is itself a pinned anchor needs no
        // intermediates; narrowing the engine to the matching anchor keeps
        // pkijs from leafing on an unrelated candidate or a different
        // anchor. Any other pinned target keeps its issuer anchors so an
        // explicitly trusted intermediate still chains to its root.
        const matchingAnchors = preparedAnchors.filter((anchor) =>
            bytesEqual(anchor.der, target.der)
        );
        const selfSigned = target.cert.subject.isEqual(target.cert.issuer);
        let engineCerts: pkijs.Certificate[];
        let engineAnchors: pkijs.Certificate[];
        if (matchingAnchors.length > 0 && selfSigned) {
            engineCerts = [target.cert];
            engineAnchors = matchingAnchors.map((anchor) => anchor.cert);
        } else {
            engineCerts = [...candidates.map((candidate) => candidate.cert), target.cert];
            engineAnchors =
                matchingAnchors.length > 0
                    ? preparedAnchors
                          .filter((anchor) => !bytesEqual(anchor.tbs, target.tbs))
                          .map((anchor) => anchor.cert)
                    : preparedAnchors.map((anchor) => anchor.cert);
            if (engineAnchors.length === 0) return false;
        }

        // Use pkijs CertificateChainValidationEngine
        const chainEngine = new pkijs.CertificateChainValidationEngine({
            trustedCerts: engineAnchors,
            certs: engineCerts,
            crls: [], // CRLs not supported in simple verify yet
            checkDate: new Date(checkMs),
        });

        // Verify the chain
        const result = await chainEngine.verify();
        if (!result.result) return false;

        // Bind the verdict to the intended target: the returned path must
        // begin with chain[0]. Without this check an unrelated trusted
        // intermediate from the bag could verify in the signer's place.
        const leaf = result.certificatePath?.[0];
        if (leaf === undefined) return false;
        const leafDer = new Uint8Array(leaf.toSchema().toBER(false));
        return bytesEqual(leafDer, target.der);
    }
}
