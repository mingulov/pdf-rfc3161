import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { TimestampError, TimestampErrorCode } from "../types.js";

/**
 * Trust Store for Certificate Chain Validation
 *
 * This module provides TrustStore and SimpleTrustStore for certificate chain validation.
 *
 * NOTE: TrustStore is NOT currently integrated into the core timestamp verification flow.
 * This is a design choice - RFC 3161 timestamps focus on cryptographic integrity of the
 * timestamp token itself, not on validating the TSA's certificate chain.
 *
 * Reasons for this design:
 * 1. TSA certificates are typically validated by the TLS connection to the TSA
 * 2. Trust validation requirements vary significantly between jurisdictions (e.g., eIDAS, FIPS)
 * 3. Users may have custom trust requirements (private PKI, specific CAs, etc.)
 * 4. Adding trust validation would require a trust store configuration mechanism
 *
 * If you need chain validation, you can:
 * 1. Use the TrustStore API directly: `trustStore.verifyChain(chain)`
 * 2. Pass a TrustStore to verifyTimestamp() options if you modify the API
 * 3. Implement custom validation logic using pkijs
 *
 * Example usage:
 * ```typescript
 * import { SimpleTrustStore } from "./pki/trust-store.js";
 *
 * const trustStore = new SimpleTrustStore();
 * trustStore.addCertificate( rootCaCert );
 *
 * // Use for custom validation
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
     * Verifies that a certificate chain chains back to a trusted root
     * @param chain List of certificates (DER-encoded or pkijs.Certificate objects)
     * @returns True if the chain is trusted
     */
    verifyChain(chain: (Uint8Array | pkijs.Certificate)[]): Promise<boolean>;
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
            const asn1 = asn1js.fromBER(cert.slice().buffer);
            if (asn1.offset === -1) {
                throw new TimestampError(
                    TimestampErrorCode.INVALID_RESPONSE,
                    "Failed to parse trusted certificate"
                );
            }
            this.trustedCerts.push(new pkijs.Certificate({ schema: asn1.result }));
        }
    }

    /**
     * Verifies a certificate chain validation using pkijs
     */
    async verifyChain(chain: (Uint8Array | pkijs.Certificate)[]): Promise<boolean> {
        if (chain.length === 0) return false;

        // Convert input chain to pkijs.Certificate objects
        const certChain = chain.map((c) => {
            if (c instanceof pkijs.Certificate) return c;
            const asn1 = asn1js.fromBER(c.slice().buffer);
            return new pkijs.Certificate({ schema: asn1.result });
        });

        // Use pkijs CertificateChainValidationEngine
        const chainEngine = new pkijs.CertificateChainValidationEngine({
            trustedCerts: this.trustedCerts,
            certs: [...certChain], // All certs in the potential chain
            crls: [], // CRLs not supported in simple verify yet
        });

        // Verify the chain
        const result = await chainEngine.verify();

        return result.result;
    }
}
