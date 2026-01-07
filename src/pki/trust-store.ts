import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { TimestampError, TimestampErrorCode } from "../types.js";

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
