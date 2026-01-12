import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { HASH_ALGORITHM_TO_OID } from "../constants.js";
import { type HashAlgorithm, type TSAConfig } from "../types.js";

// Polyfill for Node.js environments (e.g. tests) where globalThis.crypto might be missing
if (typeof globalThis.crypto === "undefined") {
    try {
        const nodeCrypto = (require as unknown as (id: string) => { webcrypto?: Crypto })(
            "node:crypto"
        );
        if (nodeCrypto.webcrypto) {
            globalThis.crypto = nodeCrypto.webcrypto;
        }
    } catch {
        // Ignore if require or node:crypto is not available (e.g. in browser/worker)
    }
}

/**
 * Creates an RFC 3161 TimeStampReq for the given data.
 *
 * @param data - The data to be timestamped (will be hashed)
 * @param config - TSA configuration
 * @returns The DER-encoded TimeStampReq
 */
export async function createTimestampRequest(
    data: Uint8Array,
    config: Omit<TSAConfig, "url"> & { url?: string }
): Promise<Uint8Array> {
    const hashAlgorithm: HashAlgorithm = config.hashAlgorithm ?? "SHA-256";

    // Hash the data using Web Crypto API (edge-compatible)
    // Use slice() to get a proper ArrayBuffer from Uint8Array
    const hashBuffer = await crypto.subtle.digest(hashAlgorithm, data.slice().buffer);

    // Generate random nonce for replay protection
    const nonce = new Uint8Array(8);
    crypto.getRandomValues(nonce);

    // Get OID for the hash algorithm
    const algorithmOID = HASH_ALGORITHM_TO_OID[hashAlgorithm];
    if (!algorithmOID) {
        throw new Error(`Unsupported hash algorithm: ${hashAlgorithm} `);
    }

    // Create MessageImprint structure
    const messageImprint = new pkijs.MessageImprint({
        hashAlgorithm: new pkijs.AlgorithmIdentifier({
            algorithmId: algorithmOID,
        }),
        hashedMessage: new asn1js.OctetString({ valueHex: hashBuffer }),
    });

    // Build the TimeStampReq
    const tsReq = new pkijs.TimeStampReq({
        version: 1,
        messageImprint,
        certReq: config.requestCertificate ?? true,
        nonce: new asn1js.Integer({ valueHex: nonce.slice().buffer }),
    });

    // Add policy OID if specified
    if (config.policy) {
        tsReq.reqPolicy = config.policy;
    }

    // Encode to DER
    const schema = tsReq.toSchema();
    const berBuffer = schema.toBER(false);

    return new Uint8Array(berBuffer);
}

/**
 * Creates a TimeStampReq for a pre-computed hash.
 * Useful when the caller has already hashed the data.
 *
 * @param hash - The pre-computed hash
 * @param hashAlgorithm - The algorithm used to compute the hash
 * @param config - TSA configuration (hashAlgorithm in config is ignored)
 * @returns The DER-encoded TimeStampReq
 */
export function createTimestampRequestFromHash(
    hash: Uint8Array,
    hashAlgorithm: HashAlgorithm,
    config: Omit<TSAConfig, "hashAlgorithm">
): Uint8Array {
    // Generate random nonce for replay protection
    const nonce = new Uint8Array(8);
    crypto.getRandomValues(nonce);

    // Get OID for the hash algorithm
    const algorithmOID = HASH_ALGORITHM_TO_OID[hashAlgorithm];
    if (!algorithmOID) {
        throw new Error(`Unsupported hash algorithm: ${hashAlgorithm} `);
    }

    // Create MessageImprint structure
    const messageImprint = new pkijs.MessageImprint({
        hashAlgorithm: new pkijs.AlgorithmIdentifier({
            algorithmId: algorithmOID,
        }),
        hashedMessage: new asn1js.OctetString({ valueHex: hash.slice().buffer }),
    });

    // Build the TimeStampReq
    const tsReq = new pkijs.TimeStampReq({
        version: 1,
        messageImprint,
        certReq: config.requestCertificate ?? true,
        nonce: new asn1js.Integer({ valueHex: nonce.slice().buffer }),
    });

    // Add policy OID if specified
    if (config.policy) {
        tsReq.reqPolicy = config.policy;
    }

    // Encode to DER
    const schema = tsReq.toSchema();
    const berBuffer = schema.toBER(false);

    return new Uint8Array(berBuffer);
}
