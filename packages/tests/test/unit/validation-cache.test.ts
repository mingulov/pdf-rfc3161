import { describe, expect, it, vi } from "vitest";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { InMemoryValidationCache } from "../../../core/src/pki/fetchers/memory-cache.js";
import { ValidationSession } from "../../../core/src/pki/validation-session.js";
import { createOCSPRequest } from "../../../core/src/pki/ocsp-utils.js";
import type {
    RevocationDataFetcher,
    ValidationCache,
} from "../../../core/src/pki/validation-types.js";
import { toArrayBuffer } from "../../../core/src/utils.js";
import { generateRSAKeyPair, importKeyForCertificate } from "../utils/crypto.js";
import { createCrlFixture, createOcspResponseCandidate } from "../fixtures/revocation-material.js";

// T05: the validation cache uses exact byte identity (full request bytes
// scoped by exact URL), copies bytes on insertion and retrieval, and honors
// retention/entry/byte limits. The session revalidates cached bytes on use
// and refetches once after rejecting stale or poisoned entries.

const OCSP_URL = "http://ocsp.example.com/";
const CRL_URL = "http://crl.example.com/ca.crl";

function roundTripCertificate(cert: pkijs.Certificate): pkijs.Certificate {
    const der = new Uint8Array(cert.toSchema(true).toBER(false));
    const asn1 = asn1js.fromBER(toArrayBuffer(der));
    if (asn1.offset === -1) throw new Error("test certificate is not DER");
    return new pkijs.Certificate({ schema: asn1.result });
}

function distinguishedName(commonName: string): pkijs.RelativeDistinguishedNames {
    const name = new pkijs.RelativeDistinguishedNames();
    name.typesAndValues.push(
        new pkijs.AttributeTypeAndValue({
            type: "2.5.4.3",
            value: new asn1js.PrintableString({ value: commonName }),
        })
    );
    return name;
}

async function createSignedPair(options: {
    ocspUrl?: string;
    crlUrl?: string;
}): Promise<{ leaf: pkijs.Certificate; issuer: pkijs.Certificate }> {
    const issuerKeys = await generateRSAKeyPair();
    const leafKeys = await generateRSAKeyPair();

    const issuer = new pkijs.Certificate();
    issuer.version = 2;
    issuer.serialNumber = new asn1js.Integer({ value: 7001 });
    issuer.subject = distinguishedName("Cache Test CA");
    issuer.issuer = distinguishedName("Cache Test CA");
    issuer.subjectPublicKeyInfo = await importKeyForCertificate(issuerKeys.publicKey);
    await issuer.sign(issuerKeys.privateKey, "SHA-256");

    const leaf = new pkijs.Certificate();
    leaf.version = 2;
    leaf.serialNumber = new asn1js.Integer({ value: 7002 });
    leaf.subject = distinguishedName("Cache Test Leaf");
    leaf.issuer = issuer.subject;
    leaf.subjectPublicKeyInfo = await importKeyForCertificate(leafKeys.publicKey);
    const extensions: pkijs.Extension[] = [];
    if (options.ocspUrl) {
        const aia = new pkijs.InfoAccess({
            accessDescriptions: [
                new pkijs.AccessDescription({
                    accessMethod: "1.3.6.1.5.5.7.48.1",
                    accessLocation: new pkijs.GeneralName({ type: 6, value: options.ocspUrl }),
                }),
            ],
        });
        extensions.push(
            new pkijs.Extension({
                extnID: "1.3.6.1.5.5.7.1.1",
                critical: false,
                extnValue: aia.toSchema().toBER(false),
            })
        );
    }
    if (options.crlUrl) {
        const cdp = new pkijs.CRLDistributionPoints({
            distributionPoints: [
                new pkijs.DistributionPoint({
                    distributionPoint: [new pkijs.GeneralName({ type: 6, value: options.crlUrl })],
                }),
            ],
        });
        extensions.push(
            new pkijs.Extension({
                extnID: "2.5.29.31",
                critical: false,
                extnValue: cdp.toSchema().toBER(false),
            })
        );
    }
    if (extensions.length > 0) {
        leaf.extensions = extensions;
    }
    await leaf.sign(issuerKeys.privateKey, "SHA-256");

    return { leaf: roundTripCertificate(leaf), issuer: roundTripCertificate(issuer) };
}

function recordingFetcher(responses: {
    ocsp?: Uint8Array;
    crl?: Uint8Array;
}): RevocationDataFetcher & { ocspCalls: number; crlCalls: number } {
    const fetcher: RevocationDataFetcher & { ocspCalls: number; crlCalls: number } = {
        ocspCalls: 0,
        crlCalls: 0,
        fetchOCSP: (_url: string) => {
            fetcher.ocspCalls += 1;
            if (!responses.ocsp) return Promise.reject(new Error("no OCSP response"));
            return Promise.resolve(responses.ocsp);
        },
        fetchCRL: (_url: string) => {
            fetcher.crlCalls += 1;
            if (!responses.crl) return Promise.reject(new Error("no CRL response"));
            return Promise.resolve(responses.crl);
        },
    };
    return fetcher;
}

describe("InMemoryValidationCache byte identity (T05)", () => {
    it("hits for a new array with equal OCSP request bytes", () => {
        const cache = new InMemoryValidationCache();
        const request = new Uint8Array([0x30, 0x82, 0x01, 0x00, 0x99]);
        const response = new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x05]);
        cache.setOCSP(OCSP_URL, request, response);
        expect(cache.getOCSP(OCSP_URL, new Uint8Array(request))).toEqual(response);
    });

    it("misses when requests share a prefix but differ in the tail", () => {
        const cache = new InMemoryValidationCache();
        const requestA = new Uint8Array(64).fill(0x30);
        const requestB = new Uint8Array(requestA);
        requestB[63] = 0x31;
        cache.setOCSP(OCSP_URL, requestA, new Uint8Array([1]));
        expect(cache.getOCSP(OCSP_URL, requestB)).toBeNull();
        expect(cache.getOCSP(OCSP_URL, new Uint8Array(requestA))).toEqual(new Uint8Array([1]));
    });

    it("misses when one request is a strict prefix of the other", () => {
        const cache = new InMemoryValidationCache();
        const short = new Uint8Array(32).fill(0x30);
        const long = new Uint8Array([...short, 0x31]);
        cache.setOCSP(OCSP_URL, short, new Uint8Array([1]));
        expect(cache.getOCSP(OCSP_URL, long)).toBeNull();
        cache.setOCSP(OCSP_URL, long, new Uint8Array([2]));
        expect(cache.getOCSP(OCSP_URL, new Uint8Array(short))).toEqual(new Uint8Array([1]));
        expect(cache.getOCSP(OCSP_URL, new Uint8Array(long))).toEqual(new Uint8Array([2]));
    });

    it("separates entries by exact URL", () => {
        const cache = new InMemoryValidationCache();
        const otherUrl = "http://ocsp.example.com/other";
        cache.setOCSP(OCSP_URL, new Uint8Array([1, 2, 3]), new Uint8Array([4]));
        expect(cache.getOCSP(otherUrl, new Uint8Array([1, 2, 3]))).toBeNull();
        expect(cache.getOCSP(OCSP_URL, new Uint8Array([1, 2, 3]))).toEqual(new Uint8Array([4]));

        cache.setCRL(CRL_URL, new Uint8Array([5]));
        expect(cache.getCRL("http://crl.example.com/other.crl")).toBeNull();
        expect(cache.getCRL(CRL_URL)).toEqual(new Uint8Array([5]));
    });

    it("keeps OCSP and CRL entries in separate namespaces", () => {
        const cache = new InMemoryValidationCache();
        cache.setOCSP(OCSP_URL, new Uint8Array([1]), new Uint8Array([2]));
        expect(cache.getCRL(OCSP_URL)).toBeNull();
        cache.setCRL(CRL_URL, new Uint8Array([3]));
        expect(cache.getOCSP(CRL_URL, new Uint8Array([1]))).toBeNull();
    });

    it("copies OCSP bytes on insertion", () => {
        const cache = new InMemoryValidationCache();
        const request = new Uint8Array([1, 2, 3]);
        const response = new Uint8Array([4, 5, 6]);
        cache.setOCSP(OCSP_URL, request, response);
        request[0] = 0x09;
        response[0] = 0x09;
        expect(cache.getOCSP(OCSP_URL, new Uint8Array([1, 2, 3]))).toEqual(
            new Uint8Array([4, 5, 6])
        );
    });

    it("copies CRL bytes on insertion", () => {
        const cache = new InMemoryValidationCache();
        const response = new Uint8Array([7, 8, 9]);
        cache.setCRL(CRL_URL, response);
        response[0] = 0x09;
        expect(cache.getCRL(CRL_URL)).toEqual(new Uint8Array([7, 8, 9]));
    });

    it("copies bytes on retrieval", () => {
        const cache = new InMemoryValidationCache();
        cache.setOCSP(OCSP_URL, new Uint8Array([1]), new Uint8Array([4, 5, 6]));
        const first = cache.getOCSP(OCSP_URL, new Uint8Array([1]));
        expect(first).toEqual(new Uint8Array([4, 5, 6]));
        if (first) first[0] = 0x09;
        expect(cache.getOCSP(OCSP_URL, new Uint8Array([1]))).toEqual(new Uint8Array([4, 5, 6]));

        cache.setCRL(CRL_URL, new Uint8Array([7, 8, 9]));
        const crl = cache.getCRL(CRL_URL);
        expect(crl).toEqual(new Uint8Array([7, 8, 9]));
        if (crl) crl[0] = 0x09;
        expect(cache.getCRL(CRL_URL)).toEqual(new Uint8Array([7, 8, 9]));
    });

    it("expires entries immediately when retentionMs is 0", () => {
        const cache = new InMemoryValidationCache({ retentionMs: 0 });
        cache.setOCSP(OCSP_URL, new Uint8Array([1]), new Uint8Array([2]));
        expect(cache.getOCSP(OCSP_URL, new Uint8Array([1]))).toBeNull();
        cache.setCRL(CRL_URL, new Uint8Array([3]));
        expect(cache.getCRL(CRL_URL)).toBeNull();
    });

    it("treats entries older than retentionMs as misses", () => {
        vi.useFakeTimers({ toFake: ["Date", "setTimeout"] });
        try {
            const cache = new InMemoryValidationCache({ retentionMs: 1000 });
            cache.setOCSP(OCSP_URL, new Uint8Array([1]), new Uint8Array([2]));
            vi.advanceTimersByTime(999);
            expect(cache.getOCSP(OCSP_URL, new Uint8Array([1]))).toEqual(new Uint8Array([2]));
            vi.advanceTimersByTime(1);
            expect(cache.getOCSP(OCSP_URL, new Uint8Array([1]))).toBeNull();
        } finally {
            vi.useRealTimers();
        }
    });

    it("evicts the oldest entry beyond maxEntries", () => {
        const cache = new InMemoryValidationCache({ maxEntries: 2 });
        cache.setCRL("http://a.test/", new Uint8Array([1]));
        cache.setCRL("http://b.test/", new Uint8Array([2]));
        cache.setCRL("http://c.test/", new Uint8Array([3]));
        expect(cache.getCRL("http://a.test/")).toBeNull();
        expect(cache.getCRL("http://b.test/")).toEqual(new Uint8Array([2]));
        expect(cache.getCRL("http://c.test/")).toEqual(new Uint8Array([3]));
    });

    it("evicts oldest entries to stay within maxTotalBytes", () => {
        const cache = new InMemoryValidationCache({ maxTotalBytes: 8 });
        cache.setCRL("http://a.test/", new Uint8Array([1, 2, 3, 4]));
        cache.setCRL("http://b.test/", new Uint8Array([5, 6, 7, 8]));
        cache.setCRL("http://c.test/", new Uint8Array([9, 10]));
        expect(cache.getCRL("http://a.test/")).toBeNull();
        expect(cache.getCRL("http://b.test/")).toEqual(new Uint8Array([5, 6, 7, 8]));
        expect(cache.getCRL("http://c.test/")).toEqual(new Uint8Array([9, 10]));
    });

    it("does not cache a single entry larger than maxTotalBytes", () => {
        const cache = new InMemoryValidationCache({ maxTotalBytes: 4 });
        cache.setCRL("http://a.test/", new Uint8Array([1, 2, 3, 4, 5]));
        expect(cache.getCRL("http://a.test/")).toBeNull();
    });

    it("overwrites the same key on repeated set", () => {
        const cache = new InMemoryValidationCache();
        cache.setOCSP(OCSP_URL, new Uint8Array([1]), new Uint8Array([2]));
        cache.setOCSP(OCSP_URL, new Uint8Array([1]), new Uint8Array([3]));
        expect(cache.getOCSP(OCSP_URL, new Uint8Array([1]))).toEqual(new Uint8Array([3]));
    });

    it("keeps get/set/clear synchronous", () => {
        const cache = new InMemoryValidationCache();
        expect(cache.setOCSP(OCSP_URL, new Uint8Array([1]), new Uint8Array([2]))).toBeUndefined();
        expect(cache.getOCSP(OCSP_URL, new Uint8Array([1]))).not.toBeInstanceOf(Promise);
        expect(cache.getCRL("http://missing.test/")).toBeNull();
        expect(cache.setCRL(CRL_URL, new Uint8Array([3]))).toBeUndefined();
        expect(cache.clear()).toBeUndefined();
        expect(cache.getOCSP(OCSP_URL, new Uint8Array([1]))).toBeNull();
        expect(cache.getCRL(CRL_URL)).toBeNull();
    });

    it("misses for same-cert requests differing only in trailing bytes", async () => {
        // Full request bytes are the cache identity, so a fresh random
        // nonce (trailing requestExtensions) normally misses. The current
        // builder does not serialize the nonce yet (R22, owned by T06), so
        // this test simulates the nonce position by flipping the trailing
        // byte of real request bytes.
        const { leaf, issuer } = await createSignedPair({});
        const request = await createOCSPRequest(leaf, issuer);
        expect(request.length).toBeGreaterThan(32);
        const rotated = new Uint8Array(request);
        const last = rotated[rotated.length - 1] ?? 0;
        rotated[rotated.length - 1] = last ^ 0xff;

        const cache = new InMemoryValidationCache();
        const candidate = createOcspResponseCandidate("good");
        cache.setOCSP(OCSP_URL, request, candidate);
        expect(cache.getOCSP(OCSP_URL, rotated)).toBeNull();
        expect(cache.getOCSP(OCSP_URL, request.slice())).toEqual(candidate);
    });
});

describe("ValidationSession cache revalidation (T05)", () => {
    it("refetches once when a custom cache serves poisoned OCSP bytes", async () => {
        const { leaf, issuer } = await createSignedPair({ ocspUrl: OCSP_URL });
        const fresh = createOcspResponseCandidate("good");
        let stored: Uint8Array | undefined;
        const poisoned: ValidationCache = {
            getOCSP: () => new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
            setOCSP: (_url: string, _request: Uint8Array, response: Uint8Array) => {
                stored = response;
            },
            getCRL: () => null,
            setCRL: () => {},
            clear: () => {},
        };
        const fetcher = recordingFetcher({ ocsp: fresh });
        const session = new ValidationSession({ cache: poisoned, fetcher });
        session.queueCertificate(leaf, { issuer });

        const [result] = await session.validateAll();
        expect(fetcher.ocspCalls).toBe(1);
        expect(result?.sources).toEqual(["OCSP"]);
        expect(result?.revocationStatus).toBe("unknown");
        expect(result?.ocspResponses).toHaveLength(1);
        expect(result?.ocspResponses?.[0]).toEqual(fresh);
        expect(stored).toEqual(fresh);
    });

    it("refetches once when a custom cache serves poisoned CRL bytes", async () => {
        const { leaf } = await createSignedPair({ crlUrl: CRL_URL });
        const fresh = createCrlFixture({ crlNumber: 3 });
        let stored: Uint8Array | undefined;
        const poisoned: ValidationCache = {
            getOCSP: () => null,
            setOCSP: () => {},
            getCRL: () => new Uint8Array([0xde, 0xad, 0xbe, 0xef]),
            setCRL: (_url: string, response: Uint8Array) => {
                stored = response;
            },
            clear: () => {},
        };
        const fetcher = recordingFetcher({ crl: fresh });
        const session = new ValidationSession({ cache: poisoned, fetcher });
        session.queueCertificate(leaf);

        const [result] = await session.validateAll();
        expect(fetcher.crlCalls).toBe(1);
        expect(result?.sources).toEqual(["CRL"]);
        expect(result?.revocationStatus).toBe("unknown");
        expect(result?.crls).toHaveLength(1);
        expect(result?.crls?.[0]).toEqual(fresh);
        expect(stored).toEqual(fresh);
    });

    it("reuses a live CRL entry across sessions sharing a cache", async () => {
        const { leaf } = await createSignedPair({ crlUrl: CRL_URL });
        const cache = new InMemoryValidationCache();
        const fetcher = recordingFetcher({ crl: createCrlFixture({ crlNumber: 3 }) });
        for (let index = 0; index < 2; index++) {
            const session = new ValidationSession({ cache, fetcher });
            session.queueCertificate(leaf);
            await session.validateAll();
        }
        expect(fetcher.crlCalls).toBe(1);
    });

    it("refetches expired CRL entries instead of serving them", async () => {
        const { leaf } = await createSignedPair({ crlUrl: CRL_URL });
        const cache = new InMemoryValidationCache({ retentionMs: 0 });
        const fetcher = recordingFetcher({ crl: createCrlFixture({ crlNumber: 3 }) });
        for (let index = 0; index < 2; index++) {
            const session = new ValidationSession({ cache, fetcher });
            session.queueCertificate(leaf);
            await session.validateAll();
        }
        expect(fetcher.crlCalls).toBe(2);
    });
});

describe("InMemoryValidationCache Buffer copy guarantees (T05 fix round 2)", () => {
    it("copies Buffer bytes on OCSP insertion", () => {
        const cache = new InMemoryValidationCache();
        const request = Buffer.from([1, 2, 3]);
        const response = Buffer.from([4, 5, 6]);
        cache.setOCSP(OCSP_URL, request, response);
        request[0] = 0x09;
        response[0] = 0x09;
        const cached = cache.getOCSP(OCSP_URL, new Uint8Array([1, 2, 3]));
        expect(cached ? new Uint8Array(cached) : cached).toEqual(new Uint8Array([4, 5, 6]));
    });

    it("copies Buffer bytes on CRL insertion", () => {
        const cache = new InMemoryValidationCache();
        const response = Buffer.from([7, 8, 9]);
        cache.setCRL(CRL_URL, response);
        response[0] = 0x09;
        const cached = cache.getCRL(CRL_URL);
        expect(cached ? new Uint8Array(cached) : cached).toEqual(new Uint8Array([7, 8, 9]));
    });

    it("copies Buffer bytes on OCSP retrieval", () => {
        const cache = new InMemoryValidationCache();
        cache.setOCSP(OCSP_URL, Buffer.from([1]), Buffer.from([4, 5, 6]));
        const first = cache.getOCSP(OCSP_URL, new Uint8Array([1]));
        expect(first ? new Uint8Array(first) : first).toEqual(new Uint8Array([4, 5, 6]));
        if (first) first[0] = 0x09;
        const second = cache.getOCSP(OCSP_URL, new Uint8Array([1]));
        expect(second ? new Uint8Array(second) : second).toEqual(new Uint8Array([4, 5, 6]));
    });

    it("copies Buffer bytes on CRL retrieval", () => {
        const cache = new InMemoryValidationCache();
        cache.setCRL(CRL_URL, Buffer.from([7, 8, 9]));
        const first = cache.getCRL(CRL_URL);
        expect(first ? new Uint8Array(first) : first).toEqual(new Uint8Array([7, 8, 9]));
        if (first) first[0] = 0x09;
        const second = cache.getCRL(CRL_URL);
        expect(second ? new Uint8Array(second) : second).toEqual(new Uint8Array([7, 8, 9]));
    });
});
