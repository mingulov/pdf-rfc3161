import { beforeAll, describe, expect, it, vi } from "vitest";
import vm from "node:vm";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { SimpleTrustStore, type TrustStore } from "../../../core/src/pki/trust-store.js";
import {
    extractTimestamps,
    verifyPdfTimestamps,
    verifyTimestamp,
    verifyTimestampsWithSharedIndex,
    withOwn,
    type ExtractedTimestamp,
} from "../../../core/src/pdf/extract.js";
import { TimestampSession } from "../../../core/src/session.js";
import { parseTimestampToken } from "../../../core/src/tsa/token-validation.js";
import { TimestampErrorCode, type VerificationOptions } from "../../../core/src/types.js";
import { archiveTimestamp } from "../../../core/src/pdf/archive.js";
import {
    createRFC3161TokenFixtureFromRequest,
    FIXTURE_GENTIME_ISO,
} from "../fixtures/rfc3161-token.js";
import { cryptoEngine, generateRSAKeyPair, importKeyForCertificate } from "../utils/crypto.js";

// T09b: explicit historical chain validation (R15/R16/R18 remainder).
// Callers can validate a chain as of a past date with a capable trust
// store; legacy stores without verifyChainAtTime stay valid for
// default current-time calls but reject explicit historical requests
// instead of silently validating at the wrong date.

const HISTORICAL_DATE = new Date("2026-03-01T12:00:00Z");
const LAPSED_NOT_BEFORE_ISO = "2025-01-01T00:00:00Z";
const LAPSED_NOT_AFTER_ISO = "2026-06-01T00:00:00Z";
const LAPSED_SIGNER_NOT_AFTER_ISO = "2026-09-01T00:00:00Z";

interface HistoricalHierarchy {
    root: pkijs.Certificate;
    intermediate: pkijs.Certificate;
    leaf: pkijs.Certificate;
    untrusted: pkijs.Certificate;
}

function derOf(certificate: pkijs.Certificate): Uint8Array {
    return new Uint8Array(certificate.toSchema().toBER(false));
}

function concatBytes(left: Uint8Array, right: Uint8Array): Uint8Array {
    const out = new Uint8Array(left.length + right.length);
    out.set(left, 0);
    out.set(right, left.length);
    return out;
}

async function createHistoricalCertificate(options: {
    commonName: string;
    keys: CryptoKeyPair;
    serial: number;
    ca: boolean;
    notBefore: string;
    notAfter: string;
    issuer?: pkijs.Certificate;
    issuerKeys?: CryptoKeyPair;
}): Promise<pkijs.Certificate> {
    const certificate = new pkijs.Certificate();
    certificate.version = 2;
    certificate.serialNumber = new asn1js.Integer({ value: options.serial });
    certificate.subject.typesAndValues.push(
        new pkijs.AttributeTypeAndValue({
            type: "2.5.4.3",
            value: new asn1js.PrintableString({ value: options.commonName }),
        })
    );
    certificate.issuer = options.issuer?.subject ?? certificate.subject;
    certificate.notBefore.value = new Date(options.notBefore);
    certificate.notAfter.value = new Date(options.notAfter);
    certificate.subjectPublicKeyInfo = await importKeyForCertificate(options.keys.publicKey);
    if (options.ca) {
        certificate.extensions = [
            new pkijs.Extension({
                extnID: "2.5.29.19",
                critical: true,
                extnValue: new pkijs.BasicConstraints({ cA: true }).toSchema().toBER(),
            }),
        ];
    }
    await certificate.sign(
        (options.issuerKeys ?? options.keys).privateKey,
        "SHA-256",
        cryptoEngine
    );
    return certificate;
}

async function buildHierarchy(): Promise<HistoricalHierarchy> {
    const rootKeys = await generateRSAKeyPair();
    const intermediateKeys = await generateRSAKeyPair();
    const leafKeys = await generateRSAKeyPair();
    const untrustedKeys = await generateRSAKeyPair();
    const root = await createHistoricalCertificate({
        commonName: "Historical Root",
        keys: rootKeys,
        serial: 5001,
        ca: true,
        notBefore: "2020-01-01T00:00:00Z",
        notAfter: "2035-01-01T00:00:00Z",
    });
    const intermediate = await createHistoricalCertificate({
        commonName: "Historical Intermediate",
        keys: intermediateKeys,
        serial: 5002,
        ca: true,
        notBefore: LAPSED_NOT_BEFORE_ISO,
        notAfter: LAPSED_NOT_AFTER_ISO,
        issuer: root,
        issuerKeys: rootKeys,
    });
    const leaf = await createHistoricalCertificate({
        commonName: "Historical Leaf",
        keys: leafKeys,
        serial: 5003,
        ca: false,
        notBefore: LAPSED_NOT_BEFORE_ISO,
        notAfter: LAPSED_NOT_AFTER_ISO,
        issuer: intermediate,
        issuerKeys: intermediateKeys,
    });
    const untrusted = await createHistoricalCertificate({
        commonName: "Historical Untrusted",
        keys: untrustedKeys,
        serial: 5004,
        ca: false,
        notBefore: LAPSED_NOT_BEFORE_ISO,
        notAfter: LAPSED_NOT_AFTER_ISO,
    });
    return { root, intermediate, leaf, untrusted };
}

/** Legacy-shaped store: only the pre-T09b capability surface. */
class LegacyStore implements TrustStore {
    private readonly inner = new SimpleTrustStore();

    addCertificate(cert: Uint8Array | pkijs.Certificate): void {
        this.inner.addCertificate(cert);
    }

    verifyChain(chain: (Uint8Array | pkijs.Certificate)[]): Promise<boolean> {
        return this.inner.verifyChain(chain);
    }
}

/**
 * Window-rule store: answers verifyChainAtTime from the carried check
 * date against the lapsed fixture signer's validity window, and
 * records which entry each call reached. Real path-engine historical
 * verdicts are proven at the direct level above (a self-signed non-CA
 * fixture signer cannot anchor pkijs -- the T01 PDF-level precedent,
 * which likewise asserts only untrusted outcomes on fixture tokens);
 * this double proves extract.ts forwards the token's genTime and
 * explicit dates to chain validation instead of one fixed time.
 */
class WindowStore implements TrustStore {
    readonly calls: { checkDate: Date | undefined }[] = [];

    addCertificate(_cert: Uint8Array | pkijs.Certificate): void {
        // Verdicts come from the window rule; nothing to pin.
    }

    async verifyChain(_chain: (Uint8Array | pkijs.Certificate)[]): Promise<boolean> {
        this.calls.push({ checkDate: undefined });
        return false;
    }

    async verifyChainAtTime(
        _chain: (Uint8Array | pkijs.Certificate)[],
        checkDate: Date
    ): Promise<boolean> {
        this.calls.push({ checkDate });
        const ms = checkDate.getTime();
        return (
            ms >= Date.parse("2025-01-01T00:00:00Z") &&
            ms <= Date.parse(LAPSED_SIGNER_NOT_AFTER_ISO)
        );
    }
}

/**
 * Date subclass whose numeric coercion disagrees with getTime (Astra T09b
 * F1): the old gate read getTime() (finite) while pkijs compared with
 * coercion (NaN, so every bound check passed). Snapshotting into a fresh
 * intrinsic Date strips the lying valueOf.
 */
class MisleadingDate extends Date {
    override valueOf(): number {
        return NaN;
    }
}

/**
 * Real Date whose own getTime throws instead of returning a number. Round-3
 * contract: the intrinsic instant governs and the overridable method is
 * never consulted, so this verifies like its intrinsic HISTORICAL_DATE.
 */
function throwingGetTimeDate(): Date {
    const date = new Date(HISTORICAL_DATE.getTime());
    (date as unknown as { getTime: () => number }).getTime = () => {
        throw new Error("boom");
    };
    return date;
}

/**
 * Date subclass whose getTime claims a different instant than the
 * intrinsic slot (Astra T09b F1 round 3): the snapshot must read the
 * intrinsic slot, so the verdict follows `intrinsic`, never `claimed`.
 */
class FakeGetTime extends Date {
    constructor(
        intrinsic: string | number,
        private readonly claimed: number
    ) {
        super(intrinsic);
    }

    override getTime(): number {
        return this.claimed;
    }
}

/** Subclass with an intrinsically invalid instant but a plausible getTime. */
class NaNIntrinsicDate extends Date {
    override getTime(): number {
        return HISTORICAL_DATE.getTime();
    }
}

/**
 * Ordinary (non-revoked) proxy over a valid Date: no intrinsic slot is
 * reachable through it, so the intrinsic read throws and the input is
 * malformed.
 */
function ordinaryProxyDate(): Date {
    return new Proxy(new Date(HISTORICAL_DATE.getTime()), {});
}

/** Revoked proxy over a Date: even `instanceof` throws on access. */
function revokedProxyDate(): Date {
    const { proxy, revoke } = Proxy.revocable(new Date(HISTORICAL_DATE.getTime()), {});
    revoke();
    return proxy;
}

/** Date from another VM realm: `instanceof Date` is false. */
function crossRealmDate(): Date {
    return vm.runInNewContext("new Date('2026-03-01T12:00:00Z')") as Date;
}

/** Object with Date.prototype but no Date internal slot: getTime throws. */
function prototypeOnlyDate(): Date {
    return Object.create(Date.prototype) as Date;
}

const MALFORMED_DATE_CASES: [string, () => Date][] = [
    ["revoked proxy", revokedProxyDate],
    ["ordinary Date proxy", ordinaryProxyDate],
    ["intrinsically-NaN subclass", () => new NaNIntrinsicDate(NaN)],
    ["cross-realm Date", crossRealmDate],
    ["prototype-only Date", prototypeOnlyDate],
];

function minimalPdf(): Uint8Array {
    return new TextEncoder().encode(
        `%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>
endobj
xref
0 4
0000000000 65535 f${" "}
0000000009 00000 n${" "}
0000000058 00000 n${" "}
0000000115 00000 n${" "}
trailer
<< /Size 4 /Root 1 0 R >>
startxref
203
%%EOF`
    );
}

interface LapsedSignerPdf {
    pdf: Uint8Array;
    extracted: ExtractedTimestamp;
    rawToken: Uint8Array;
    signerDer: Uint8Array;
    genTime: Date;
}

/** Embeds a token whose signer lapsed after issuance (T09a C05 shape). */
async function embedLapsedSignerPdf(): Promise<LapsedSignerPdf> {
    const session = new TimestampSession(minimalPdf(), {
        enableLTV: false,
        prepareOptions: { signatureSize: 4096 },
    });
    const request = await session.createTimestampRequest({
        hashAlgorithm: "SHA-256",
        requestCertificate: true,
    });
    const token = await createRFC3161TokenFixtureFromRequest(request, {
        form: "raw",
        signerValidityDates: {
            notBefore: "2025-01-01T00:00:00Z",
            notAfter: LAPSED_SIGNER_NOT_AFTER_ISO,
        },
    });
    const pdf = await session.embedTimestampToken(token.rawToken);
    const extracted = await extractTimestamps(pdf);
    if (extracted.length !== 1 || extracted[0] === undefined) {
        throw new Error("expected exactly one extracted timestamp");
    }
    return {
        pdf,
        extracted: extracted[0],
        rawToken: token.rawToken,
        signerDer: token.signerCertificate,
        genTime: parseTimestampToken(token.rawToken).tstInfo.genTime,
    };
}

/**
 * Loads the T09b capability. On BASE the method does not exist, so the
 * test fails with an assertion (capability absence), not an
 * infrastructure error -- the T06 module-absence red precedent.
 */
async function expectAtTime(
    store: SimpleTrustStore
): Promise<(chain: (Uint8Array | pkijs.Certificate)[], checkDate: Date) => Promise<boolean>> {
    const atTime = store.verifyChainAtTime;
    expect(typeof atTime, "verifyChainAtTime capability exists (T09b implementation)").toBe(
        "function"
    );
    if (typeof atTime !== "function") throw new Error("unreachable");
    return atTime.bind(store);
}

describe("verifyChainAtTime (T09b item 1)", () => {
    let hierarchy: HistoricalHierarchy;

    beforeAll(async () => {
        hierarchy = await buildHierarchy();
        // The lapsed window must cover the check date but end before any
        // run date, so "expired today, valid then" holds forever.
        expect(new Date(LAPSED_NOT_AFTER_ISO).getTime()).toBeGreaterThan(HISTORICAL_DATE.getTime());
        expect(new Date(LAPSED_NOT_AFTER_ISO).getTime()).toBeLessThan(Date.now());
    }, 60000);

    function pinnedRootStore(): SimpleTrustStore {
        const store = new SimpleTrustStore();
        store.addCertificate(hierarchy.root);
        return store;
    }

    it("validates a chain that was valid at the check date but is expired today", async () => {
        const store = pinnedRootStore();
        const atTime = await expectAtTime(store);
        const chain = [derOf(hierarchy.leaf), derOf(hierarchy.intermediate)];
        await expect(atTime(chain, HISTORICAL_DATE)).resolves.toBe(true);
        // Default current-time behavior is unchanged: the same chain no
        // longer validates once its certificates have lapsed.
        await expect(store.verifyChain(chain)).resolves.toBe(false);
    });

    it("rejects a chain whose signer was not yet valid at the check date", async () => {
        const store = pinnedRootStore();
        const atTime = await expectAtTime(store);
        const chain = [derOf(hierarchy.leaf), derOf(hierarchy.intermediate)];
        await expect(atTime(chain, new Date("2024-06-01T00:00:00Z"))).resolves.toBe(false);
    });

    it("verifies chain[0] at historical dates (T01 target identity)", async () => {
        const store = pinnedRootStore();
        const atTime = await expectAtTime(store);
        const leafDer = derOf(hierarchy.leaf);
        const intermediateDer = derOf(hierarchy.intermediate);
        // The genuine target still validates with its path candidates.
        await expect(atTime([leafDer, intermediateDer], HISTORICAL_DATE)).resolves.toBe(true);
        // An untrusted target does not validate merely because the bag
        // also carries a complete trusted path for another certificate.
        const untrustedDer = derOf(hierarchy.untrusted);
        await expect(
            atTime([untrustedDer, leafDer, intermediateDer], HISTORICAL_DATE)
        ).resolves.toBe(false);
        // Duplicates and candidate order cannot change the verdict for a
        // fixed target.
        await expect(atTime([leafDer, leafDer, intermediateDer], HISTORICAL_DATE)).resolves.toBe(
            true
        );
    });

    it("verifyChain still resolves without throwing at the current date", async () => {
        // No-throw delegation smoke only: this uses the lapsed
        // hierarchy, so `false` follows from expiry alone regardless
        // of target binding. The genuine current-date T01 target
        // proof is the preserved trust-store-signer-target.test.ts
        // suite (see T09b review M1).
        const store = pinnedRootStore();
        const chain = [
            derOf(hierarchy.untrusted),
            derOf(hierarchy.leaf),
            derOf(hierarchy.intermediate),
        ];
        await expect(store.verifyChain(chain)).resolves.toBe(false);
    });

    it("rejects non-finite check dates with INVALID_ARGUMENT", async () => {
        const store = pinnedRootStore();
        const atTime = await expectAtTime(store);
        const chain = [derOf(hierarchy.leaf), derOf(hierarchy.intermediate)];
        for (const checkDate of [new Date(NaN), new Date(Infinity)]) {
            await expect(atTime(chain, checkDate)).rejects.toMatchObject({
                code: TimestampErrorCode.INVALID_ARGUMENT,
                message: expect.stringContaining("finite"),
            });
        }
        await expect(
            atTime(chain, "2026-03-01T12:00:00Z" as unknown as Date)
        ).rejects.toMatchObject({
            code: TimestampErrorCode.INVALID_ARGUMENT,
            message: expect.stringContaining("finite"),
        });
    });

    it("leaves legacy-shaped stores usable for default current-time calls", async () => {
        const store = new LegacyStore();
        store.addCertificate(hierarchy.root);
        const chain = [derOf(hierarchy.leaf), derOf(hierarchy.intermediate)];
        await expect(store.verifyChain(chain)).resolves.toBe(false);
        expect("verifyChainAtTime" in store).toBe(false);
    });
});

describe("DER consumption for anchors and chain inputs (T09b item 3)", () => {
    let hierarchy: HistoricalHierarchy;

    beforeAll(async () => {
        hierarchy = await buildHierarchy();
    }, 60000);

    it("addCertificate rejects an anchor with trailing garbage", () => {
        const store = new SimpleTrustStore();
        const padded = concatBytes(derOf(hierarchy.root), new Uint8Array([0x00]));
        let thrown: unknown;
        try {
            store.addCertificate(padded);
        } catch (error) {
            thrown = error;
        }
        expect(thrown).toMatchObject({ code: TimestampErrorCode.INVALID_RESPONSE });
        // A clean anchor still pins.
        expect(() => store.addCertificate(derOf(hierarchy.root))).not.toThrow();
    });

    it("verifyChain rejects trailing-garbage chain inputs", async () => {
        const store = new SimpleTrustStore();
        store.addCertificate(hierarchy.root);
        const paddedLeaf = concatBytes(derOf(hierarchy.leaf), new Uint8Array([0x00]));
        await expect(
            store.verifyChain([paddedLeaf, derOf(hierarchy.intermediate)])
        ).rejects.toMatchObject({
            code: TimestampErrorCode.INVALID_RESPONSE,
        });
    });

    it("verifyChainAtTime rejects trailing-garbage chain inputs at historical dates", async () => {
        const store = new SimpleTrustStore();
        store.addCertificate(hierarchy.root);
        const atTime = await expectAtTime(store);
        const paddedLeaf = concatBytes(derOf(hierarchy.leaf), new Uint8Array([0x00]));
        await expect(
            atTime([paddedLeaf, derOf(hierarchy.intermediate)], HISTORICAL_DATE)
        ).rejects.toMatchObject({
            code: TimestampErrorCode.INVALID_RESPONSE,
        });
    });

    it("verifyChain rejects garbage-only chain inputs with INVALID_RESPONSE", async () => {
        const store = new SimpleTrustStore();
        store.addCertificate(hierarchy.root);
        await expect(store.verifyChain([new Uint8Array([0x30, 0x01])])).rejects.toMatchObject({
            code: TimestampErrorCode.INVALID_RESPONSE,
        });
    });
});

describe("extract.ts chainValidationTime forwarding (T09b item 4)", () => {
    let lapsed: LapsedSignerPdf;

    beforeAll(async () => {
        lapsed = await embedLapsedSignerPdf();
        // The signer lapsed after issuance: notAfter falls between the
        // fixed genTime and today at every run date past 2026-09-01.
        expect(new Date(LAPSED_SIGNER_NOT_AFTER_ISO).getTime()).toBeGreaterThan(
            lapsed.genTime.getTime()
        );
        expect(new Date(LAPSED_SIGNER_NOT_AFTER_ISO).getTime()).toBeLessThan(Date.now());
        expect(lapsed.genTime.getTime()).toBe(new Date(FIXTURE_GENTIME_ISO).getTime());
    }, 60000);

    function pinnedSignerStore(): SimpleTrustStore {
        const store = new SimpleTrustStore();
        store.addCertificate(lapsed.signerDer);
        return store;
    }

    it("forwards explicit historical dates to chain validation", async () => {
        const store = new WindowStore();
        const checkDate = new Date(FIXTURE_GENTIME_ISO);
        const verified = await verifyTimestamp(lapsed.extracted, {
            pdf: lapsed.pdf,
            trustStore: store,
            strictESSValidation: true,
            chainValidationTime: checkDate,
        });
        expect(verified.verified).toBe(true);
        expect(store.calls).toHaveLength(1);
        expect(store.calls[0]?.checkDate?.getTime()).toBe(checkDate.getTime());
    });

    it('resolves "genTime" from the token under validation', async () => {
        const store = new WindowStore();
        const verified = await verifyTimestamp(lapsed.extracted, {
            pdf: lapsed.pdf,
            trustStore: store,
            strictESSValidation: true,
            chainValidationTime: "genTime",
        });
        expect(verified.verified).toBe(true);
        // The carried check time is the token's own genTime instant, not
        // a fresh wall-clock read (which would be years later).
        expect(store.calls).toHaveLength(1);
        expect(store.calls[0]?.checkDate?.getTime()).toBe(lapsed.genTime.getTime());
    });

    it("distinguishes historical dates instead of validating at one fixed time", async () => {
        const store = new WindowStore();
        const atIssuance = await verifyTimestamp(lapsed.extracted, {
            pdf: lapsed.pdf,
            trustStore: store,
            chainValidationTime: new Date(FIXTURE_GENTIME_ISO),
        });
        const beforeValidity = await verifyTimestamp(lapsed.extracted, {
            pdf: lapsed.pdf,
            trustStore: store,
            chainValidationTime: new Date("2020-01-01T00:00:00Z"),
        });
        expect(atIssuance.verified).toBe(true);
        expect(beforeValidity.verified).toBe(false);
        expect(beforeValidity.verificationError).toBe("Certificate chain not trusted");
    });

    it('rejects "genTime" requests against a legacy store without the capability', async () => {
        const store = new LegacyStore();
        store.addCertificate(lapsed.signerDer);
        const result = await verifyTimestamp(lapsed.extracted, {
            pdf: lapsed.pdf,
            trustStore: store,
            chainValidationTime: "genTime",
        });
        expect(result.verified).toBe(false);
        expect(result.verificationErrorCode).toBe(TimestampErrorCode.INVALID_ARGUMENT);
        expect(result.verificationError).toMatch(/verifyChainAtTime/);
    });

    it("rejects explicit Date requests against a legacy store without the capability", async () => {
        const store = new LegacyStore();
        store.addCertificate(lapsed.signerDer);
        const result = await verifyTimestamp(lapsed.extracted, {
            pdf: lapsed.pdf,
            trustStore: store,
            chainValidationTime: new Date(FIXTURE_GENTIME_ISO),
        });
        expect(result.verified).toBe(false);
        expect(result.verificationErrorCode).toBe(TimestampErrorCode.INVALID_ARGUMENT);
        expect(result.verificationError).toMatch(/verifyChainAtTime/);
    });

    it('accepts legacy stores for default and explicit "current" calls', async () => {
        for (const chainValidationTime of [undefined, "current"] as const) {
            const store = new LegacyStore();
            store.addCertificate(lapsed.signerDer);
            const verified = await verifyTimestamp(lapsed.extracted, {
                pdf: lapsed.pdf,
                trustStore: store,
                chainValidationTime,
            });
            // Current-time default is unchanged: the lapsed signer no
            // longer chains, and the legacy store still drives that call.
            expect(verified.verified).toBe(false);
            expect(verified.verificationError).toBe("Certificate chain not trusted");
        }
    });

    it("rejects non-finite explicit dates with INVALID_ARGUMENT", async () => {
        const store = pinnedSignerStore();
        const result = await verifyTimestamp(lapsed.extracted, {
            pdf: lapsed.pdf,
            trustStore: store,
            chainValidationTime: new Date(NaN),
        });
        expect(result.verified).toBe(false);
        expect(result.verificationErrorCode).toBe(TimestampErrorCode.INVALID_ARGUMENT);
        expect(result.verificationError).toMatch(/finite/);
    });

    it("performs no network fetch on the historical path (no silent CRL use)", async () => {
        const store = new WindowStore();
        const fetchStub = vi.fn(() => {
            throw new Error("historical path must not fetch");
        });
        vi.stubGlobal("fetch", fetchStub);
        try {
            const verified = await verifyTimestamp(lapsed.extracted, {
                pdf: lapsed.pdf,
                trustStore: store,
                chainValidationTime: "genTime",
            });
            expect(verified.verified).toBe(true);
            expect(fetchStub).not.toHaveBeenCalled();
        } finally {
            vi.unstubAllGlobals();
        }
    });
});

describe("C05 historical acceptance (T09b item 6)", () => {
    it("validates a signer expired today but valid at issuance, byte-for-byte", async () => {
        const lapsed = await embedLapsedSignerPdf();
        expect(new Date(LAPSED_SIGNER_NOT_AFTER_ISO).getTime()).toBeGreaterThan(
            lapsed.genTime.getTime()
        );
        expect(new Date(LAPSED_SIGNER_NOT_AFTER_ISO).getTime()).toBeLessThan(Date.now());

        // The window-rule store models "valid at issuance, expired
        // today" through the forwarded check date; the direct-level
        // suite above proves the same verdict shape on the real engine.
        const historical = await verifyTimestamp(lapsed.extracted, {
            pdf: lapsed.pdf,
            trustStore: new WindowStore(),
            strictESSValidation: true,
            chainValidationTime: "genTime",
        });
        expect(historical.verified).toBe(true);

        // The default current-time call still rejects solely for later
        // expiry; only the explicit historical request accepts.
        const pinned = new SimpleTrustStore();
        pinned.addCertificate(lapsed.signerDer);
        const current = await verifyTimestamp(lapsed.extracted, {
            pdf: lapsed.pdf,
            trustStore: pinned,
            strictESSValidation: true,
        });
        expect(current.verified).toBe(false);

        // Fixing trust-target ordering must not rewrite the embedded CMS
        // token: extracted bytes equal the accepted token exactly apart
        // from PDF reservation zero padding.
        expect(lapsed.extracted.token).toEqual(lapsed.rawToken);
        const contents = lapsed.extracted.contentsValueBytes;
        expect(contents.slice(0, lapsed.rawToken.length)).toEqual(lapsed.rawToken);
        const padding = contents.slice(lapsed.rawToken.length);
        expect(padding.length).toBeGreaterThan(0);
        expect(padding).toEqual(new Uint8Array(padding.length));
    });
});

describe("validation-date snapshot (T09b-F1 direct entry)", () => {
    let hierarchy: HistoricalHierarchy;

    beforeAll(async () => {
        hierarchy = await buildHierarchy();
    }, 60000);

    function pinnedRootStore(): SimpleTrustStore {
        const store = new SimpleTrustStore();
        store.addCertificate(hierarchy.root);
        return store;
    }

    it("ignores subclass valueOf: a 2035 date over a lapsed chain does not verify", async () => {
        const store = pinnedRootStore();
        const atTime = await expectAtTime(store);
        const chain = [derOf(hierarchy.leaf), derOf(hierarchy.intermediate)];
        // getTime() reads 2035 (finite, past expiry) while coercion reads
        // NaN (every pkijs bound check passes) without the snapshot.
        await expect(atTime(chain, new MisleadingDate("2035-01-01T00:00:00Z"))).resolves.toBe(
            false
        );
    });

    it("snapshots before async work: NaN mutation mid-await does not verify", async () => {
        const store = pinnedRootStore();
        const atTime = await expectAtTime(store);
        const chain = [derOf(hierarchy.leaf), derOf(hierarchy.intermediate)];
        const checkDate = new Date("2026-09-01T00:00:00Z");
        const pending = atTime(chain, checkDate);
        checkDate.setTime(NaN);
        await expect(pending).resolves.toBe(false);
    });

    it("ignores overridden getTime: FakeGetTime(2035) over a lapsed chain does not verify", async () => {
        const store = pinnedRootStore();
        const atTime = await expectAtTime(store);
        const chain = [derOf(hierarchy.leaf), derOf(hierarchy.intermediate)];
        // Intrinsic 2035 (past expiry) governs; the in-window getTime
        // claim is ignored, so this rejects instead of accepting.
        await expect(
            atTime(
                chain,
                new FakeGetTime("2035-01-01T00:00:00Z", HISTORICAL_DATE.getTime())
            )
        ).resolves.toBe(false);
    });

    it("governs by the intrinsic instant: FakeGetTime(2026) with a 2035 getTime verifies", async () => {
        const store = pinnedRootStore();
        const atTime = await expectAtTime(store);
        const chain = [derOf(hierarchy.leaf), derOf(hierarchy.intermediate)];
        // The expired getTime claim is ignored: intrinsic HISTORICAL_DATE
        // is in-window, so the chain verifies (not INVALID_ARGUMENT).
        await expect(
            atTime(
                chain,
                new FakeGetTime(
                    HISTORICAL_DATE.getTime(),
                    Date.parse("2035-01-01T00:00:00Z")
                )
            )
        ).resolves.toBe(true);
    });

    it("ignores a throwing own getTime: the intrinsic instant governs", async () => {
        const store = pinnedRootStore();
        const atTime = await expectAtTime(store);
        const chain = [derOf(hierarchy.leaf), derOf(hierarchy.intermediate)];
        await expect(atTime(chain, throwingGetTimeDate())).resolves.toBe(true);
    });

    it.each(MALFORMED_DATE_CASES)(
        "direct entry codes %s as INVALID_ARGUMENT",
        async (_name, makeInput) => {
            const store = pinnedRootStore();
            const atTime = await expectAtTime(store);
            const chain = [derOf(hierarchy.leaf), derOf(hierarchy.intermediate)];
            await expect(atTime(chain, makeInput())).rejects.toMatchObject({
                code: TimestampErrorCode.INVALID_ARGUMENT,
            });
        }
    );
});

describe("validation-date snapshot (T09b-F1 extract dispatch)", () => {
    let hierarchy: HistoricalHierarchy;
    let lapsed: LapsedSignerPdf;

    beforeAll(async () => {
        hierarchy = await buildHierarchy();
        lapsed = await embedLapsedSignerPdf();
    }, 60000);

    /**
     * Store double mirroring pkijs basicCheck relational semantics over a
     * fixed window: the caller's date is read with numeric coercion
     * (ToNumber), exactly the read that disagreed with the old
     * getTime() gate.
     */
    class CoercingWindowStore implements TrustStore {
        constructor(private readonly window: pkijs.Certificate) {}

        addCertificate(_cert: Uint8Array | pkijs.Certificate): void {
            // Verdicts come from the window rule; nothing to pin.
        }

        async verifyChain(_chain: (Uint8Array | pkijs.Certificate)[]): Promise<boolean> {
            return false;
        }

        async verifyChainAtTime(
            _chain: (Uint8Array | pkijs.Certificate)[],
            checkDate: Date
        ): Promise<boolean> {
            const ms = Number(checkDate);
            return !(
                this.window.notBefore.value.getTime() > ms ||
                this.window.notAfter.value.getTime() < ms
            );
        }
    }

    it("strips subclass valueOf at the dispatch: MisleadingDate(2035) fails", async () => {
        const store = new CoercingWindowStore(hierarchy.leaf);
        const result = await verifyTimestamp(lapsed.extracted, {
            pdf: lapsed.pdf,
            trustStore: store,
            chainValidationTime: new MisleadingDate("2035-01-01T00:00:00Z"),
        });
        expect(result.verified).toBe(false);
    });

    it("ignores overridden getTime at the dispatch: FakeGetTime(2035) fails", async () => {
        const store = new CoercingWindowStore(hierarchy.leaf);
        const result = await verifyTimestamp(lapsed.extracted, {
            pdf: lapsed.pdf,
            trustStore: store,
            chainValidationTime: new FakeGetTime(
                "2035-01-01T00:00:00Z",
                HISTORICAL_DATE.getTime()
            ),
        });
        expect(result.verified).toBe(false);
    });

    it("governs by the intrinsic instant at the dispatch: FakeGetTime(2026) verifies", async () => {
        const store = new CoercingWindowStore(hierarchy.leaf);
        const result = await verifyTimestamp(lapsed.extracted, {
            pdf: lapsed.pdf,
            trustStore: store,
            chainValidationTime: new FakeGetTime(
                HISTORICAL_DATE.getTime(),
                Date.parse("2035-01-01T00:00:00Z")
            ),
        });
        expect(result.verified).toBe(true);
    });

    it("ignores a throwing own getTime at the dispatch: the intrinsic instant governs", async () => {
        const store = new CoercingWindowStore(hierarchy.leaf);
        const result = await verifyTimestamp(lapsed.extracted, {
            pdf: lapsed.pdf,
            trustStore: store,
            chainValidationTime: throwingGetTimeDate(),
        });
        expect(result.verified).toBe(true);
    });

    it("freezes the call-time instant: sync future-to-past mutation stays rejected", async () => {
        const store = new CoercingWindowStore(hierarchy.leaf);
        const checkDate = new Date("2035-01-01T00:00:00Z");
        const pending = verifyTimestamp(lapsed.extracted, {
            pdf: lapsed.pdf,
            trustStore: store,
            chainValidationTime: checkDate,
        });
        // Mutate synchronously: no await has resolved, so this lands in
        // the pre-dispatch window the entry freeze closes. The call-time
        // 2035 instant governs.
        checkDate.setTime(HISTORICAL_DATE.getTime());
        const result = await pending;
        expect(result.verified).toBe(false);
    });

    it("freezes the call-time instant: sync past-to-NaN mutation stays accepted", async () => {
        const store = new CoercingWindowStore(hierarchy.leaf);
        const checkDate = new Date(HISTORICAL_DATE.getTime());
        const pending = verifyTimestamp(lapsed.extracted, {
            pdf: lapsed.pdf,
            trustStore: store,
            chainValidationTime: checkDate,
        });
        // Mutate synchronously, before any await resolves: the call-time
        // in-window instant governs, so this verifies instead of coding
        // INVALID_ARGUMENT.
        checkDate.setTime(NaN);
        const result = await pending;
        expect(result.verified).toBe(true);
    });

    it("ignores overridden getTime at the PDF entry: FakeGetTime(2035) fails", async () => {
        const store = new CoercingWindowStore(hierarchy.leaf);
        const results = await verifyPdfTimestamps(lapsed.pdf, {
            trustStore: store,
            chainValidationTime: new FakeGetTime(
                "2035-01-01T00:00:00Z",
                HISTORICAL_DATE.getTime()
            ),
        });
        expect(results).toHaveLength(1);
        expect(results[0]?.verified).toBe(false);
    });

    it("freezes the call-time instant at the PDF entry: sync future-to-past stays rejected", async () => {
        const store = new CoercingWindowStore(hierarchy.leaf);
        const checkDate = new Date("2035-01-01T00:00:00Z");
        const pending = verifyPdfTimestamps(lapsed.pdf, {
            trustStore: store,
            chainValidationTime: checkDate,
        });
        // Mutate synchronously, before discovery awaits resolve.
        checkDate.setTime(HISTORICAL_DATE.getTime());
        const results = await pending;
        expect(results).toHaveLength(1);
        expect(results[0]?.verified).toBe(false);
    });

    it("freezes the call-time instant at the PDF entry: sync past-to-NaN stays accepted", async () => {
        const store = new CoercingWindowStore(hierarchy.leaf);
        const checkDate = new Date(HISTORICAL_DATE.getTime());
        const pending = verifyPdfTimestamps(lapsed.pdf, {
            trustStore: store,
            chainValidationTime: checkDate,
        });
        // Mutate synchronously, before discovery awaits resolve: the
        // call-time in-window instant governs.
        checkDate.setTime(NaN);
        const results = await pending;
        expect(results).toHaveLength(1);
        expect(results[0]?.verified).toBe(true);
    });

    it.each(MALFORMED_DATE_CASES)(
        "dispatch codes %s as INVALID_ARGUMENT",
        async (_name, makeInput) => {
            const store = new CoercingWindowStore(hierarchy.leaf);
            const result = await verifyTimestamp(lapsed.extracted, {
                pdf: lapsed.pdf,
                trustStore: store,
                chainValidationTime: makeInput(),
            });
            expect(result.verified).toBe(false);
            expect(result.verificationErrorCode).toBe(TimestampErrorCode.INVALID_ARGUMENT);
        }
    );

    it("captures the current date once per distinct signature value (T09b-F4b)", async () => {
        // Legacy-shaped store (no verifyChainAtTime): "current" requests
        // reach verifyChain, once per distinct signature value -- batch
        // verification shares one chain-validation call per value, never
        // one wall-clock capture for the whole call.
        const verdicts: readonly boolean[] = [true, false];
        let verifyChainCalls = 0;
        const store: TrustStore = {
            addCertificate(_cert: Uint8Array | pkijs.Certificate): void {},
            verifyChain(_chain: (Uint8Array | pkijs.Certificate)[]): Promise<boolean> {
                const verdict = verdicts[verifyChainCalls] ?? false;
                verifyChainCalls += 1;
                return Promise.resolve(verdict);
            },
        };
        const second: ExtractedTimestamp = {
            ...lapsed.extracted,
            fieldName: "SecondValue",
            contentsObject: { objectNumber: 999001, generationNumber: 0 },
            byteRange: [0, 7, 11, 13],
        };
        const results = await verifyTimestampsWithSharedIndex([lapsed.extracted, second], {
            trustStore: store,
        });
        expect(verifyChainCalls).toBe(2);
        expect(results.map((result) => result.verified)).toEqual([true, false]);
    });
});

describe("verification-option lookup semantics (T09b-N1)", () => {
    let lapsed: LapsedSignerPdf;

    beforeAll(async () => {
        lapsed = await embedLapsedSignerPdf();
    }, 60000);

    /** Store double that rejects every chain and counts its invocations. */
    class RejectingStore implements TrustStore {
        calls = 0;

        addCertificate(_cert: Uint8Array | pkijs.Certificate): void {
            // Nothing to pin; verdicts are unconditional.
        }

        async verifyChain(_chain: (Uint8Array | pkijs.Certificate)[]): Promise<boolean> {
            this.calls += 1;
            return false;
        }

        async verifyChainAtTime(
            _chain: (Uint8Array | pkijs.Certificate)[],
            _checkDate: Date
        ): Promise<boolean> {
            this.calls += 1;
            return false;
        }
    }

    /**
     * Options with an own chainValidationTime but an inherited
     * (prototype-getter) trustStore. A spread-based freeze drops the
     * policy, so verification must still consult the store exactly once.
     */
    class InheritedPolicyOptions {
        chainValidationTime: Date | "current" | "genTime";

        constructor(
            time: Date | "current" | "genTime",
            private readonly rejecting: TrustStore
        ) {
            this.chainValidationTime = time;
        }

        get trustStore(): TrustStore {
            return this.rejecting;
        }
    }

    function nonEnumerablePolicyOptions(time: Date, store: TrustStore): VerificationOptions {
        const options = { chainValidationTime: time } as VerificationOptions;
        Object.defineProperty(options, "trustStore", { value: store, enumerable: false });
        return options;
    }

    function explicitDate(): Date {
        return new Date(FIXTURE_GENTIME_ISO);
    }

    it("verifyTimestamp honors an inherited trustStore with an explicit Date", async () => {
        const store = new RejectingStore();
        const result = await verifyTimestamp(
            lapsed.extracted,
            new InheritedPolicyOptions(explicitDate(), store)
        );
        expect(result.verified).toBe(false);
        expect(result.verificationError).toBe("Certificate chain not trusted");
        expect(result.verificationErrorCode).toBe(TimestampErrorCode.VERIFICATION_FAILED);
        expect(store.calls).toBe(1);
    });

    it("verifyTimestamp honors an own non-enumerable trustStore with an explicit Date", async () => {
        const store = new RejectingStore();
        const result = await verifyTimestamp(
            lapsed.extracted,
            nonEnumerablePolicyOptions(explicitDate(), store)
        );
        expect(result.verified).toBe(false);
        expect(result.verificationError).toBe("Certificate chain not trusted");
        expect(store.calls).toBe(1);
    });

    it("verifyTimestamp codes an invalid Date as INVALID_ARGUMENT with an inherited store", async () => {
        const store = new RejectingStore();
        const result = await verifyTimestamp(
            lapsed.extracted,
            new InheritedPolicyOptions(new Date(NaN), store)
        );
        expect(result.verified).toBe(false);
        expect(result.verificationErrorCode).toBe(TimestampErrorCode.INVALID_ARGUMENT);
        expect(store.calls).toBe(0);
    });

    it("verifyTimestamp honors an own enumerable trustStore with an explicit Date (control)", async () => {
        const store = new RejectingStore();
        const result = await verifyTimestamp(lapsed.extracted, {
            chainValidationTime: explicitDate(),
            trustStore: store,
        });
        expect(result.verified).toBe(false);
        expect(result.verificationError).toBe("Certificate chain not trusted");
        expect(store.calls).toBe(1);
    });

    it.each(["current", "genTime"] as const)(
        "verifyTimestamp honors an inherited trustStore for %s (control)",
        async (time) => {
            const store = new RejectingStore();
            const result = await verifyTimestamp(
                lapsed.extracted,
                new InheritedPolicyOptions(time, store)
            );
            expect(result.verified).toBe(false);
            expect(result.verificationError).toBe("Certificate chain not trusted");
            expect(store.calls).toBe(1);
        }
    );

    it("verifyTimestampsWithSharedIndex honors an inherited trustStore with an explicit Date", async () => {
        const store = new RejectingStore();
        const results = await verifyTimestampsWithSharedIndex(
            [lapsed.extracted],
            new InheritedPolicyOptions(explicitDate(), store)
        );
        expect(results).toHaveLength(1);
        expect(results[0]?.verified).toBe(false);
        expect(results[0]?.verificationError).toBe("Certificate chain not trusted");
        expect(store.calls).toBe(1);
    });

    it("verifyPdfTimestamps honors an inherited trustStore with an explicit Date", async () => {
        const store = new RejectingStore();
        const results = await verifyPdfTimestamps(
            lapsed.pdf,
            new InheritedPolicyOptions(explicitDate(), store)
        );
        expect(results).toHaveLength(1);
        expect(results[0]?.verified).toBe(false);
        expect(results[0]?.verificationError).toBe("Certificate chain not trusted");
        expect(store.calls).toBe(1);
    });

    it("archiveTimestamp strict mode enforces an inherited trustStore before any TSA call", async () => {
        const store = new RejectingStore();
        const fetchMock = vi.fn(async () => {
            throw new Error("TSA must not be reached");
        });
        vi.stubGlobal("fetch", fetchMock);
        try {
            await expect(
                archiveTimestamp({
                    pdf: lapsed.pdf,
                    tsa: { url: "https://tsa.example.invalid/tsa" },
                    strictExistingVerification: true,
                    existingTimestampVerifyOptions: new InheritedPolicyOptions(
                        explicitDate(),
                        store
                    ),
                })
            ).rejects.toMatchObject({ code: TimestampErrorCode.VERIFICATION_FAILED });
            expect(fetchMock).not.toHaveBeenCalled();
            expect(store.calls).toBe(1);
        } finally {
            vi.unstubAllGlobals();
        }
    });

    it("a throwing trustStore getter fails verification instead of rejecting uncoded", async () => {
        const options = { chainValidationTime: explicitDate() } as VerificationOptions;
        Object.defineProperty(options, "trustStore", {
            enumerable: true,
            configurable: true,
            get(): TrustStore {
                throw new Error("boom");
            },
        });
        const result = await verifyTimestamp(lapsed.extracted, options);
        expect(result.verified).toBe(false);
        expect(result.verificationError).toContain("boom");
    });

    it("revoked-proxy options fail verification instead of rejecting uncoded", async () => {
        const { proxy, revoke } = Proxy.revocable(
            { chainValidationTime: explicitDate() } as VerificationOptions,
            {}
        );
        revoke();
        const result = await verifyTimestamp(lapsed.extracted, proxy);
        expect(result.verified).toBe(false);
    });

    it("frozen options keep their explicit Date and trustStore", async () => {
        const store = new RejectingStore();
        const options = Object.freeze({
            chainValidationTime: explicitDate(),
            trustStore: store,
        });
        const result = await verifyTimestamp(lapsed.extracted, options);
        expect(result.verified).toBe(false);
        expect(result.verificationError).toBe("Certificate chain not trusted");
        expect(store.calls).toBe(1);
    });
});

describe("verification-option override semantics (T09b-N2/N3)", () => {
    let lapsed: LapsedSignerPdf;

    beforeAll(async () => {
        lapsed = await embedLapsedSignerPdf();
    }, 60000);

    /** Store double that accepts in-window dates and records the carried instant. */
    class CarryingWindowStore implements TrustStore {
        carried: number[] = [];

        addCertificate(_cert: Uint8Array | pkijs.Certificate): void {
            // Verdicts come from the window rule; nothing to pin.
        }

        async verifyChain(_chain: (Uint8Array | pkijs.Certificate)[]): Promise<boolean> {
            return false;
        }

        async verifyChainAtTime(
            _chain: (Uint8Array | pkijs.Certificate)[],
            checkDate: Date
        ): Promise<boolean> {
            const ms = checkDate.getTime();
            this.carried.push(ms);
            return (
                ms >= Date.parse("2025-01-01T00:00:00Z") &&
                ms <= Date.parse("2026-06-01T00:00:00Z")
            );
        }
    }

    /** Store double that rejects every chain and counts its invocations. */
    class RejectingStore implements TrustStore {
        calls = 0;

        addCertificate(_cert: Uint8Array | pkijs.Certificate): void {
            // Nothing to pin; verdicts are unconditional.
        }

        async verifyChain(_chain: (Uint8Array | pkijs.Certificate)[]): Promise<boolean> {
            this.calls += 1;
            return false;
        }

        async verifyChainAtTime(
            _chain: (Uint8Array | pkijs.Certificate)[],
            _checkDate: Date
        ): Promise<boolean> {
            this.calls += 1;
            return false;
        }
    }

    /**
     * Options inheriting a chainValidationTime getter paired with a
     * counting no-op setter. Ordinary assignment would invoke the setter
     * instead of installing the frozen instant (T09b-N2).
     */
    class InheritedDateOptions {
        trustStore: TrustStore;
        pdf?: Uint8Array;
        setterCalls = 0;

        constructor(store: TrustStore, private readonly date: Date, pdf?: Uint8Array) {
            this.trustStore = store;
            this.pdf = pdf;
        }

        get chainValidationTime(): Date {
            return this.date;
        }

        set chainValidationTime(_value: Date) {
            this.setterCalls += 1;
        }
    }

    /** Options inheriting a getter-only chainValidationTime (no setter at all). */
    class GetterOnlyDateOptions {
        trustStore: TrustStore;
        pdf?: Uint8Array;

        constructor(store: TrustStore, private readonly date: Date, pdf?: Uint8Array) {
            this.trustStore = store;
            this.pdf = pdf;
        }

        get chainValidationTime(): Date {
            return this.date;
        }
    }

    /** Own enumerable trustStore getter backed by the original receiver's identity. */
    function weakMapPolicyOptions(time: Date, store: TrustStore): VerificationOptions {
        const policies = new WeakMap<object, TrustStore>();
        const options = {
            chainValidationTime: time,
            get trustStore(): TrustStore | undefined {
                return policies.get(this);
            },
        };
        policies.set(options, store);
        return options;
    }

    /** Own enumerable trustStore getter that only answers for the original receiver. */
    function receiverSensitivePolicyOptions(time: Date, store: TrustStore): VerificationOptions {
        const options = {
            chainValidationTime: time,
            get trustStore(): TrustStore | undefined {
                return this === options ? store : undefined;
            },
        };
        return options;
    }

    /** Proxy whose get trap supplies the trust policy over an undefined own field. */
    function proxyPolicyOptions(time: Date, store: TrustStore): VerificationOptions {
        return new Proxy(
            { chainValidationTime: time, trustStore: undefined } as VerificationOptions,
            {
                get(target, key, receiver): unknown {
                    if (key === "trustStore") return store;
                    return Reflect.get(target, key, receiver);
                },
            }
        );
    }

    function throwingPolicyOptions(time: Date, message: string): VerificationOptions {
        const options = { chainValidationTime: time } as VerificationOptions;
        Object.defineProperty(options, "trustStore", {
            enumerable: true,
            configurable: true,
            get(): TrustStore {
                throw new Error(message);
            },
        });
        return options;
    }

    function windowDate(): Date {
        return new Date(HISTORICAL_DATE.getTime());
    }

    function expiredDate(): Date {
        return new Date("2035-01-01T00:00:00Z");
    }

    /**
     * Flips the PDF minor-version digit: a covered byte whose change keeps
     * a parseable PDF with identical signature offsets.
     */
    function tamperCoveredHeaderByte(pdf: Uint8Array): Uint8Array {
        const tampered = Uint8Array.from(pdf);
        expect(Array.from(tampered.subarray(0, 7))).toEqual([
            0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e,
        ]);
        tampered[7] = tampered[7] === 55 ? 54 : 55;
        return tampered;
    }

    it("verifyTimestamp: an inherited setter cannot swallow the frozen instant", async () => {
        const store = new CarryingWindowStore();
        const checkDate = expiredDate();
        const options = new InheritedDateOptions(store, checkDate, lapsed.pdf);
        const pending = verifyTimestamp(lapsed.extracted, options);
        checkDate.setTime(HISTORICAL_DATE.getTime());
        const result = await pending;
        expect(result.verified).toBe(false);
        expect(store.carried).toEqual([Date.parse("2035-01-01T00:00:00Z")]);
        expect(options.setterCalls).toBe(0);
    });

    it("verifyTimestampsWithSharedIndex: an inherited setter cannot swallow the frozen instant", async () => {
        const store = new CarryingWindowStore();
        const checkDate = expiredDate();
        const options = new InheritedDateOptions(store, checkDate, lapsed.pdf);
        const pending = verifyTimestampsWithSharedIndex([lapsed.extracted], options);
        checkDate.setTime(HISTORICAL_DATE.getTime());
        const results = await pending;
        expect(results).toHaveLength(1);
        expect(results[0]?.verified).toBe(false);
        expect(store.carried).toEqual([Date.parse("2035-01-01T00:00:00Z")]);
        expect(options.setterCalls).toBe(0);
    });

    it("verifyPdfTimestamps: an inherited setter cannot swallow the frozen instant", async () => {
        const store = new CarryingWindowStore();
        const checkDate = expiredDate();
        const options = new InheritedDateOptions(store, checkDate);
        const pending = verifyPdfTimestamps(lapsed.pdf, options);
        checkDate.setTime(HISTORICAL_DATE.getTime());
        const results = await pending;
        expect(results).toHaveLength(1);
        expect(results[0]?.verified).toBe(false);
        expect(store.carried).toEqual([Date.parse("2035-01-01T00:00:00Z")]);
        expect(options.setterCalls).toBe(0);
    });

    it("verifyTimestamp: a getter-only inherited date yields the frozen value, never throws", async () => {
        const store = new CarryingWindowStore();
        const valid = await verifyTimestamp(
            lapsed.extracted,
            new GetterOnlyDateOptions(store, windowDate(), lapsed.pdf)
        );
        expect(valid.verified).toBe(true);
        const expired = await verifyTimestamp(
            lapsed.extracted,
            new GetterOnlyDateOptions(store, expiredDate(), lapsed.pdf)
        );
        expect(expired.verified).toBe(false);
    });

    it("verifyTimestampsWithSharedIndex: a getter-only inherited date yields the frozen value", async () => {
        const store = new CarryingWindowStore();
        const results = await verifyTimestampsWithSharedIndex(
            [lapsed.extracted],
            new GetterOnlyDateOptions(store, windowDate(), lapsed.pdf)
        );
        expect(results).toHaveLength(1);
        expect(results[0]?.verified).toBe(true);
    });

    it("verifyPdfTimestamps: a getter-only inherited date yields the frozen value", async () => {
        const store = new CarryingWindowStore();
        const results = await verifyPdfTimestamps(
            lapsed.pdf,
            new GetterOnlyDateOptions(store, expiredDate())
        );
        expect(results).toHaveLength(1);
        expect(results[0]?.verified).toBe(false);
    });

    it("verifyPdfTimestamps: an inherited pdf setter cannot swallow the attached bytes", async () => {
        const store = new CarryingWindowStore();
        const tampered = tamperCoveredHeaderByte(lapsed.pdf);
        // Premise: the tamper keeps a parseable PDF with one timestamp.
        expect(await extractTimestamps(tampered)).toHaveLength(1);
        let setterCalls = 0;
        const options = Object.assign(
            Object.create({
                get pdf(): Uint8Array | undefined {
                    return undefined;
                },
                set pdf(_value: Uint8Array | undefined) {
                    setterCalls += 1;
                },
            }),
            { trustStore: store, chainValidationTime: windowDate() }
        ) as VerificationOptions;
        const results = await verifyPdfTimestamps(tampered, options);
        expect(results).toHaveLength(1);
        expect(results[0]?.verified).toBe(false);
        expect(results[0]?.verificationError).toMatch(/Document hash mismatch/);
        expect(setterCalls).toBe(0);
    });

    it("verifyPdfTimestamps: a getter-only inherited pdf cannot block the attach override", async () => {
        const store = new CarryingWindowStore();
        const options = Object.assign(
            Object.create({
                get pdf(): Uint8Array {
                    return new Uint8Array([9, 9, 9]);
                },
            }),
            { trustStore: store, chainValidationTime: windowDate() }
        ) as VerificationOptions;
        const results = await verifyPdfTimestamps(lapsed.pdf, options);
        expect(results).toHaveLength(1);
        expect(results[0]?.verified).toBe(true);
    });

    it("verifyTimestamp: a hostile inherited pdf is read once without invoking its setter", async () => {
        const store = new CarryingWindowStore();
        const tampered = tamperCoveredHeaderByte(lapsed.pdf);
        let setterCalls = 0;
        let getterCalls = 0;
        const options = Object.assign(
            Object.create({
                get pdf(): Uint8Array {
                    getterCalls += 1;
                    return tampered;
                },
                set pdf(_value: Uint8Array) {
                    setterCalls += 1;
                },
            }),
            { trustStore: store, chainValidationTime: windowDate() }
        ) as VerificationOptions;
        const result = await verifyTimestamp(lapsed.extracted, options);
        expect(result.verified).toBe(false);
        expect(result.verificationError).toMatch(/Document hash mismatch/);
        expect(setterCalls).toBe(0);
        expect(getterCalls).toBe(1);
    });

    it("verifyTimestamp honors a WeakMap-backed trustStore getter with the original receiver", async () => {
        const store = new RejectingStore();
        const result = await verifyTimestamp(
            lapsed.extracted,
            weakMapPolicyOptions(windowDate(), store)
        );
        expect(result.verified).toBe(false);
        expect(result.verificationError).toBe("Certificate chain not trusted");
        expect(store.calls).toBe(1);
    });

    it("verifyTimestampsWithSharedIndex honors a WeakMap-backed trustStore getter", async () => {
        const store = new RejectingStore();
        const results = await verifyTimestampsWithSharedIndex(
            [lapsed.extracted],
            weakMapPolicyOptions(windowDate(), store)
        );
        expect(results).toHaveLength(1);
        expect(results[0]?.verified).toBe(false);
        expect(results[0]?.verificationError).toBe("Certificate chain not trusted");
        expect(store.calls).toBe(1);
    });

    it("verifyPdfTimestamps honors a WeakMap-backed trustStore getter", async () => {
        const store = new RejectingStore();
        const results = await verifyPdfTimestamps(
            lapsed.pdf,
            weakMapPolicyOptions(windowDate(), store)
        );
        expect(results).toHaveLength(1);
        expect(results[0]?.verified).toBe(false);
        expect(results[0]?.verificationError).toBe("Certificate chain not trusted");
        expect(store.calls).toBe(1);
    });

    it("verifyTimestamp honors a receiver-sensitive trustStore getter", async () => {
        const store = new RejectingStore();
        const result = await verifyTimestamp(
            lapsed.extracted,
            receiverSensitivePolicyOptions(windowDate(), store)
        );
        expect(result.verified).toBe(false);
        expect(result.verificationError).toBe("Certificate chain not trusted");
        expect(store.calls).toBe(1);
    });

    it("verifyPdfTimestamps honors a receiver-sensitive trustStore getter", async () => {
        const store = new RejectingStore();
        const results = await verifyPdfTimestamps(
            lapsed.pdf,
            receiverSensitivePolicyOptions(windowDate(), store)
        );
        expect(results).toHaveLength(1);
        expect(results[0]?.verified).toBe(false);
        expect(results[0]?.verificationError).toBe("Certificate chain not trusted");
        expect(store.calls).toBe(1);
    });

    it("verifyTimestamp honors a proxy-supplied trust policy", async () => {
        const store = new RejectingStore();
        const result = await verifyTimestamp(
            lapsed.extracted,
            proxyPolicyOptions(windowDate(), store)
        );
        expect(result.verified).toBe(false);
        expect(result.verificationError).toBe("Certificate chain not trusted");
        expect(store.calls).toBe(1);
    });

    it("verifyTimestampsWithSharedIndex honors a proxy-supplied trust policy", async () => {
        const store = new RejectingStore();
        const results = await verifyTimestampsWithSharedIndex(
            [lapsed.extracted],
            proxyPolicyOptions(windowDate(), store)
        );
        expect(results).toHaveLength(1);
        expect(results[0]?.verified).toBe(false);
        expect(results[0]?.verificationError).toBe("Certificate chain not trusted");
        expect(store.calls).toBe(1);
    });

    it("verifyPdfTimestamps honors a proxy-supplied trust policy", async () => {
        const store = new RejectingStore();
        const results = await verifyPdfTimestamps(
            lapsed.pdf,
            proxyPolicyOptions(windowDate(), store)
        );
        expect(results).toHaveLength(1);
        expect(results[0]?.verified).toBe(false);
        expect(results[0]?.verificationError).toBe("Certificate chain not trusted");
        expect(store.calls).toBe(1);
    });

    it("archiveTimestamp strict mode enforces a WeakMap-backed trustStore before any TSA call", async () => {
        const store = new RejectingStore();
        const fetchMock = vi.fn(async () => {
            throw new Error("TSA must not be reached");
        });
        vi.stubGlobal("fetch", fetchMock);
        try {
            await expect(
                archiveTimestamp({
                    pdf: lapsed.pdf,
                    tsa: { url: "https://tsa.example.invalid/tsa" },
                    strictExistingVerification: true,
                    existingTimestampVerifyOptions: weakMapPolicyOptions(windowDate(), store),
                })
            ).rejects.toMatchObject({ code: TimestampErrorCode.VERIFICATION_FAILED });
            expect(fetchMock).not.toHaveBeenCalled();
            expect(store.calls).toBe(1);
        } finally {
            vi.unstubAllGlobals();
        }
    });

    it("archiveTimestamp strict mode enforces a proxy-supplied trust policy before any TSA call", async () => {
        const store = new RejectingStore();
        const fetchMock = vi.fn(async () => {
            throw new Error("TSA must not be reached");
        });
        vi.stubGlobal("fetch", fetchMock);
        try {
            await expect(
                archiveTimestamp({
                    pdf: lapsed.pdf,
                    tsa: { url: "https://tsa.example.invalid/tsa" },
                    strictExistingVerification: true,
                    existingTimestampVerifyOptions: proxyPolicyOptions(windowDate(), store),
                })
            ).rejects.toMatchObject({ code: TimestampErrorCode.VERIFICATION_FAILED });
            expect(fetchMock).not.toHaveBeenCalled();
            expect(store.calls).toBe(1);
        } finally {
            vi.unstubAllGlobals();
        }
    });

    it("archiveTimestamp strict mode rejects a tampered PDF despite an inherited pdf setter", async () => {
        const store = new CarryingWindowStore();
        const tampered = tamperCoveredHeaderByte(lapsed.pdf);
        const fetchMock = vi.fn(async () => {
            throw new Error("TSA must not be reached");
        });
        vi.stubGlobal("fetch", fetchMock);
        try {
            let setterCalls = 0;
            const options = Object.assign(
                Object.create({
                    get pdf(): Uint8Array | undefined {
                        return undefined;
                    },
                    set pdf(_value: Uint8Array | undefined) {
                        setterCalls += 1;
                    },
                }),
                { trustStore: store, chainValidationTime: windowDate() }
            ) as VerificationOptions;
            await expect(
                archiveTimestamp({
                    pdf: tampered,
                    tsa: { url: "https://tsa.example.invalid/tsa" },
                    strictExistingVerification: true,
                    existingTimestampVerifyOptions: options,
                })
            ).rejects.toMatchObject({ code: TimestampErrorCode.VERIFICATION_FAILED });
            expect(fetchMock).not.toHaveBeenCalled();
            expect(setterCalls).toBe(0);
        } finally {
            vi.unstubAllGlobals();
        }
    });

    it("shared-index verification maps a throwing trustStore getter to verified:false", async () => {
        const results = await verifyTimestampsWithSharedIndex(
            [lapsed.extracted],
            throwingPolicyOptions(windowDate(), "boom-shared")
        );
        expect(results).toHaveLength(1);
        expect(results[0]?.verified).toBe(false);
        expect(results[0]?.verificationError).toContain("boom-shared");
        expect(results[0]?.verificationErrorCode).toBe(TimestampErrorCode.VERIFICATION_FAILED);
    });

    it("PDF verification maps a throwing trustStore getter to verified:false", async () => {
        const results = await verifyPdfTimestamps(
            lapsed.pdf,
            throwingPolicyOptions(windowDate(), "boom-pdf")
        );
        expect(results).toHaveLength(1);
        expect(results[0]?.verified).toBe(false);
        expect(results[0]?.verificationError).toContain("boom-pdf");
        expect(results[0]?.verificationErrorCode).toBe(TimestampErrorCode.VERIFICATION_FAILED);
    });

    it("archiveTimestamp strict mode maps a throwing trustStore getter before any TSA call", async () => {
        const fetchMock = vi.fn(async () => {
            throw new Error("TSA must not be reached");
        });
        vi.stubGlobal("fetch", fetchMock);
        try {
            await expect(
                archiveTimestamp({
                    pdf: lapsed.pdf,
                    tsa: { url: "https://tsa.example.invalid/tsa" },
                    strictExistingVerification: true,
                    existingTimestampVerifyOptions: throwingPolicyOptions(
                        windowDate(),
                        "boom-archive"
                    ),
                })
            ).rejects.toMatchObject({ code: TimestampErrorCode.VERIFICATION_FAILED });
            expect(fetchMock).not.toHaveBeenCalled();
        } finally {
            vi.unstubAllGlobals();
        }
    });

    it("verifyTimestamp maps a throwing prototype trustStore getter to verified:false", async () => {
        const options = Object.assign(
            Object.create({
                get trustStore(): TrustStore {
                    throw new Error("boom-proto");
                },
            }),
            { chainValidationTime: windowDate() }
        ) as VerificationOptions;
        const result = await verifyTimestamp(lapsed.extracted, options);
        expect(result.verified).toBe(false);
        expect(result.verificationError).toContain("boom-proto");
        expect(result.verificationErrorCode).toBe(TimestampErrorCode.VERIFICATION_FAILED);
    });
});

describe("withOwn override mechanics (T09b-N2/N3 unit)", () => {
    it("defines the override without invoking an inherited setter", () => {
        let setterCalls = 0;
        const options = Object.assign(
            Object.create({
                get chainValidationTime(): Date {
                    return new Date(0);
                },
                set chainValidationTime(_value: Date) {
                    setterCalls += 1;
                },
            }),
            { trustStore: undefined }
        );
        const clone = withOwn(options, "chainValidationTime", new Date(1234));
        expect(setterCalls).toBe(0);
        expect(clone.chainValidationTime).toEqual(new Date(1234));
        expect(Object.getOwnPropertyDescriptor(clone, "chainValidationTime")).toMatchObject({
            writable: true,
            enumerable: true,
            configurable: true,
        });
    });

    it("defines the override over a getter-only inherited shape", () => {
        const options = Object.assign(
            Object.create({
                get pdf(): Uint8Array | undefined {
                    return undefined;
                },
            }),
            {}
        );
        const clone = withOwn(options, "pdf", new Uint8Array([1]));
        expect(clone.pdf).toEqual(new Uint8Array([1]));
    });

    it("reads policy getters eagerly with the original receiver", () => {
        const policies = new WeakMap<object, TrustStore>();
        const store = { marker: true } as unknown as TrustStore;
        const options = {
            get trustStore(): TrustStore | undefined {
                return policies.get(this);
            },
        };
        policies.set(options, store);
        const clone = withOwn(options, "chainValidationTime", "current");
        expect(clone.trustStore).toBe(store);
    });

    it("reads a proxy-supplied policy through the get trap", () => {
        const store = { marker: true } as unknown as TrustStore;
        const options = new Proxy(
            { chainValidationTime: new Date(0), trustStore: undefined } as VerificationOptions,
            {
                get(target, key, receiver): unknown {
                    if (key === "trustStore") return store;
                    return Reflect.get(target, key, receiver);
                },
            }
        );
        const clone = withOwn(options, "chainValidationTime", "current");
        expect(clone.trustStore).toBe(store);
    });

    it("invokes each policy getter exactly once", () => {
        let reads = 0;
        const options = {
            get trustStore(): TrustStore | undefined {
                reads += 1;
                return undefined;
            },
        };
        withOwn(options, "pdf", new Uint8Array([1]));
        expect(reads).toBe(1);
    });

    it("defers a throwing policy getter instead of throwing uncoded", () => {
        const options = {
            get trustStore(): TrustStore {
                throw new Error("boom");
            },
        };
        const clone = withOwn(options, "chainValidationTime", "current");
        expect(() => clone.trustStore).toThrow("boom");
    });

    it("materializes frozen policy values as writable own properties", () => {
        const store = { marker: true } as unknown as TrustStore;
        const options = Object.freeze({
            trustStore: store,
            chainValidationTime: "current" as const,
        });
        const clone = withOwn(options, "pdf", new Uint8Array([1]));
        expect(clone.trustStore).toBe(store);
        expect(Object.getOwnPropertyDescriptor(clone, "trustStore")).toMatchObject({
            writable: true,
            enumerable: true,
            configurable: true,
        });
    });
});
