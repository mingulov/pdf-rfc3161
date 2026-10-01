// T00/T18 real-browser signing fixture: page-side journeys.
//
// This module is bundled with esbuild (platform "browser", no Node
// polyfills) against the PACKED candidate under test and executed in a
// real browser page (Chromium, Firefox, WebKit) by
// scripts/test-browser-consumer.ts. It must not use Node built-ins,
// process/require/Buffer, or the filesystem: the harness asserts a
// browser-only runtime before running any journey. Journey logic is
// engine-neutral; engine differences surface as per-engine receipts.
//
// Extension hooks for later tasks (T01/T02/T03/T09/T12): each
// exported function is one documented fixture entry point. Add a new
// exported function plus its result interface here, bundle it through the
// existing entry (exposed on globalThis.__T00__ below), drive it from
// test-browser-consumer.ts via page.evaluate, and assert on the returned
// plain data in Node. All arguments and return values must survive
// structured clone (plain JSON data only, PDF bytes as number[]).
import {
    SimpleTrustStore,
    TimestampError,
    TimestampSession,
    extractTimestamps,
    sendTimestampRequest,
    timestampPdf,
    verifyPdfTimestamps,
} from "pdf-rfc3161";
import { extractSignatures, verify } from "verifiedby";

/** Controlled test-TSA endpoints served by test-browser-consumer.ts. */
export interface T00Urls {
    /** Correctly signed openssl responses with proper CORS headers. */
    tsa: string;
    /** Signer certificate carries an OCSP AIA URL (CORS-denied revocation). */
    tsaAia: string;
    /** Crafted pre-embed rejection tokens (valid transport, CORS *). */
    rejectDigest: string;
    rejectNonce: string;
    rejectSignature: string;
    rejectEss: string;
    rejectEku: string;
    /** Valid crafted token: control for the rejection family (same fixture). */
    craftedValid: string;
    /** Token whose CMS bag carries an unrelated trusted intermediate (T01). */
    trustTarget: string;
    /** Expired signer certificate (T09 hook: observation only). */
    expiredSigner: string;
    /** Correctly signed responses WITHOUT CORS headers (must fail in page). */
    tsaNoCors: string;
    /** 307 redirect (T02 hook: observation only). */
    redirect: string;
    /** Stalled body (T02 hook: observation only). */
    stall: string;
    /** Opaque-response endpoint (T02 hook: observation only). */
    opaque: string;
}

export interface PositiveJourneySummary {
    status: string;
    timestampCount: number;
    genTime: string;
    hashAlg: string | null;
    trailingKinds: (string | undefined)[];
    everyElementAuthentic: boolean;
    tamperStatus: string;
}

export interface PositiveJourneyOutput {
    name: string;
    bytes: number[];
    summary: PositiveJourneySummary;
}

/** A signed output whose token carries no certificates (certReq=false). */
export interface CertlessJourneyOutput {
    name: string;
    bytes: number[];
    /** Downstream verdict: the pinned engine cannot evaluate certless tokens. */
    status: string;
    dictType: string | null;
    subFilter: string | null;
}

export interface RejectionOutcome {
    name: string;
    /** Which public API surface produced this outcome. */
    api: "session" | "one-call";
    rejected: boolean;
    code: string | null;
    message: string;
}

/**
 * Expected downstream shape of one positive output: exact trailing
 * classification and coverage per element. LTV outputs always trail
 * data (the DSS append / later timestamp), so coversWholeFile is false;
 * only a bare timestamp with no later update reports kind "none".
 */
export interface PositiveExpectation {
    trailingKinds: string[];
    coversWholeFile: boolean[];
}

export interface TrustStoreSummary {
    count: number;
    verified: boolean[];
    errors: (string | null)[];
}

export interface CorsOutcome {
    tsaDenied: RejectionOutcome;
    /** LTV signing with CORS-denied OCSP must still return PDF bytes. */
    revocationDeniedPdf: number[];
    revocationDeniedLtv: { certificates: number; crls: number; ocspResponses: number };
    defaultVerify: TrustStoreSummary;
    nullTrustStoreVerify: TrustStoreSummary;
    customTrustStoreVerify: TrustStoreSummary;
}

export interface SignerValidityObservation {
    embedded: boolean;
    code: string | null;
    message: string;
}

/** Post-embed trust verdict for a token with a poisoned certificate bag. */
export interface TrustTargetOutcome {
    name: string;
    /** The pre-embed gate accepts the token; only trust must fail. */
    embedded: boolean;
    count: number;
    verified: boolean;
    error: string | null;
    /** Proves the unrelated intermediate rode along in the CMS bag. */
    certificateCount: number;
}

export interface TransportObservation {
    name: string;
    /** "hung" means the attempt never settled within the hook's bound. */
    outcome: "signed" | "rejected" | "hung";
    code: string | null;
    message: string;
    elapsedMs: number;
}

export interface RuntimeProbe {
    userAgent: string;
    hasCryptoSubtle: boolean;
    webdriver: boolean;
    /** Node globals that must all be absent in the page. */
    nodeGlobalsPresent: string[];
}

function check(condition: unknown, message: string): asserts condition {
    if (!condition) throw new Error(message);
}

/** Proves the journeys execute in a real browser without Node shims. */
export function runtimeProbe(): RuntimeProbe {
    const globalScope = globalThis as unknown as Record<string, unknown>;
    const nodeGlobalsPresent = ["process", "require", "Buffer", "__dirname", "__filename"].filter(
        (name) => globalScope[name] !== undefined
    );
    return {
        userAgent: navigator.userAgent,
        hasCryptoSubtle:
            typeof crypto !== "undefined" && typeof crypto.subtle.digest === "function",
        webdriver: navigator.webdriver,
        nodeGlobalsPresent,
    };
}

async function recordPositive(
    name: string,
    bytes: Uint8Array,
    count: number,
    expected: PositiveExpectation,
    expectedTime?: Date
): Promise<PositiveJourneyOutput> {
    const parsed = extractSignatures(bytes);
    check(
        parsed.length === count &&
            parsed.every(
                (item) => item.dictType === "DocTimeStamp" && item.subFilter === "ETSI.RFC3161"
            ),
        `${name}: expected ${count.toString()} raw DocTimeStamp dictionaries`
    );
    const verdict = await verify(bytes);
    check(
        verdict.status === "verified-untrusted-root" &&
            verdict.timestampCount === count &&
            verdict.documentMatches === true,
        `${name}: unexpected downstream aggregate verdict ${verdict.status}`
    );
    check(verdict.elements.length === count, `${name}: every timestamp must be examined`);
    for (const [index, element] of verdict.elements.entries()) {
        for (const flag of [
            "documentMatches",
            "signatureValid",
            "attrsCommit",
            "chainValid",
            "withinValidity",
            "authentic",
        ] as const) {
            check(element[flag] === true, `${name}: downstream ${flag} must be true`);
        }
        check(
            element.trailingKind === expected.trailingKinds[index],
            `${name}: element ${index.toString()} trailing must be ${expected.trailingKinds[index] ?? "(missing)"}`
        );
        const covers = parsed[index]?.coversWholeFile;
        check(
            covers === expected.coversWholeFile[index],
            `${name}: element ${index.toString()} coverage mismatch`
        );
        if (expected.coversWholeFile[index] === false) {
            check(
                (parsed[index]?.trailingBytes ?? 0) > 0,
                `${name}: element ${index.toString()} must trail appended bytes`
            );
        }
    }
    if (expectedTime !== undefined) {
        check(
            verdict.genTime?.toISOString() === expectedTime.toISOString(),
            `${name}: latest time metadata must match`
        );
    }
    check(
        JSON.stringify(verdict.byteRange) === JSON.stringify(parsed[count - 1]?.byteRange ?? null),
        `${name}: outermost ByteRange must be selected`
    );
    const tampered = new Uint8Array(bytes);
    let changed = false;
    const firstRange = parsed[0]?.byteRange;
    check(firstRange !== undefined, `${name}: first ByteRange must exist`);
    for (let index = 16; index < firstRange[1]; index++) {
        if (tampered[index] === 10) {
            tampered[index] = 13;
            changed = true;
            break;
        }
    }
    check(changed, `${name}: covered whitespace tamper control must apply`);
    const bad = await verify(tampered);
    check(
        bad.status === "mismatch" && bad.documentMatches === false,
        `${name}: covered-byte tampering must be rejected`
    );
    return {
        name,
        bytes: Array.from(bytes),
        summary: {
            status: verdict.status,
            timestampCount: verdict.timestampCount ?? 0,
            genTime: verdict.genTime?.toISOString() ?? "",
            hashAlg: verdict.hashAlg ?? null,
            trailingKinds: verdict.elements.map((element) => element.trailingKind),
            everyElementAuthentic: true,
            tamperStatus: bad.status,
        },
    };
}

/**
 * Expected downstream shapes. The modern input uses object streams, so
 * its DSS lands in a compressed stream with no literal markers and the
 * engine reports "appended-data"; the classic input keeps literal
 * objects, so its DSS reports "signature-update". A second timestamp
 * leaves signature markers behind the first element.
 */
const MODERN_LTV_SHAPE: PositiveExpectation = {
    trailingKinds: ["appended-data"],
    coversWholeFile: [false],
};
const CLASSIC_LTV_SHAPE: PositiveExpectation = {
    trailingKinds: ["signature-update"],
    coversWholeFile: [false],
};
const SECOND_TIMESTAMP_SHAPE: PositiveExpectation = {
    trailingKinds: ["signature-update", "appended-data"],
    coversWholeFile: [false, false],
};

/**
 * Baseline positive journeys (T00 gate): one-call direct-TSA signing on
 * two inputs, a second timestamp preserving the earlier signature, a
 * manual TimestampSession journey, and a one-call journey with enableLTV
 * omitted (C01 default behavior). Later tasks extend this file with
 * their own entry points instead of changing these baselines.
 */
export async function runPositiveJourneys(
    inputs: Record<string, number[]>,
    urls: T00Urls,
    policy: string
): Promise<PositiveJourneyOutput[]> {
    const outputs: PositiveJourneyOutput[] = [];
    let firstModern: Uint8Array | undefined;
    for (const [name, input] of Object.entries(inputs)) {
        const original = new Uint8Array(input);
        const result = await timestampPdf({
            pdf: original,
            tsa: { url: urls.tsa, policy, retry: 0 },
            enableLTV: true,
        });
        check(
            result.pdf instanceof Uint8Array && result.timestamp.genTime instanceof Date,
            `${name}: public result shape`
        );
        check(
            result.ltvData?.certificates.length === 2,
            `${name}: one-call LTV returns the fixture chain`
        );
        check(
            original.every((value, index) => result.pdf[index] === value),
            `${name}: original PDF prefix preserved`
        );
        outputs.push(
            await recordPositive(
                `${name}-one-call-ltv`,
                result.pdf,
                1,
                name === "classic" ? CLASSIC_LTV_SHAPE : MODERN_LTV_SHAPE,
                result.timestamp.genTime
            )
        );
        if (name === "modern") firstModern = result.pdf;
    }
    check(firstModern !== undefined, "modern input must exist");
    const second = await timestampPdf({
        pdf: firstModern,
        tsa: { url: urls.tsa, policy, retry: 0 },
        enableLTV: true,
    });
    check(
        firstModern.every((value, index) => second.pdf[index] === value),
        "first sealed PDF prefix preserved"
    );
    check(
        JSON.stringify(extractSignatures(firstModern)[0]?.byteRange) ===
            JSON.stringify(extractSignatures(second.pdf)[0]?.byteRange),
        "first ByteRange preserved"
    );
    outputs.push(
        await recordPositive(
            "modern-second-timestamp",
            second.pdf,
            2,
            SECOND_TIMESTAMP_SHAPE,
            second.timestamp.genTime
        )
    );

    const modernInput = inputs.modern;
    check(modernInput !== undefined, "modern input must exist");
    const session = new TimestampSession(new Uint8Array(modernInput), { enableLTV: true });
    try {
        const request = await session.createTimestampRequest({
            hashAlgorithm: "SHA-256",
            policy,
            requestCertificate: true,
        });
        const response = await sendTimestampRequest(request, { url: urls.tsa, retry: 0 });
        const manual = await session.embedTimestampToken(response);
        outputs.push(await recordPositive("modern-manual-session", manual, 1, MODERN_LTV_SHAPE));
    } finally {
        session.dispose();
    }

    // C01 default behavior: enableLTV omitted must still sign with LTV.
    const defaultLtv = await timestampPdf({
        pdf: new Uint8Array(modernInput),
        tsa: { url: urls.tsa, policy, retry: 0 },
    });
    check(
        defaultLtv.ltvData?.certificates.length === 2,
        "default-ltv: omitted enableLTV still returns the fixture chain"
    );
    check(
        new Uint8Array(modernInput).every((value, index) => defaultLtv.pdf[index] === value),
        "default-ltv: original PDF prefix preserved"
    );
    outputs.push(
        await recordPositive(
            "modern-default-ltv",
            defaultLtv.pdf,
            1,
            MODERN_LTV_SHAPE,
            defaultLtv.timestamp.genTime
        )
    );
    return outputs;
}

/**
 * Manual certReq=false journey with a user-supplied signer certificate:
 * the TSA omits the certificate bag and the caller provides the signer.
 * The library validates and embeds in-page; the downstream oracle
 * explicitly reports "unsupported" for certless tokens (a documented
 * consumer limit: it needs the signer certificate to evaluate).
 */
export async function runManualCertReqFalseJourney(
    input: number[],
    urls: T00Urls,
    policy: string,
    tsaSignerCert: number[]
): Promise<CertlessJourneyOutput> {
    const original = new Uint8Array(input);
    const session = new TimestampSession(original, { enableLTV: false });
    try {
        const request = await session.createTimestampRequest({
            hashAlgorithm: "SHA-256",
            policy,
            requestCertificate: false,
        });
        const response = await sendTimestampRequest(request, { url: urls.tsa, retry: 0 });
        const manual = await session.embedTimestampToken(response, {
            signerCertificates: [new Uint8Array(tsaSignerCert)],
        });
        const name = "modern-manual-certreq-false";
        check(
            original.every((value, index) => manual[index] === value),
            `${name}: original PDF prefix preserved`
        );
        const parsed = extractSignatures(manual);
        const first = parsed[0];
        check(first !== undefined, `${name}: signature dictionary must exist`);
        check(
            parsed.length === 1 &&
                first.dictType === "DocTimeStamp" &&
                first.subFilter === "ETSI.RFC3161",
            `${name}: one raw DocTimeStamp dictionary`
        );
        const verdict = await verify(manual);
        check(verdict.status === "unsupported", `${name}: certless downstream verdict`);
        return {
            name,
            bytes: Array.from(manual),
            status: verdict.status,
            dictType: first.dictType,
            subFilter: first.subFilter,
        };
    } finally {
        session.dispose();
    }
}

const REJECTION_CASES: { name: string; url: (urls: T00Urls) => string }[] = [
    { name: "wrong-digest", url: (urls) => urls.rejectDigest },
    { name: "wrong-nonce", url: (urls) => urls.rejectNonce },
    { name: "invalid-signature", url: (urls) => urls.rejectSignature },
    { name: "invalid-ess", url: (urls) => urls.rejectEss },
    { name: "invalid-eku", url: (urls) => urls.rejectEku },
];

function rejectionOutcome(
    name: string,
    api: "session" | "one-call",
    error: unknown
): RejectionOutcome {
    if (
        error instanceof Error &&
        error.message.endsWith("unexpectedly embedded a rejected token")
    ) {
        throw error;
    }
    return {
        name,
        api,
        rejected: true,
        code: error instanceof TimestampError ? error.code : null,
        message: error instanceof Error ? error.message : String(error),
    };
}

/**
 * Mandatory pre-embed rejection cases executed in the page on BOTH API
 * surfaces: the manual TimestampSession path and the one-call timestampPdf
 * path. Every case must fail signing with no successful embed result.
 * The harness asserts the exact error codes plus case-specific failure
 * reasons in Node; later tasks add their cases to REJECTION_CASES plus
 * a matching server endpoint.
 */
export async function runRejectionCases(
    input: number[],
    urls: T00Urls,
    policy: string
): Promise<RejectionOutcome[]> {
    const outcomes: RejectionOutcome[] = [];
    for (const { name, url } of REJECTION_CASES) {
        const session = new TimestampSession(new Uint8Array(input), { enableLTV: false });
        try {
            const request = await session.createTimestampRequest({
                hashAlgorithm: "SHA-256",
                policy,
                requestCertificate: true,
            });
            const response = await sendTimestampRequest(request, { url: url(urls), retry: 0 });
            await session.embedTimestampToken(response);
            throw new Error(`${name}: unexpectedly embedded a rejected token`);
        } catch (error) {
            outcomes.push(rejectionOutcome(name, "session", error));
        } finally {
            session.dispose();
        }
    }
    for (const { name, url } of REJECTION_CASES) {
        try {
            await timestampPdf({
                pdf: new Uint8Array(input),
                tsa: { url: url(urls), policy, retry: 0 },
                enableLTV: false,
            });
            throw new Error(`${name}: unexpectedly embedded a rejected token`);
        } catch (error) {
            outcomes.push(rejectionOutcome(name, "one-call", error));
        }
    }
    return outcomes;
}

/**
 * Valid control for the crafted-token family: the same fixture that
 * serves the rejection endpoints returns a fully valid token here, and
 * both API surfaces must embed it. The pinned downstream engine cannot
 * parse this fixture's CMS (a documented consumer limit, like the
 * certless journey), so the page asserts the embedded dictionary shape
 * and the harness asserts byte-level token preservation in Node.
 */
export async function runCraftedValidControl(
    input: number[],
    urls: T00Urls,
    policy: string
): Promise<{ session: CertlessJourneyOutput; oneCall: CertlessJourneyOutput }> {
    const original = new Uint8Array(input);
    const checkControl = async (
        name: string,
        bytes: Uint8Array
    ): Promise<CertlessJourneyOutput> => {
        check(
            original.every((value, index) => bytes[index] === value),
            `${name}: original PDF prefix preserved`
        );
        const parsed = extractSignatures(bytes);
        const first = parsed[0];
        check(first !== undefined, `${name}: signature dictionary must exist`);
        check(
            parsed.length === 1 &&
                first.dictType === "DocTimeStamp" &&
                first.subFilter === "ETSI.RFC3161",
            `${name}: one raw DocTimeStamp dictionary`
        );
        const verdict = await verify(bytes);
        check(verdict.status === "unsupported", `${name}: crafted-token engine limit`);
        return {
            name,
            bytes: Array.from(bytes),
            status: verdict.status,
            dictType: first.dictType,
            subFilter: first.subFilter,
        };
    };

    const manual = new TimestampSession(original, { enableLTV: false });
    let sessionBytes: Uint8Array;
    try {
        const request = await manual.createTimestampRequest({
            hashAlgorithm: "SHA-256",
            policy,
            requestCertificate: true,
        });
        const response = await sendTimestampRequest(request, {
            url: urls.craftedValid,
            retry: 0,
        });
        sessionBytes = await manual.embedTimestampToken(response);
    } finally {
        manual.dispose();
    }
    const oneCall = await timestampPdf({
        pdf: original,
        tsa: { url: urls.craftedValid, policy, retry: 0 },
        enableLTV: false,
    });
    return {
        session: await checkControl("crafted-valid-session", sessionBytes),
        oneCall: await checkControl("crafted-valid-one-call", oneCall.pdf),
    };
}

/**
 * Bounded resource-limit rejection: a small input with a deliberately
 * smaller maxSize must fail with PDF_ERROR before any TSA request. The
 * harness asserts zero server-side TSA requests across this probe, so
 * the bound is proven without allocating a hostile PDF.
 */
export async function probeResourceLimit(
    input: number[],
    tsaUrl: string
): Promise<RejectionOutcome> {
    const original = new Uint8Array(input);
    check(original.length > 64, "resource-limit probe needs a nontrivial input");
    try {
        await timestampPdf({
            pdf: original,
            tsa: { url: tsaUrl, retry: 0 },
            maxSize: 64,
        });
        throw new Error("resource-limit-max-size: unexpectedly signed an over-limit PDF");
    } catch (error) {
        if (
            error instanceof Error &&
            error.message.endsWith("unexpectedly signed an over-limit PDF")
        ) {
            throw error;
        }
        return {
            name: "resource-limit-max-size",
            api: "one-call",
            rejected: true,
            code: error instanceof TimestampError ? error.code : null,
            message: error instanceof Error ? error.message : String(error),
        };
    }
}

/**
 * T03 placeholder/input bound negatives: invalid reservations and ceilings
 * must reject with INVALID_ARGUMENT/PDF_ERROR before any TSA request. The
 * harness asserts zero server-side TSA requests across this probe, so the
 * bounds are proven without allocating hostile PDFs or reservations.
 */
export async function probePlaceholderBounds(
    input: number[],
    tsaUrl: string
): Promise<RejectionOutcome[]> {
    const original = new Uint8Array(input);
    check(original.length > 64, "placeholder-bounds probe needs a nontrivial input");
    const outcomes: RejectionOutcome[] = [];
    const attempt = async (
        name: string,
        api: RejectionOutcome["api"],
        fn: () => Promise<unknown>
    ): Promise<void> => {
        try {
            await fn();
            throw new Error(`${name}: unexpectedly succeeded`);
        } catch (error) {
            if (error instanceof Error && error.message.endsWith("unexpectedly succeeded")) {
                throw error;
            }
            outcomes.push({
                name,
                api,
                rejected: true,
                code: error instanceof TimestampError ? error.code : null,
                message: error instanceof Error ? error.message : String(error),
            });
        }
    };

    await attempt("oversize-reservation", "one-call", () =>
        timestampPdf({
            pdf: original,
            tsa: { url: tsaUrl, retry: 0 },
            signatureSize: 70000,
        })
    );
    await attempt("infinite-reservation", "one-call", () =>
        timestampPdf({
            pdf: original,
            tsa: { url: tsaUrl, retry: 0 },
            signatureSize: Number.POSITIVE_INFINITY,
        })
    );
    await attempt("nan-reservation", "session", async () => {
        const session = new TimestampSession(original, {
            prepareOptions: { signatureSize: Number.NaN },
        });
        await session.createTimestampRequest();
    });
    await attempt("setter-nan-reservation", "session", async () => {
        const session = new TimestampSession(original);
        session.setSignatureSize(Number.NaN);
        await session.createTimestampRequest();
    });
    await attempt("invalid-ceiling", "one-call", () =>
        timestampPdf({ pdf: original, tsa: { url: tsaUrl, retry: 0 }, maxSize: 0 })
    );
    await attempt("extract-over-ceiling", "one-call", () =>
        extractTimestamps(original, { maxSize: 64 })
    );
    return outcomes;
}

/**
 * CORS matrix executed in the page with real browser enforcement: a
 * CORS-denied TSA must fail signing clearly, while CORS-denied optional
 * revocation collection must still return signed bytes. Post-embed
 * verification runs through verifyPdfTimestamps with explicit
 * trustStore:null/custom stores.
 */
export async function runCorsCases(
    input: number[],
    urls: T00Urls,
    policy: string,
    rootDer: number[]
): Promise<CorsOutcome> {
    const original = new Uint8Array(input);
    let tsaDenied: RejectionOutcome;
    try {
        await timestampPdf({ pdf: original, tsa: { url: urls.tsaNoCors, retry: 0 } });
        throw new Error("cors-denied-tsa: unexpectedly signed");
    } catch (error) {
        if (error instanceof Error && error.message.endsWith("unexpectedly signed")) throw error;
        tsaDenied = {
            name: "cors-denied-tsa",
            api: "one-call",
            rejected: true,
            code: error instanceof TimestampError ? error.code : null,
            message: error instanceof Error ? error.message : String(error),
        };
    }

    const ltvResult = await timestampPdf({
        pdf: original,
        tsa: { url: urls.tsaAia, policy, retry: 0 },
        enableLTV: true,
    });
    check(
        ltvResult.pdf.length > original.length,
        "cors-denied revocation must still return signed bytes"
    );

    const summarize = async (store: "default" | "null" | "custom"): Promise<TrustStoreSummary> => {
        const trustStore =
            store === "custom"
                ? (() => {
                      const custom = new SimpleTrustStore();
                      custom.addCertificate(new Uint8Array(rootDer));
                      return custom;
                  })()
                : undefined;
        const verified = await verifyPdfTimestamps(
            ltvResult.pdf,
            store === "null" ? { trustStore: null } : trustStore === undefined ? {} : { trustStore }
        );
        return {
            count: verified.length,
            verified: verified.map((item) => item.verified),
            errors: verified.map((item) => item.verificationError ?? null),
        };
    };

    return {
        tsaDenied,
        revocationDeniedPdf: Array.from(ltvResult.pdf),
        revocationDeniedLtv: {
            certificates: ltvResult.ltvData?.certificates.length ?? 0,
            crls: ltvResult.ltvData?.crls.length ?? 0,
            ocspResponses: ltvResult.ltvData?.ocspResponses.length ?? 0,
        },
        defaultVerify: await summarize("default"),
        nullTrustStoreVerify: await summarize("null"),
        customTrustStoreVerify: await summarize("custom"),
    };
}

/**
 * T01 trust-target regression: embeds a token whose unsigned CMS bag
 * carries an unrelated intermediate chaining to the pinned root, then
 * verifies through the post-embed journey. The signer itself is
 * untrusted, so the verdict must be false: the bag entry must not
 * verify in the signer's place.
 */
export async function runTrustTargetCase(
    input: number[],
    urls: T00Urls,
    policy: string,
    rootDer: number[]
): Promise<TrustTargetOutcome> {
    const session = new TimestampSession(new Uint8Array(input), { enableLTV: false });
    try {
        const request = await session.createTimestampRequest({
            hashAlgorithm: "SHA-256",
            policy,
            requestCertificate: true,
        });
        const response = await sendTimestampRequest(request, {
            url: urls.trustTarget,
            retry: 0,
        });
        const pdf = await session.embedTimestampToken(response);
        check(pdf.length > input.length, "trust-target: poisoned token must embed");
        const custom = new SimpleTrustStore();
        custom.addCertificate(new Uint8Array(rootDer));
        const verified = await verifyPdfTimestamps(pdf, {
            trustStore: custom,
            strictESSValidation: true,
        });
        const result = verified[0];
        return {
            name: "trust-target",
            embedded: true,
            count: verified.length,
            verified: result?.verified ?? false,
            error: result?.verificationError ?? null,
            certificateCount: result?.certificates?.length ?? 0,
        };
    } finally {
        session.dispose();
    }
}

/**
 * T09 hook: signer validity at genTime is NOT enforced pre-embed on
 * current code. This probe embeds a token whose signer certificate is
 * expired and returns the observation; the strict rejection assertion
 * lands with T09, not here.
 */
export async function probeSignerValidityAtGenTime(
    input: number[],
    urls: T00Urls,
    policy: string
): Promise<SignerValidityObservation> {
    const session = new TimestampSession(new Uint8Array(input), { enableLTV: false });
    try {
        const request = await session.createTimestampRequest({
            hashAlgorithm: "SHA-256",
            policy,
            requestCertificate: true,
        });
        const response = await sendTimestampRequest(request, {
            url: urls.expiredSigner,
            retry: 0,
        });
        await session.embedTimestampToken(response);
        return { embedded: true, code: null, message: "" };
    } catch (error) {
        return {
            embedded: false,
            code: error instanceof TimestampError ? error.code : null,
            message: error instanceof Error ? error.message : String(error),
        };
    } finally {
        session.dispose();
    }
}

/**
 * T02 hook: opaque-response transport probe. The library never selects
 * no-cors mode (its only fetch call site passes no `mode` option, so
 * the browser default `cors` applies), which makes an opaque response
 * unreachable through the product path: a CORS-denied TSA rejects
 * instead (see the tsa-no-cors case). This probe documents that
 * boundary directly with a raw no-cors fetch of a candidate-built TSQ:
 * the server returns a correctly signed token with valid CORS headers,
 * yet the page can read nothing back. Observation only: no assertions
 * here. (The redirect:manual strictness itself is asserted by the runner
 * since T02; this probe only documents why opaque bytes stay unreadable.)
 */
async function probeOpaqueResponse(
    input: number[],
    url: string,
    policy: string
): Promise<TransportObservation> {
    const started = Date.now();
    const session = new TimestampSession(new Uint8Array(input), { enableLTV: false });
    try {
        const tsq = await session.createTimestampRequest({
            hashAlgorithm: "SHA-256",
            policy,
            requestCertificate: true,
        });
        // Exact-size copy: the DOM BodyInit type only accepts an
        // ArrayBuffer-backed view, not a generic Uint8Array.
        const body = new Uint8Array(tsq.length);
        body.set(tsq);
        const response = await fetch(url, {
            method: "POST",
            mode: "no-cors",
            headers: { "Content-Type": "application/timestamp-query" },
            body: body.buffer,
        });
        const readable = await response.arrayBuffer();
        return {
            name: "opaque-response",
            outcome: "rejected",
            code: null,
            message:
                `no-cors hides the token: type=${response.type} ` +
                `status=${response.status.toString()} ` +
                `sentBytes=${tsq.length.toString()} ` +
                `readableBytes=${readable.byteLength.toString()}`,
            elapsedMs: Date.now() - started,
        };
    } catch (error) {
        return {
            name: "opaque-response",
            outcome: "rejected",
            code: error instanceof TimestampError ? error.code : null,
            message: error instanceof Error ? error.message : String(error),
            elapsedMs: Date.now() - started,
        };
    } finally {
        session.dispose();
    }
}

/**
 * T02 transport probes: redirect and stalled-body outcomes are asserted
 * strictly by the runner (its C06 transport cases: redirect rejected, stall
 * rejected with TIMEOUT). The opaque-response probe stays
 * observation-only (raw no-cors fetch, never the product path). Each
 * product-path attempt races a hook-level bound so a never-settling
 * transport documents as "hung" instead of hanging the gate.
 */
export async function probeTransportHooks(
    input: number[],
    urls: T00Urls,
    policy: string
): Promise<TransportObservation[]> {
    const observations: TransportObservation[] = [];
    for (const probe of [
        { name: "redirect", url: urls.redirect, timeout: 30000 },
        { name: "stalled-body", url: urls.stall, timeout: 3000 },
    ] as const) {
        const started = Date.now();
        const attempt = timestampPdf({
            pdf: new Uint8Array(input),
            tsa: { url: probe.url, policy, retry: 0, timeout: probe.timeout },
            enableLTV: false,
        });
        // The race may leave the attempt pending; never report it as an
        // unhandled rejection if it settles after the hook bound.
        void attempt.then(
            () => undefined,
            () => undefined
        );
        const raced = await Promise.race([
            attempt.then(
                () => ({ settled: true as const, error: null }),
                (error: unknown) => ({ settled: true as const, error })
            ),
            new Promise<{ settled: false }>((resolve) => {
                setTimeout(() => {
                    resolve({ settled: false });
                }, 15000);
            }),
        ]);
        const elapsedMs = Date.now() - started;
        if (!raced.settled) {
            observations.push({
                name: probe.name,
                outcome: "hung",
                code: null,
                message: `no settlement within 15000ms (per-attempt timeout ${probe.timeout.toString()}ms)`,
                elapsedMs,
            });
            continue;
        }
        if (raced.error === null) {
            observations.push({
                name: probe.name,
                outcome: "signed",
                code: null,
                message: "",
                elapsedMs,
            });
        } else if (raced.error instanceof Error) {
            observations.push({
                name: probe.name,
                outcome: "rejected",
                code: raced.error instanceof TimestampError ? raced.error.code : null,
                message: raced.error.message,
                elapsedMs,
            });
        } else {
            observations.push({
                name: probe.name,
                outcome: "rejected",
                code: null,
                message: "transport probe rejected with a non-error value",
                elapsedMs,
            });
        }
    }
    observations.push(await probeOpaqueResponse(input, urls.opaque, policy));
    return observations;
}

/**
 * Module-worker smoke: the worker bundle (signer-worker.ts, bundled
 * against the same candidate) signs inside a real module worker on the
 * engine under test. The harness asserts the worker user agent matches
 * the expected engine.
 */
export async function runWorkerJourney(
    workerUrl: string,
    input: number[],
    tsaUrl: string,
    policy: string
): Promise<{ pdf: number[]; workerUserAgent: string }> {
    const worker = new Worker(workerUrl, { type: "module" });
    try {
        const response = await new Promise<{ pdf: number[]; workerUserAgent: string }>(
            (resolve, reject) => {
                const timeout = setTimeout(() => {
                    reject(new Error("worker signing timed out after 60s"));
                }, 60000);
                worker.onmessage = (event: MessageEvent) => {
                    clearTimeout(timeout);
                    const data = event.data as {
                        ok: boolean;
                        pdf?: number[];
                        workerUserAgent?: string;
                        message?: string;
                    };
                    if (data.ok && data.pdf !== undefined) {
                        resolve({
                            pdf: data.pdf,
                            workerUserAgent: data.workerUserAgent ?? "",
                        });
                    } else {
                        reject(new Error(data.message ?? "worker signing failed"));
                    }
                };
                worker.onerror = (event) => {
                    clearTimeout(timeout);
                    reject(new Error(typeof event === "string" ? event : event.message));
                };
                worker.postMessage({ pdf: input, tsaUrl, policy });
            }
        );
        check(response.pdf.length > input.length, "worker must return appended PDF bytes");
        return response;
    } finally {
        worker.terminate();
    }
}

(globalThis as unknown as { __T00__: unknown }).__T00__ = {
    runtimeProbe,
    runPositiveJourneys,
    runManualCertReqFalseJourney,
    runRejectionCases,
    runCraftedValidControl,
    probeResourceLimit,
    probePlaceholderBounds,
    runCorsCases,
    runTrustTargetCase,
    probeSignerValidityAtGenTime,
    probeTransportHooks,
    runWorkerJourney,
};
