// T00/T18 gate: prove PDF timestamp signing works entirely in real browsers.
//
// Packs (or accepts) the core candidate tarball, installs it into an
// isolated temporary consumer, bundles the browser fixtures in
// ../browser against the installed candidate with esbuild (platform
// "browser", no Node polyfills), and executes the signing journeys in
// real browser pages and module workers against a controlled openssl TSA
// with real CORS enforcement. The signing pipeline never runs in Node:
// Node owns transport (servers), the independent verifiedby oracle, and
// assertions over returned plain data.
//
// Usage:
//   corepack pnpm --filter pdf-rfc3161-tests test:browser:package -- "$CORE_TARBALL"
//   corepack pnpm --filter pdf-rfc3161-tests test:browser:package -- --receipt /tmp/t00.json
//   corepack pnpm --filter pdf-rfc3161-tests test:browser:package -- --engine all
//   corepack pnpm --filter pdf-rfc3161-tests test:browser:package -- --engine all \
//       --receipt /tmp/receipt.json --trace-dir /tmp/traces --pdf-export-dir /tmp/pdfs
//
// --trace-dir saves one Playwright trace zip per failed engine
// (trace-<engine>.zip, save-on-failure only). --pdf-export-dir
// exports every candidate-produced PDF as <engine>-<case>.pdf plus a
// SHA-256 manifest.json for the native-reader handoff (T10 consumes
// it; see the browser-matrix job in .github/workflows/ci.yml).
//
// Harness-only routing: the controlled TSA listens on 127.0.0.1 but is
// addressed through the test hostnames below. Chromium maps them through
// --host-resolver-rules; Firefox and WebKit have no such flag, so they
// run behind a harness-local forward proxy that maps the same test
// hostnames to loopback and refuses every other host. Product URL
// validation is never weakened and browser CORS is never disabled.
//
// Later tasks (T01/T02/T03/T09/T12) extend this gate by adding a
// fixture entry point in ../browser plus a server endpoint and Node-side
// assertions here; see the EXTENSION HOOKS comment on driveJourneys.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
    existsSync,
    mkdirSync,
    mkdtempSync,
    readFileSync,
    realpathSync,
    rmSync,
    writeFileSync,
} from "node:fs";
import {
    createServer,
    request as forwardHttpRequest,
    type IncomingMessage,
    type Server,
    type ServerResponse,
} from "node:http";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import * as asn1js from "asn1js";
import { build, type Metafile } from "esbuild";
import {
    PDFArray,
    PDFDict,
    PDFDocument,
    PDFName,
    PDFRef,
    StandardFonts,
} from "pdf-lib-incremental-save";
import * as pkijs from "pkijs";
import { chromium, firefox, webkit } from "playwright";
import { extractSignatures, verify } from "verifiedby";
import type * as SignerPage from "../browser/signer.spec.js";
import type {
    CertlessJourneyOutput,
    CorsOutcome,
    PositiveJourneyOutput,
    RejectionOutcome,
    SignerValidityObservation,
    T00Urls,
    TransportObservation,
    TrustTargetOutcome,
} from "../browser/signer.spec.js";
import { parseTimestampToken } from "../../core/src/tsa/token-validation.js";
import {
    createRFC3161TokenFixtureFromRequest,
    type RFC3161TokenFixtureOptions,
} from "../test/fixtures/rfc3161-token.js";
import { cryptoEngine, generateRSAKeyPair, importKeyForCertificate } from "../test/utils/crypto.js";
import {
    createLocalTsa,
    createTimestampResponse,
    TSA_POLICY,
    type LocalTsaConfiguration,
} from "./local-tsa-fixture";
import {
    commandOutput,
    commandSucceeded,
    installConsumer,
    packPackage,
    runPnpm,
} from "./packed-consumer-spawn";

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(SCRIPT_DIRECTORY, "../../..");
const CORE_DIRECTORY = resolve(SCRIPT_DIRECTORY, "../../core");
const BROWSER_DIRECTORY = resolve(SCRIPT_DIRECTORY, "../browser");

// Harness-only test hostnames. They never resolve via DNS: Chromium maps
// them to loopback through --host-resolver-rules and Firefox/WebKit
// through the harness forward proxy, so product URL policy (which
// rejects loopback literals) stays intact and real CORS applies.
const TSA_HOST = "signedby-timestamp.test";
const OCSP_HOST = "signedby-ocsp.test";

/** Browser engines the gate can execute. Each engine gets a separate receipt. */
type EngineName = "chromium" | "firefox" | "webkit";
const ENGINE_NAMES: EngineName[] = ["chromium", "firefox", "webkit"];

function parseEngineSelection(value: string): EngineName[] {
    if (value === "all") return [...ENGINE_NAMES];
    const found = ENGINE_NAMES.find((name) => name === value);
    if (found === undefined) {
        throw new Error(`--engine must be one of chromium, firefox, webkit, all (got: ${value})`);
    }
    return [found];
}

// Pinned SignedBy downstream engine (C01/C04). The gate hashes the
// installed engine and refuses to run when it differs.
const VERIFIEDBY_COMMIT = "f7c933e601a7febbc6a8f572ca30dc275c908905";
const TRUEDOC_COMMIT = "ba51af66270a4fa7ac991f24ad5026546f635b9d";
const VERIFIEDBY_ENGINE_SHA256 = "6ccfb6e6ee5568d1102226410341b15f5806f9927129de92debd304e4964feff";

const SHA256_OID = "2.16.840.1.101.3.4.2.1";
const MAX_TSA_REQUEST_BYTES = 1024 * 1024;
const PDF_MAGIC = [0x25, 0x50, 0x44, 0x46];

const rootPackage = JSON.parse(readFileSync(join(REPOSITORY_ROOT, "package.json"), "utf8")) as {
    packageManager?: unknown;
};
const packageManager = rootPackage.packageManager;
if (typeof packageManager !== "string" || !packageManager.startsWith("pnpm@")) {
    throw new Error("root package.json packageManager must be a pnpm version");
}
const ROOT_PNPM_VERSION = packageManager.slice("pnpm@".length);

function requirePnpmEntrypoint(): string {
    const entrypoint = process.env.npm_execpath;
    if (!entrypoint) throw new Error("Run this check through pnpm run test:browser:package");
    return entrypoint;
}
const PNPM_ENTRYPOINT = requirePnpmEntrypoint();

type PageApi = typeof SignerPage;

function sha256(value: Uint8Array | string): string {
    return createHash("sha256").update(value).digest("hex");
}

function opensslTimestampAvailable(): boolean {
    const probe = spawnSync("openssl", ["ts", "-help"], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
    });
    if (probe.error) return false;
    return probe.status === 0 || commandOutput(probe).includes("-queryfile");
}

function toExactBuffer(bytes: Uint8Array): ArrayBuffer {
    return new Uint8Array(bytes).buffer;
}

function pemToDer(pemPath: string): Uint8Array {
    const text = readFileSync(pemPath, "utf8");
    const body = text
        .split("\n")
        .map((line) => line.trim())
        .filter((line) => line.length > 0 && !line.startsWith("-----"))
        .join("");
    return new Uint8Array(Buffer.from(body, "base64"));
}

/**
 * Slices the raw ContentInfo token out of a TimeStampResp (or returns a
 * raw token unchanged) without re-encoding, so the raw-byte preservation
 * check compares exact TSA output bytes.
 */
function extractRawToken(responseOrToken: Uint8Array): Uint8Array {
    const parsed = asn1js.fromBER(toExactBuffer(responseOrToken));
    if (parsed.offset === -1 || !(parsed.result instanceof asn1js.Sequence)) {
        throw new Error("TSA response is not a DER SEQUENCE");
    }
    const children = parsed.result.valueBlock.value;
    const first = children[0];
    if (first instanceof asn1js.ObjectIdentifier) return new Uint8Array(responseOrToken);
    const tokenSchema = children[1];
    if (tokenSchema === undefined) throw new Error("Granted TimeStampResp has no token");
    return new Uint8Array(tokenSchema.valueBeforeDecodeView);
}

interface ParsedTsq {
    imprintAlgorithm: string;
    imprintLength: number;
    noncePresent: boolean;
    nonceBytes: Uint8Array;
    reqPolicy: string | null;
    certReq: boolean | null;
}

function parseTsq(body: Uint8Array): ParsedTsq {
    const parsed = asn1js.fromBER(toExactBuffer(body));
    assert.notEqual(parsed.offset, -1, "TSA request must be DER");
    assert.equal(parsed.offset, body.length, "TSA request must be complete DER");
    const tsq = new pkijs.TimeStampReq({ schema: parsed.result });
    const nonceBytes =
        tsq.nonce === undefined
            ? new Uint8Array()
            : new Uint8Array(tsq.nonce.valueBlock.valueHexView);
    return {
        imprintAlgorithm: tsq.messageImprint.hashAlgorithm.algorithmId,
        imprintLength: tsq.messageImprint.hashedMessage.valueBlock.valueHexView.length,
        noncePresent: tsq.nonce !== undefined,
        nonceBytes,
        reqPolicy: tsq.reqPolicy ?? null,
        certReq: tsq.certReq ?? null,
    };
}

interface CapturedRequest {
    route: string;
    origin: string | null;
    method: string | undefined;
    contentType: string | undefined;
    requestBytes: number;
    imprintAlgorithm: string;
    imprintLength: number;
    noncePresent: boolean;
    reqPolicy: string | null;
    certReq: boolean | null;
    hasPdfMagic: boolean;
    /** True for a follow-up POST the browser issued after the 307 hook. */
    viaRedirect: boolean;
}

/** Server-side view of the redirect hook's initial POST (T02 hook). */
interface RedirectHit {
    method: string | undefined;
    origin: string | null;
    requestBytes: number;
}

interface OcspHit {
    method: string | undefined;
    origin: string | null;
    requestBytes: number;
}

/** Server-side view of the opaque probe's no-cors POST (T02 hook). */
interface OpaqueHit {
    method: string | undefined;
    origin: string | null;
    contentType: string | undefined;
    requestBytes: number;
}

interface Preflight {
    route: string;
    origin: string | null;
    requestMethod: string | null;
    requestHeaders: string | null;
}

function hasPdfMagic(body: Uint8Array): boolean {
    if (body.length < PDF_MAGIC.length) return false;
    return body.some(
        (_, index) =>
            index + PDF_MAGIC.length <= body.length &&
            PDF_MAGIC.every((byte, offset) => body[index + offset] === byte)
    );
}

async function readBoundedBody(request: IncomingMessage): Promise<Uint8Array> {
    const chunks: Uint8Array[] = [];
    let length = 0;
    for await (const chunk of request) {
        const bytes = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk as ArrayBuffer);
        length += bytes.length;
        if (length > MAX_TSA_REQUEST_BYTES) {
            throw new Error("TSA request exceeds the 1 MiB harness cap");
        }
        chunks.push(bytes);
    }
    const body = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) {
        body.set(chunk, offset);
        offset += chunk.length;
    }
    return body;
}

const CORS_HEADERS: Record<string, string> = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
};

interface TsaWorld {
    tsa: LocalTsaConfiguration | undefined;
    tsaAia: LocalTsaConfiguration | undefined;
    tsaDirectory: string;
    tsaAiaDirectory: string;
    /** Unrelated intermediate appended to the T01 trust-target token bag. */
    trustTargetIntermediate: Uint8Array | undefined;
    requests: CapturedRequest[];
    acceptedTokens: Uint8Array[];
    ocspHits: OcspHit[];
    opaqueHits: OpaqueHit[];
    redirectHits: RedirectHit[];
    preflights: Preflight[];
}

/**
 * T01 poison material: a pinned root plus an unrelated intermediate that
 * chains to it. The trust-target token is signed by the crafted fixture
 * signer, so the intermediate must never verify in the signer's place.
 */
async function createTrustTargetMaterial(): Promise<{
    rootDer: Uint8Array;
    intermediateDer: Uint8Array;
}> {
    const buildCertificate = async (
        commonName: string,
        keys: CryptoKeyPair,
        serial: number,
        issuer?: pkijs.Certificate,
        issuerKeys?: CryptoKeyPair
    ): Promise<pkijs.Certificate> => {
        const certificate = new pkijs.Certificate();
        certificate.version = 2;
        certificate.serialNumber = new asn1js.Integer({ value: serial });
        certificate.subject.typesAndValues.push(
            new pkijs.AttributeTypeAndValue({
                type: "2.5.4.3",
                value: new asn1js.PrintableString({ value: commonName }),
            })
        );
        certificate.issuer = issuer?.subject ?? certificate.subject;
        certificate.notBefore.value = new Date(Date.now() - 86400000);
        certificate.notAfter.value = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
        certificate.subjectPublicKeyInfo = await importKeyForCertificate(keys.publicKey);
        certificate.extensions = [
            new pkijs.Extension({
                extnID: "2.5.29.19",
                critical: true,
                extnValue: new pkijs.BasicConstraints({ cA: true }).toSchema().toBER(),
            }),
        ];
        await certificate.sign((issuerKeys ?? keys).privateKey, "SHA-256", cryptoEngine);
        return certificate;
    };
    const rootKeys = await generateRSAKeyPair();
    const intermediateKeys = await generateRSAKeyPair();
    const root = await buildCertificate("Browser Trust Target Root", rootKeys, 2001);
    const intermediate = await buildCertificate(
        "Browser Trust Target Intermediate",
        intermediateKeys,
        2002,
        root,
        rootKeys
    );
    return {
        rootDer: new Uint8Array(root.toSchema().toBER(false)),
        intermediateDer: new Uint8Array(intermediate.toSchema().toBER(false)),
    };
}

function flippedNonce(nonce: Uint8Array): Uint8Array {
    if (nonce.length === 0) return new Uint8Array([1]);
    const copy = new Uint8Array(nonce);
    const first = ((copy[0] ?? 0) ^ 1) & 0x7f;
    copy[0] = first === 0 ? 1 : first;
    return copy;
}

async function craftedResponse(
    body: Uint8Array,
    buildOptions: (parsed: ParsedTsq) => RFC3161TokenFixtureOptions
): Promise<Uint8Array> {
    const parsed = parseTsq(body);
    const fixture = await createRFC3161TokenFixtureFromRequest(body, {
        form: "response",
        ...buildOptions(parsed),
    });
    return fixture.input;
}

/**
 * Appends extra certificates to the unsigned CMS bag of a crafted
 * TimeStampResp without touching its signature or signed attributes.
 * The response stays byte-comparable through the accepted-token record.
 */
function poisonResponseBag(
    response: Uint8Array,
    extraBagCertificates: readonly Uint8Array[]
): Uint8Array {
    const parsed = parseTimestampToken(extractRawToken(response));
    assert.ok(
        parsed.signedData.certificates !== undefined,
        "crafted token must carry a certificate bag to poison"
    );
    for (const extra of extraBagCertificates) {
        const schema = asn1js.fromBER(toExactBuffer(extra));
        assert.notEqual(schema.offset, -1, "poison certificate must be DER");
        parsed.signedData.certificates.push(new pkijs.Certificate({ schema: schema.result }));
    }
    const poisonedToken = new Uint8Array(
        new pkijs.ContentInfo({
            contentType: "1.2.840.113549.1.7.2",
            content: parsed.signedData.toSchema(),
        })
            .toSchema()
            .toBER(false)
    );
    const responseSchema = asn1js.fromBER(toExactBuffer(response));
    assert.notEqual(responseSchema.offset, -1, "crafted response must be DER");
    const timeStampResp = new pkijs.TimeStampResp({ schema: responseSchema.result });
    const tokenSchema = asn1js.fromBER(toExactBuffer(poisonedToken));
    assert.notEqual(tokenSchema.offset, -1, "poisoned token must be DER");
    timeStampResp.timeStampToken = new pkijs.ContentInfo({ schema: tokenSchema.result });
    return new Uint8Array(timeStampResp.toSchema().toBER(false));
}

async function handleTsaRequest(
    world: TsaWorld,
    request: IncomingMessage,
    response: ServerResponse
): Promise<void> {
    const url = new URL(request.url ?? "/", "http://tsa.invalid");
    const route = url.pathname;
    const noCorsRoutes = new Set(["/tsa-no-cors", "/ocsp"]);
    const withCors = !noCorsRoutes.has(route);
    if (request.method === "OPTIONS") {
        world.preflights.push({
            route,
            origin: request.headers.origin ?? null,
            requestMethod: request.headers["access-control-request-method"] ?? null,
            requestHeaders: request.headers["access-control-request-headers"] ?? null,
        });
        response.writeHead(204, withCors ? CORS_HEADERS : {}).end();
        if (route === "/ocsp") {
            world.ocspHits.push({
                method: request.method,
                origin: request.headers.origin ?? null,
                requestBytes: 0,
            });
        }
        return;
    }
    if (route === "/ocsp") {
        const body = await readBoundedBody(request);
        world.ocspHits.push({
            method: request.method,
            origin: request.headers.origin ?? null,
            requestBytes: body.length,
        });
        // Deliberately no CORS headers: the browser must block this read.
        response
            .writeHead(200, { "Content-Type": "application/ocsp-response" })
            .end(new Uint8Array([0x30, 0x03, 0x0a, 0x01, 0x00]));
        return;
    }
    if (route === "/tsa-redirect") {
        const redirectBody = await readBoundedBody(request);
        world.redirectHits.push({
            method: request.method,
            origin: request.headers.origin ?? null,
            requestBytes: redirectBody.length,
        });
        // The marker query lets the harness attribute the browser's
        // follow-up POST without prescribing whether one arrives.
        response.writeHead(307, { ...CORS_HEADERS, Location: "/tsa?via=redirect" }).end();
        return;
    }
    if (route === "/tsa-stall") {
        await readBoundedBody(request);
        response.writeHead(200, {
            ...CORS_HEADERS,
            "Content-Type": "application/timestamp-reply",
        });
        response.flushHeaders();
        // Never complete: the client timeout must fire. Destroyed on cleanup.
        return;
    }

    const tsa = world.tsa;
    const tsaAia = world.tsaAia;
    assert.ok(tsa !== undefined && tsaAia !== undefined, "TSA fixtures must exist");
    if (route === "/tsa-opaque") {
        // T02 hook endpoint: a raw no-cors POST. The browser strips the
        // non-safelisted Content-Type, so this intentionally bypasses the
        // recorded-TSQ assertions (which require application/timestamp-query)
        // and the per-route request counts. The server still signs a real
        // token with valid CORS headers: the response is opaque purely
        // because of the request mode, which is the recorded observation.
        assert.equal(request.method, "POST", "unexpected TSA method on /tsa-opaque");
        const opaqueBody = await readBoundedBody(request);
        world.opaqueHits.push({
            method: request.method,
            origin: request.headers.origin ?? null,
            contentType: request.headers["content-type"],
            requestBytes: opaqueBody.length,
        });
        const opaqueReply = createTimestampResponse(world.tsaDirectory, tsa.config, opaqueBody);
        response.writeHead(200, {
            ...CORS_HEADERS,
            "Content-Type": "application/timestamp-reply",
        });
        response.end(opaqueReply);
        return;
    }
    const opensslRoutes = new Map([
        ["/tsa", tsa],
        ["/tsa-aia", tsaAia],
        ["/tsa-no-cors", tsa],
    ]);
    const opensslConfig = opensslRoutes.get(route);
    const craftedRoutes = new Map<string, (parsed: ParsedTsq) => RFC3161TokenFixtureOptions>([
        ["/reject/digest", () => ({ imprint: "mismatch" })],
        ["/reject/nonce", (parsed) => ({ responseNonce: flippedNonce(parsed.nonceBytes) })],
        ["/reject/signature", () => ({ corruptSignature: true })],
        ["/reject/ess", () => ({ ess: "mismatched" })],
        ["/reject/eku", () => ({ eku: "extra" })],
        ["/hook/crafted-valid", () => ({})],
        ["/hook/trust-target", () => ({})],
        ["/hook/expired-signer", () => ({ certificateValidity: "expired" })],
    ]);
    const crafted = craftedRoutes.get(route);
    if (opensslConfig === undefined && crafted === undefined) {
        response.writeHead(404).end("unknown TSA route");
        return;
    }
    assert.equal(request.method, "POST", `unexpected TSA method on ${route}`);
    const body = await readBoundedBody(request);
    const parsed = parseTsq(body);
    world.requests.push({
        route,
        origin: request.headers.origin ?? null,
        method: request.method,
        contentType: request.headers["content-type"],
        requestBytes: body.length,
        imprintAlgorithm: parsed.imprintAlgorithm,
        imprintLength: parsed.imprintLength,
        noncePresent: parsed.noncePresent,
        reqPolicy: parsed.reqPolicy,
        certReq: parsed.certReq,
        hasPdfMagic: hasPdfMagic(body),
        viaRedirect: route === "/tsa" && url.searchParams.get("via") === "redirect",
    });
    let reply =
        crafted !== undefined
            ? await craftedResponse(body, crafted)
            : createTimestampResponse(
                  route === "/tsa-aia" ? world.tsaAiaDirectory : world.tsaDirectory,
                  opensslConfig?.config ?? "",
                  body
              );
    if (route === "/hook/trust-target") {
        const intermediate = world.trustTargetIntermediate;
        assert.ok(intermediate !== undefined, "trust-target intermediate must exist");
        reply = poisonResponseBag(reply, [intermediate]);
    }
    world.acceptedTokens.push(extractRawToken(reply));
    response.writeHead(
        200,
        withCors
            ? { ...CORS_HEADERS, "Content-Type": "application/timestamp-reply" }
            : { "Content-Type": "application/timestamp-reply" }
    );
    response.end(reply);
}

function createTsaServer(world: TsaWorld): Server {
    return createServer((request, response) => {
        handleTsaRequest(world, request, response).catch((error: unknown) => {
            if (!response.headersSent) response.writeHead(500);
            response.end(String(error));
        });
    });
}

async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolvePromise, reject) => {
        server.once("error", reject);
        server.listen(0, "127.0.0.1", () => {
            resolvePromise();
        });
    });
    const address = server.address();
    assert.ok(address !== null && typeof address === "object", "server must bind");
    return address.port;
}

async function twoPageInput(useObjectStreams: boolean): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    const font = await document.embedFont(StandardFonts.Helvetica);
    for (const pageNumber of [1, 2]) {
        const page = document.addPage([400, 300]);
        page.drawText(`T00 browser gate fixture page ${pageNumber.toString()}`, {
            x: 40,
            y: 220,
            size: 16,
            font,
        });
        page.drawText("The TSA receives the message imprint, never this content.", {
            x: 40,
            y: 190,
            size: 10,
            font,
        });
    }
    return new Uint8Array(await document.save({ useObjectStreams }));
}

interface BrowserBundles {
    pageBundle: Uint8Array;
    workerBundle: Uint8Array;
}

function assertCandidateIsolation(
    metafile: Metafile | undefined,
    candidateDirectory: string,
    candidateIndex: string
): void {
    assert.ok(metafile !== undefined, "esbuild metafile must exist");
    const inputs = Object.keys(metafile.inputs);
    assert.ok(inputs.length > 0, "bundle must have inputs");
    // esbuild resolves symlinks (the isolated consumer links the
    // candidate), so compare canonical paths on both sides.
    const resolvedCandidateDirectory = realpathSync(candidateDirectory);
    const resolvedCandidateIndex = realpathSync(candidateIndex);
    const resolvedCore = realpathSync(join(REPOSITORY_ROOT, "packages", "core"));
    const resolvedInputs = inputs.map((input) => realpathSync(resolve(REPOSITORY_ROOT, input)));
    const candidateInputs = resolvedInputs.filter(
        (input) =>
            input === resolvedCandidateDirectory ||
            input.startsWith(resolvedCandidateDirectory + sep)
    );
    assert.ok(
        candidateInputs.length > 0,
        "bundle must resolve pdf-rfc3161 from the installed candidate"
    );
    assert.ok(
        candidateInputs.includes(resolvedCandidateIndex),
        "bundle must use the candidate package entry point"
    );
    for (const [index, resolved] of resolvedInputs.entries()) {
        assert.ok(
            resolved !== resolvedCore && !resolved.startsWith(resolvedCore + sep),
            `bundle must not resolve workspace core: ${inputs[index] ?? ""}`
        );
    }
}

async function bundleFixtures(
    fixtureDirectory: string,
    candidateDirectory: string,
    candidateIndex: string,
    enginePath: string
): Promise<BrowserBundles> {
    // The fixtures live inside the isolated consumer, so the bare
    // "pdf-rfc3161" import resolves through the candidate's own
    // package.json exports exactly as a downstream browser bundler
    // would see it (a broken browser export/condition fails here).
    // Only the pinned downstream engine stays aliased: it is the
    // oracle, not the product under test.
    const shared = {
        bundle: true,
        platform: "browser" as const,
        alias: { verifiedby: enginePath },
        absWorkingDir: REPOSITORY_ROOT,
        metafile: true,
        write: false,
    };
    const page = await build({
        ...shared,
        entryPoints: [join(fixtureDirectory, "signer.spec.ts")],
        format: "iife",
    });
    const worker = await build({
        ...shared,
        entryPoints: [join(fixtureDirectory, "signer-worker.ts")],
        format: "esm",
    });
    const pageOutput = page.outputFiles?.[0];
    const workerOutput = worker.outputFiles?.[0];
    assert.ok(pageOutput !== undefined && workerOutput !== undefined, "bundles must emit");
    assertCandidateIsolation(page.metafile, candidateDirectory, candidateIndex);
    assertCandidateIsolation(worker.metafile, candidateDirectory, candidateIndex);
    return {
        pageBundle: new Uint8Array(pageOutput.contents),
        workerBundle: new Uint8Array(workerOutput.contents),
    };
}

function createPageServer(bundles: BrowserBundles): Server {
    return createServer((request, response) => {
        if (request.url === "/bundle.js") {
            response.writeHead(200, { "Content-Type": "text/javascript" }).end(bundles.pageBundle);
        } else if (request.url === "/worker.js") {
            response
                .writeHead(200, { "Content-Type": "text/javascript" })
                .end(bundles.workerBundle);
        } else if (request.url === "/" || request.url === "/index.html") {
            response
                .writeHead(200, { "Content-Type": "text/html" })
                .end(
                    '<!doctype html><html><body><div id="status">T00 browser gate</div>' +
                        '<script src="/bundle.js"></script></body></html>'
                );
        } else {
            response.writeHead(404).end("not found");
        }
    });
}

/**
 * Harness-local forward proxy for engines without Chromium's
 * --host-resolver-rules (Firefox, WebKit). It maps the harness test
 * hostnames to loopback while preserving the URL port, and refuses every
 * other host with 502. Forwarding is a byte relay: method, path, headers
 * (including Origin and CORS response headers) and bodies pass through
 * untouched, so the browser still dispatches native preflights and
 * enforces real CORS. The recorded host lists let the gate fail on any
 * unexpected destination, exactly like the page-side host observation.
 */
interface ForwardProxy {
    server: Server;
    port: number;
    forwardedHosts: string[];
    deniedHosts: string[];
}

function createForwardProxy(): ForwardProxy {
    const forwardedHosts: string[] = [];
    const deniedHosts: string[] = [];
    const server = createServer((request, response) => {
        let target: URL;
        try {
            target = new URL(request.url ?? "");
        } catch {
            response.writeHead(400).end("proxy: unparsable request URL");
            return;
        }
        const allowed =
            target.hostname === TSA_HOST ||
            target.hostname === OCSP_HOST ||
            target.hostname === "127.0.0.1";
        if (!allowed || target.protocol !== "http:" || target.port === "") {
            deniedHosts.push(target.hostname);
            response.writeHead(502).end("proxy: host not allowed");
            return;
        }
        forwardedHosts.push(target.hostname);
        const upstream = forwardHttpRequest(
            {
                hostname: "127.0.0.1",
                port: Number(target.port),
                path: `${target.pathname}${target.search}`,
                method: request.method,
                headers: { ...request.headers, host: target.host },
            },
            (upstreamResponse) => {
                response.writeHead(upstreamResponse.statusCode ?? 502, upstreamResponse.headers);
                // Flush immediately: writeHead alone only queues the
                // headers until the first body chunk or end, which a
                // stalled body never produces (the /tsa-stall hook
                // depends on the browser seeing headers promptly).
                response.flushHeaders();
                upstreamResponse.on("error", () => {
                    if (!response.writableEnded) response.destroy();
                });
                response.on("close", () => {
                    upstreamResponse.destroy();
                });
                upstreamResponse.pipe(response);
            }
        );
        upstream.on("error", (error: unknown) => {
            if (!response.headersSent) response.writeHead(502);
            response.end(`proxy: upstream failed: ${String(error)}`);
        });
        // Propagate downstream cancellation upstream so a browser
        // timeout does not leave the TSA-side connection alive until
        // teardown. This is robustness only: the relay still makes no
        // server-observed cancellation guarantees.
        request.on("aborted", () => {
            upstream.destroy();
        });
        request.on("error", () => {
            upstream.destroy();
        });
        response.on("close", () => {
            upstream.destroy();
        });
        request.pipe(upstream);
    });
    return { server, port: 0, forwardedHosts, deniedHosts };
}

async function startForwardProxy(proxy: ForwardProxy): Promise<string> {
    proxy.port = await listen(proxy.server);
    return `http://127.0.0.1:${proxy.port.toString()}`;
}

function assertTsaRequests(world: TsaWorld, pageOrigin: string, policy: string): void {
    assert.ok(world.requests.length > 0, "the page must issue TSA requests");
    for (const captured of world.requests) {
        progress(
            `request ${captured.route} origin=${captured.origin ?? "(none)"} ` +
                `policy=${captured.reqPolicy ?? "(none)"} certReq=${String(captured.certReq)} ` +
                `bytes=${captured.requestBytes.toString()}`
        );
    }
    for (const preflight of world.preflights) {
        progress(
            `preflight ${preflight.route} origin=${preflight.origin ?? "(none)"} ` +
                `method=${preflight.requestMethod ?? "(none)"} ` +
                `headers=${preflight.requestHeaders ?? "(none)"}`
        );
    }
    for (const captured of world.requests) {
        assert.equal(captured.method, "POST", `${captured.route}: TSA request must be POST`);
        assert.equal(
            captured.contentType,
            "application/timestamp-query",
            `${captured.route}: TSA request content type`
        );
        assert.ok(
            captured.requestBytes < 1024,
            `${captured.route}: TSA request must be an imprint, not a PDF upload`
        );
        assert.equal(
            captured.hasPdfMagic,
            false,
            `${captured.route}: TSA request must not contain PDF bytes`
        );
        assert.equal(
            captured.imprintAlgorithm,
            SHA256_OID,
            `${captured.route}: message imprint algorithm`
        );
        assert.equal(captured.imprintLength, 32, `${captured.route}: SHA-256 imprint length`);
        assert.equal(captured.noncePresent, true, `${captured.route}: nonce must be present`);
        assert.equal(captured.reqPolicy, policy, `${captured.route}: requested policy`);
        assert.equal(
            captured.origin,
            pageOrigin,
            `${captured.route}: request must carry the page Origin (real browser CORS fetch)`
        );
    }
    // Deterministic plan with retry: 0 everywhere, counted over direct
    // (non-redirect-follow-up) requests only: 5 positive journeys plus
    // the certReq=false journey and the worker journey hit /tsa; the
    // revocation journey hits /tsa-aia; each rejection case hits its
    // endpoint twice (session + one-call); the crafted-valid control
    // hits twice (session + one-call); the T01 trust-target case and
    // the T09 hook hit once each. The CORS-denied TSA never reaches
    // the server (the browser blocks its preflight), and the
    // resource-limit probe fails before any request.
    // The T02 redirect follow-up is recorded separately below without
    // prescribing it: redirect rejection must not fail this gate.
    const direct = world.requests.filter((captured) => !captured.viaRedirect);
    const directByRoute = new Map<string, number>();
    for (const captured of direct) {
        directByRoute.set(captured.route, (directByRoute.get(captured.route) ?? 0) + 1);
    }
    const expected = new Map([
        ["/tsa", 7],
        ["/tsa-aia", 1],
        ["/reject/digest", 2],
        ["/reject/nonce", 2],
        ["/reject/signature", 2],
        ["/reject/ess", 2],
        ["/reject/eku", 2],
        ["/hook/crafted-valid", 2],
        ["/hook/trust-target", 1],
        ["/hook/expired-signer", 1],
    ]);
    for (const [route, count] of expected) {
        assert.equal(
            directByRoute.get(route) ?? 0,
            count,
            `expected ${count.toString()} direct TSA request(s) on ${route}`
        );
    }
    assert.equal(direct.length, 22, "total direct TSA requests");
    assert.equal(world.redirectHits.length, 1, "the redirect hook must execute its initial POST");
    const followUps = world.requests.filter((captured) => captured.viaRedirect);
    assert.equal(
        followUps.length,
        0,
        "redirect:manual must prevent the browser from following the TSA redirect (C06 behavior change)"
    );
    progress(
        `redirect follow-ups observed: ${followUps.length.toString()} (strict since T02: rejection expected)`
    );
    // requestCertificate:false omits certReq from the TSQ (parsed as null).
    const certReqFalse = world.requests.filter((captured) => captured.certReq !== true);
    assert.equal(certReqFalse.length, 1, "one manual journey must use certReq=false");
    assert.equal(certReqFalse[0]?.route, "/tsa", "certReq=false journey hits the good TSA");
}

function assertPreflights(world: TsaWorld, pageOrigin: string): void {
    assert.ok(world.preflights.length > 0, "the browser must dispatch CORS preflights");
    for (const preflight of world.preflights) {
        assert.equal(preflight.origin, pageOrigin, `${preflight.route}: preflight origin`);
        assert.equal(preflight.requestMethod, "POST", `${preflight.route}: preflight method`);
        assert.ok(
            (preflight.requestHeaders ?? "").toLowerCase().includes("content-type"),
            `${preflight.route}: preflight must cover Content-Type`
        );
    }
    const routes = new Set(world.preflights.map((preflight) => preflight.route));
    assert.ok(routes.has("/tsa"), "the good TSA must see a native preflight");
    assert.ok(routes.has("/tsa-no-cors"), "the denied TSA must be preflighted");
    assert.ok(
        !world.requests.some((captured) => captured.route === "/tsa-no-cors"),
        "the denied TSA preflight must block the POST"
    );
}

interface OracleCase {
    name: string;
    status: string;
    timestampCount: number;
    genTime: string;
    hashAlg: string | null;
    trailingKinds: (string | undefined)[];
    coversWholeFile: boolean[];
    dssCertificates: number;
    tamperStatus: string;
    pdfSha256: string;
    pdfBytes: number;
    rawTokenPreserved: boolean;
}

/**
 * Expected downstream shape of one oracle output: exact per-element
 * trailing classification and coverage, plus whether a Document
 * Security Store with embedded certificates must be present. Returned
 * LTV counts alone never prove embedding; the DSS check below reads
 * the actual Catalog entry.
 */
interface OracleExpectation {
    count: number;
    trailingKinds: string[];
    coversWholeFile: boolean[];
    dss: "present" | "absent";
}

function tokenPreserved(signatureToken: Uint8Array, acceptedTokens: Uint8Array[]): boolean {
    return acceptedTokens.some(
        (token) =>
            signatureToken.length >= token.length &&
            token.every((value, index) => signatureToken[index] === value) &&
            signatureToken.subarray(token.length).every((value) => value === 0)
    );
}

/**
 * Reads the embedded Document Security Store straight from the
 * Catalog (compression-independent) and returns its certificate
 * count. LTV outputs must carry a DSS with certificates; bare
 * timestamps must carry no DSS at all.
 */
async function assertDss(
    name: string,
    bytes: Uint8Array,
    expected: "present" | "absent"
): Promise<number> {
    const document = await PDFDocument.load(bytes);
    const rawDss = document.catalog.get(PDFName.of("DSS"));
    if (expected === "absent") {
        assert.equal(rawDss, undefined, `${name}: bare output must not embed a DSS`);
        return 0;
    }
    assert.ok(rawDss !== undefined, `${name}: Catalog must embed a DSS`);
    const dss = rawDss instanceof PDFRef ? document.context.lookup(rawDss) : rawDss;
    assert.ok(dss instanceof PDFDict, `${name}: DSS entry must be a dictionary`);
    const rawCerts = dss.get(PDFName.of("Certs"));
    assert.ok(rawCerts !== undefined, `${name}: DSS must embed certificates`);
    const certs = rawCerts instanceof PDFRef ? document.context.lookup(rawCerts) : rawCerts;
    assert.ok(certs instanceof PDFArray, `${name}: DSS Certs must be an array`);
    assert.ok(certs.size() > 0, `${name}: DSS must embed at least one certificate`);
    return certs.size();
}

async function assertOracle(
    name: string,
    bytes: Uint8Array,
    acceptedTokens: Uint8Array[],
    expected: OracleExpectation
): Promise<OracleCase> {
    const parsed = extractSignatures(bytes);
    assert.equal(parsed.length, expected.count, `${name}: signature dictionary count`);
    for (const item of parsed) {
        assert.equal(item.dictType, "DocTimeStamp", `${name}: dictionary type`);
        assert.equal(item.subFilter, "ETSI.RFC3161", `${name}: sub-filter`);
    }
    const verdict = await verify(bytes);
    assert.equal(verdict.status, "verified-untrusted-root", `${name}: aggregate verdict`);
    assert.equal(verdict.timestampCount, expected.count, `${name}: timestamp count`);
    assert.equal(verdict.documentMatches, true, `${name}: document matches`);
    assert.equal(verdict.elements.length, expected.count, `${name}: every element examined`);
    for (const [index, element] of verdict.elements.entries()) {
        for (const flag of [
            "documentMatches",
            "signatureValid",
            "attrsCommit",
            "chainValid",
            "withinValidity",
            "authentic",
        ] as const) {
            assert.equal(element[flag], true, `${name}: downstream ${flag}`);
        }
        assert.equal(
            element.trailingKind,
            expected.trailingKinds[index],
            `${name}: element ${index.toString()} trailing classification`
        );
        assert.equal(
            parsed[index]?.coversWholeFile,
            expected.coversWholeFile[index],
            `${name}: element ${index.toString()} coverage`
        );
        if (expected.coversWholeFile[index] === false) {
            assert.ok(
                (parsed[index]?.trailingBytes ?? 0) > 0,
                `${name}: element ${index.toString()} must trail appended bytes`
            );
        }
    }
    const dssCertificates = await assertDss(name, bytes, expected.dss);
    assert.deepEqual(
        verdict.byteRange,
        parsed[expected.count - 1]?.byteRange,
        `${name}: outermost ByteRange selected`
    );
    const tampered = new Uint8Array(bytes);
    let changed = false;
    const firstRange = parsed[0]?.byteRange;
    assert.ok(firstRange !== undefined, `${name}: first ByteRange must exist`);
    for (let index = 16; index < firstRange[1]; index++) {
        if (tampered[index] === 10) {
            tampered[index] = 13;
            changed = true;
            break;
        }
    }
    assert.ok(changed, `${name}: covered-byte tamper control must apply`);
    const bad = await verify(tampered);
    assert.equal(bad.status, "mismatch", `${name}: tampered status`);
    assert.equal(bad.documentMatches, false, `${name}: tampered document mismatch`);
    let rawTokenPreserved = true;
    for (const item of parsed) {
        rawTokenPreserved = rawTokenPreserved && tokenPreserved(item.token, acceptedTokens);
    }
    assert.equal(rawTokenPreserved, true, `${name}: embedded token equals accepted TSA bytes`);
    return {
        name,
        status: verdict.status,
        timestampCount: verdict.timestampCount ?? 0,
        genTime: verdict.genTime?.toISOString() ?? "",
        hashAlg: verdict.hashAlg ?? null,
        trailingKinds: verdict.elements.map((element) => element.trailingKind),
        coversWholeFile: parsed.map((item) => item.coversWholeFile),
        dssCertificates,
        tamperStatus: bad.status,
        pdfSha256: sha256(bytes),
        pdfBytes: bytes.length,
        rawTokenPreserved,
    };
}

interface CertlessCase {
    name: string;
    status: string;
    dictType: string | null;
    subFilter: string | null;
    pdfSha256: string;
    pdfBytes: number;
    rawTokenPreserved: boolean;
}

async function assertCertless(
    output: CertlessJourneyOutput,
    acceptedTokens: Uint8Array[]
): Promise<CertlessCase> {
    const name = output.name;
    const bytes = new Uint8Array(output.bytes);
    const parsed = extractSignatures(bytes);
    assert.equal(parsed.length, 1, `${name}: signature dictionary count`);
    const first = parsed[0];
    assert.ok(first !== undefined, `${name}: signature dictionary must exist`);
    assert.equal(first.dictType, "DocTimeStamp", `${name}: dictionary type`);
    assert.equal(first.subFilter, "ETSI.RFC3161", `${name}: sub-filter`);
    const verdict = await verify(bytes);
    assert.equal(verdict.status, "unsupported", `${name}: certless downstream verdict`);
    const rawTokenPreserved = tokenPreserved(first.token, acceptedTokens);
    assert.equal(rawTokenPreserved, true, `${name}: embedded token equals accepted TSA bytes`);
    return {
        name,
        status: verdict.status,
        dictType: first.dictType,
        subFilter: first.subFilter,
        pdfSha256: sha256(bytes),
        pdfBytes: bytes.length,
        rawTokenPreserved,
    };
}

/**
 * Valid-control check for the crafted-token family: the token embeds
 * byte-identically on both API surfaces with no DSS (enableLTV is
 * false), covering the whole file with nothing trailing. The pinned
 * engine cannot parse this fixture's CMS, so no verify() verdict is
 * asserted here (documented consumer limit, as for certless tokens).
 */
async function assertCraftedValid(
    output: CertlessJourneyOutput,
    acceptedTokens: Uint8Array[]
): Promise<CertlessCase> {
    const name = output.name;
    const bytes = new Uint8Array(output.bytes);
    const parsed = extractSignatures(bytes);
    assert.equal(parsed.length, 1, `${name}: signature dictionary count`);
    const first = parsed[0];
    assert.ok(first !== undefined, `${name}: signature dictionary must exist`);
    assert.equal(first.dictType, "DocTimeStamp", `${name}: dictionary type`);
    assert.equal(first.subFilter, "ETSI.RFC3161", `${name}: sub-filter`);
    assert.equal(first.coversWholeFile, true, `${name}: bare token must cover the whole file`);
    assert.equal(first.trailingBytes, 0, `${name}: bare token must trail nothing`);
    await assertDss(name, bytes, "absent");
    const rawTokenPreserved = tokenPreserved(first.token, acceptedTokens);
    assert.equal(rawTokenPreserved, true, `${name}: embedded token equals accepted TSA bytes`);
    return {
        name,
        status: output.status,
        dictType: first.dictType,
        subFilter: first.subFilter,
        pdfSha256: sha256(bytes),
        pdfBytes: bytes.length,
        rawTokenPreserved,
    };
}

/** Everything one engine executed and observed. A Chromium pass never qualifies another engine. */
interface EngineReceipt {
    engine: EngineName;
    version: string;
    userAgent: string;
    routing: string;
    counts: Record<string, number>;
    cases: OracleCase[];
    certlessManual: CertlessCase;
    craftedValid: { session: CertlessCase; oneCall: CertlessCase };
    requests: CapturedRequest[];
    rejections: RejectionOutcome[];
    resourceLimit: RejectionOutcome;
    placeholderBounds: RejectionOutcome[];
    cors: {
        tsaDenied: RejectionOutcome;
        revocationDeniedLtv: CorsOutcome["revocationDeniedLtv"];
        defaultVerify: CorsOutcome["defaultVerify"];
        nullTrustStoreVerify: CorsOutcome["nullTrustStoreVerify"];
        customTrustStoreVerify: CorsOutcome["customTrustStoreVerify"];
    };
    signerValidityHook: SignerValidityObservation;
    trustTarget: TrustTargetOutcome;
    transportHooks: TransportObservation[];
    ocspHits: OcspHit[];
    opaqueHits: OpaqueHit[];
    redirectHits: RedirectHit[];
    redirectFollowUps: number;
    preflights: Preflight[];
    observedHosts: string[];
    proxiedHosts: string[];
    proxyDeniedHosts: string[];
    /** Raw page-side error events (WebKit surfaces expected CORS denials here). */
    pageErrors: string[];
}

/**
 * Per-engine execution outcome. Dispositions for every requested engine
 * are initialized before the first run, so a mid-matrix failure still
 * records the passing engines' evidence plus failed/not-run states.
 */
interface EngineDisposition {
    engine: EngineName;
    status: "pass" | "fail" | "not-run";
    /** Failure reason for "fail", or why the engine never ran for "not-run". */
    reason?: string;
    /** Playwright trace zip saved for a failed engine, when --trace-dir is set. */
    trace?: string;
}

/** One candidate-produced PDF exported for the native-reader handoff (T10 consumes it). */
interface ExportedPdfCase {
    engine: EngineName;
    case: string;
    file: string;
    sha256: string;
    bytes: number;
}

/** Hash manifest written next to the exported PDFs. Hash algorithm is always SHA-256. */
interface PdfExportManifest {
    gate: string;
    hashAlgorithm: "SHA-256";
    candidate: { tarballSha256: string; distSha256: string; version: string };
    files: ExportedPdfCase[];
}

const PDF_EXPORT_MANIFEST = "manifest.json";

function traceFileName(engine: EngineName): string {
    return `trace-${engine}.zip`;
}

interface BrowserReceipt {
    gate: string;
    node: string;
    engines: EngineReceipt[];
    dispositions: EngineDisposition[];
    pdfExport: {
        manifest: string;
        manifestSha256: string;
        files: ExportedPdfCase[];
    } | null;
    candidate: { tarballSha256: string; distSha256: string; version: string };
    bundles: { pageSha256: string; workerSha256: string };
    engine: {
        verifiedbyCommit: string;
        engineSha256: string;
        truedocCommit: string;
        truedocUiExecuted: boolean;
    };
    fixture: string;
}

interface DriveArguments {
    inputs: Record<string, number[]>;
    urls: T00Urls;
    policy: string;
    tsaSignerCert: number[];
    rootDer: number[];
    trustTargetRootDer: number[];
    workerUrl: string;
}

interface DrivenJourneys {
    userAgent: string;
    positives: PositiveJourneyOutput[];
    certReqFalse: CertlessJourneyOutput;
    rejections: RejectionOutcome[];
    craftedValid: { session: CertlessJourneyOutput; oneCall: CertlessJourneyOutput };
    cors: CorsOutcome;
    signerValidityHook: SignerValidityObservation;
    trustTarget: TrustTargetOutcome;
    transportHooks: TransportObservation[];
    worker: { pdf: number[]; workerUserAgent: string };
}

/**
 * EXTENSION HOOKS: every later task with browser regressions (T01/T02/
 * T03/T09/T12) adds one page.evaluate call here that invokes its
 * fixture entry point from ../browser, then asserts on the returned
 * plain data below or in a dedicated assert function. The page fixture
 * owns journey logic; this file owns transport, the oracle, and verdicts.
 * New journeys run on every engine automatically through runEngine.
 */
function progress(label: string): void {
    process.stderr.write(`[browser-gate] ${label}\n`);
}

async function driveJourneys(
    page: import("playwright").Page,
    args: DriveArguments
): Promise<DrivenJourneys> {
    const probe = await page.evaluate(() => {
        const api = (globalThis as unknown as { __T00__: PageApi }).__T00__;
        return api.runtimeProbe();
    });
    assert.deepEqual(probe.nodeGlobalsPresent, [], "no Node globals in the page");
    assert.equal(probe.hasCryptoSubtle, true, "page must have WebCrypto");
    progress("runtime probe ok");

    const positives = await page.evaluate(
        (arg: { inputs: Record<string, number[]>; urls: T00Urls; policy: string }) => {
            const api = (globalThis as unknown as { __T00__: PageApi }).__T00__;
            return api.runPositiveJourneys(arg.inputs, arg.urls, arg.policy);
        },
        { inputs: args.inputs, urls: args.urls, policy: args.policy }
    );
    const modernInput = args.inputs.modern;
    assert.ok(modernInput !== undefined, "modern input must exist");
    progress(`positive journeys ok (${positives.length.toString()})`);
    const certReqFalse = await page.evaluate(
        (arg: { input: number[]; urls: T00Urls; policy: string; tsaSignerCert: number[] }) => {
            const api = (globalThis as unknown as { __T00__: PageApi }).__T00__;
            return api.runManualCertReqFalseJourney(
                arg.input,
                arg.urls,
                arg.policy,
                arg.tsaSignerCert
            );
        },
        {
            input: modernInput,
            urls: args.urls,
            policy: args.policy,
            tsaSignerCert: args.tsaSignerCert,
        }
    );
    progress("certreq-false journey ok");
    const rejections = await page.evaluate(
        (arg: { input: number[]; urls: T00Urls; policy: string }) => {
            const api = (globalThis as unknown as { __T00__: PageApi }).__T00__;
            return api.runRejectionCases(arg.input, arg.urls, arg.policy);
        },
        { input: modernInput, urls: args.urls, policy: args.policy }
    );
    progress(`rejection cases ok (${rejections.length.toString()})`);
    const craftedValid = await page.evaluate(
        (arg: { input: number[]; urls: T00Urls; policy: string }) => {
            const api = (globalThis as unknown as { __T00__: PageApi }).__T00__;
            return api.runCraftedValidControl(arg.input, arg.urls, arg.policy);
        },
        { input: modernInput, urls: args.urls, policy: args.policy }
    );
    progress("crafted valid control ok");
    const cors = await page.evaluate(
        (arg: { input: number[]; urls: T00Urls; policy: string; rootDer: number[] }) => {
            const api = (globalThis as unknown as { __T00__: PageApi }).__T00__;
            return api.runCorsCases(arg.input, arg.urls, arg.policy, arg.rootDer);
        },
        { input: modernInput, urls: args.urls, policy: args.policy, rootDer: args.rootDer }
    );
    progress("cors cases ok");
    const signerValidityHook = await page.evaluate(
        (arg: { input: number[]; urls: T00Urls; policy: string }) => {
            const api = (globalThis as unknown as { __T00__: PageApi }).__T00__;
            return api.probeSignerValidityAtGenTime(arg.input, arg.urls, arg.policy);
        },
        { input: modernInput, urls: args.urls, policy: args.policy }
    );
    progress("signer-validity hook ok");
    const trustTarget = await page.evaluate(
        (arg: { input: number[]; urls: T00Urls; policy: string; rootDer: number[] }) => {
            const api = (globalThis as unknown as { __T00__: PageApi }).__T00__;
            return api.runTrustTargetCase(arg.input, arg.urls, arg.policy, arg.rootDer);
        },
        {
            input: modernInput,
            urls: args.urls,
            policy: args.policy,
            rootDer: args.trustTargetRootDer,
        }
    );
    progress("trust-target case ok");
    const transportHooks = await page.evaluate(
        (arg: { input: number[]; urls: T00Urls; policy: string }) => {
            const api = (globalThis as unknown as { __T00__: PageApi }).__T00__;
            return api.probeTransportHooks(arg.input, arg.urls, arg.policy);
        },
        { input: modernInput, urls: args.urls, policy: args.policy }
    );
    progress("transport hooks ok");
    const worker = await page.evaluate(
        (arg: { workerUrl: string; input: number[]; tsaUrl: string; policy: string }) => {
            const api = (globalThis as unknown as { __T00__: PageApi }).__T00__;
            return api.runWorkerJourney(arg.workerUrl, arg.input, arg.tsaUrl, arg.policy);
        },
        {
            workerUrl: args.workerUrl,
            input: modernInput,
            tsaUrl: args.urls.tsa,
            policy: args.policy,
        }
    );
    progress("worker journey ok");
    return {
        userAgent: probe.userAgent,
        positives,
        certReqFalse,
        rejections,
        craftedValid,
        cors,
        signerValidityHook,
        trustTarget,
        transportHooks,
        worker,
    };
}

/**
 * Each rejection case must fail on BOTH API surfaces with a message
 * that identifies the rejected predicate: a shared unrelated error
 * across cases fails here.
 */
const REJECTION_REASONS: Record<string, string> = {
    "wrong-digest": "message-imprint does not match",
    "wrong-nonce": "nonce does not match",
    "invalid-signature": "CMS signature verification failed",
    "invalid-ess": "does not bind the selected signer",
    "invalid-eku": "exclusive id-kp-timeStamping EKU",
};

function assertRejections(rejections: RejectionOutcome[]): void {
    const cases = [
        "wrong-digest",
        "wrong-nonce",
        "invalid-signature",
        "invalid-ess",
        "invalid-eku",
    ];
    const expected = [
        ...cases.map((name) => `session:${name}`),
        ...cases.map((name) => `one-call:${name}`),
    ];
    assert.deepEqual(
        rejections.map((outcome) => `${outcome.api}:${outcome.name}`),
        expected,
        "rejection cases on both API surfaces"
    );
    for (const outcome of rejections) {
        const label = `${outcome.api}:${outcome.name}`;
        const reason = REJECTION_REASONS[outcome.name];
        assert.equal(outcome.rejected, true, `${label}: must reject pre-embed`);
        assert.equal(outcome.code, "VERIFICATION_FAILED", `${label}: error code`);
        assert.ok(reason !== undefined, `${label}: known rejection case`);
        assert.ok(
            outcome.message.includes(reason),
            `${label}: message must identify the rejected predicate (got: ${outcome.message})`
        );
    }
}

function assertTrustTarget(outcome: TrustTargetOutcome): void {
    assert.equal(outcome.name, "trust-target", "trust-target case name");
    assert.equal(outcome.embedded, true, "trust-target: poisoned token must embed");
    assert.equal(outcome.count, 1, "trust-target: verified timestamp count");
    assert.equal(outcome.certificateCount, 2, "trust-target: bag must carry the poison cert");
    assert.equal(
        outcome.verified,
        false,
        "trust-target: unrelated trusted intermediate must not verify the signer"
    );
    assert.ok(
        (outcome.error ?? "").includes("not trusted"),
        `trust-target: error must cite the untrusted chain (got: ${outcome.error ?? "(none)"})`
    );
}

function assertResourceLimit(outcome: RejectionOutcome): void {
    assert.equal(outcome.name, "resource-limit-max-size", "resource-limit case name");
    assert.equal(outcome.rejected, true, "resource-limit: must reject pre-embed");
    assert.equal(outcome.code, "PDF_ERROR", "resource-limit: error code");
    assert.ok(
        outcome.message.includes("maximum supported size"),
        `resource-limit: message must cite the size bound (got: ${outcome.message})`
    );
}

/** T03 placeholder/input bound negatives (C02/C06): codes plus bound citation. */
function assertPlaceholderBounds(outcomes: RejectionOutcome[]): void {
    const expected: { name: string; api: string; code: string; messagePart: string }[] = [
        {
            name: "oversize-reservation",
            api: "one-call",
            code: "INVALID_ARGUMENT",
            messagePart: "signatureSize",
        },
        {
            name: "infinite-reservation",
            api: "one-call",
            code: "INVALID_ARGUMENT",
            messagePart: "signatureSize",
        },
        {
            name: "nan-reservation",
            api: "session",
            code: "INVALID_ARGUMENT",
            messagePart: "signatureSize",
        },
        {
            name: "setter-nan-reservation",
            api: "session",
            code: "INVALID_ARGUMENT",
            messagePart: "signatureSize",
        },
        {
            name: "invalid-ceiling",
            api: "one-call",
            code: "INVALID_ARGUMENT",
            messagePart: "maxSize",
        },
        {
            name: "extract-over-ceiling",
            api: "one-call",
            code: "PDF_ERROR",
            messagePart: "maximum supported size",
        },
    ];
    assert.deepEqual(
        outcomes.map((outcome) => outcome.name),
        expected.map((item) => item.name),
        "placeholder-bounds case names"
    );
    for (const [index, outcome] of outcomes.entries()) {
        const item = expected[index];
        assert.ok(item !== undefined, `placeholder-bounds case ${index.toString()} must be known`);
        const label = `placeholder-bounds:${item.name}`;
        assert.equal(outcome.api, item.api, `${label}: api surface`);
        assert.equal(outcome.rejected, true, `${label}: must reject pre-embed`);
        assert.equal(outcome.code, item.code, `${label}: error code`);
        assert.ok(
            outcome.message.includes(item.messagePart),
            `${label}: message must cite the bound (got: ${outcome.message})`
        );
    }
}

/**
 * T02 strict transport assertions (C06). The redirect and stalled-body
 * hooks flipped from observation-only to strict: redirect:manual rejects
 * the 307 instead of following it to a signature, and the per-attempt
 * deadline now covers the body so the stall rejects with TIMEOUT instead
 * of hanging. The opaque probe stays observation-only: it uses a raw
 * page-side no-cors fetch (never the product path, which cannot produce
 * opacity), with harness integrity covered by the opaqueHits count.
 */
function assertTransportHooks(transportHooks: TransportObservation[]): void {
    const byName = new Map(transportHooks.map((hook) => [hook.name, hook]));
    assert.equal(transportHooks.length, 3, "transport hook count");

    const redirect = byName.get("redirect");
    assert.ok(redirect !== undefined, "redirect hook must run");
    assert.equal(redirect.outcome, "rejected", "TSA redirect must be rejected, not followed");
    assert.equal(redirect.code, "NETWORK_ERROR", "redirect rejection code");
    assert.match(redirect.message, /redirect/i, "redirect rejection message");
    assert.ok(
        redirect.elapsedMs < 15000,
        `redirect probe must settle before the hook bound, took ${redirect.elapsedMs.toString()}ms`
    );

    const stall = byName.get("stalled-body");
    assert.ok(stall !== undefined, "stalled-body hook must run");
    assert.equal(stall.outcome, "rejected", "stalled body must reject, not hang");
    assert.equal(stall.code, "TIMEOUT", "stalled-body rejection code");
    assert.match(stall.message, /timed out/i, "stalled-body rejection message");
    // Single attempt, 3 s per-attempt deadline (retry: 0), observed ~3002 ms
    // on every engine. The lower bound proves the client waited out the full
    // deadline instead of failing fast (500 ms grace for timer slop); the
    // upper bound is 2x the deadline, excluding hangs while allowing
    // loaded-CI timer lateness. The 15 s hook race bound stays the hang
    // backstop above this (a hang reports outcome "hung" and fails there).
    assert.ok(
        stall.elapsedMs >= 2500 && stall.elapsedMs < 6000,
        `stalled body must reject near the 3s deadline, took ${stall.elapsedMs.toString()}ms`
    );

    const opaque = byName.get("opaque-response");
    assert.ok(opaque !== undefined, "opaque-response hook must run");
}

function assertCors(cors: CorsOutcome): void {
    assert.equal(cors.tsaDenied.rejected, true, "CORS-denied TSA must fail signing");
    assert.equal(cors.tsaDenied.code, "NETWORK_ERROR", "CORS-denied TSA error code");
    assert.ok(cors.tsaDenied.message.length > 0, "CORS-denied TSA error message");
    assert.ok(
        cors.revocationDeniedPdf.length > 0,
        "CORS-denied revocation must still return bytes"
    );
    assert.equal(cors.revocationDeniedLtv.certificates, 2, "revocation-denied LTV certificates");
    assert.equal(cors.revocationDeniedLtv.crls, 0, "revocation-denied LTV CRLs");
    assert.equal(cors.revocationDeniedLtv.ocspResponses, 0, "revocation-denied LTV OCSP responses");
    for (const [label, summary] of [
        ["default", cors.defaultVerify],
        ["trustStore:null", cors.nullTrustStoreVerify],
        ["custom trust store", cors.customTrustStoreVerify],
    ] as const) {
        assert.equal(summary.count, 1, `${label}: verified timestamp count`);
        assert.deepEqual(summary.verified, [true], `${label}: verified flags`);
    }
}

interface ParsedArguments {
    coreTarball: string | undefined;
    receiptPath: string | undefined;
    engines: EngineName[];
    traceDirectory: string | undefined;
    pdfExportDirectory: string | undefined;
}

function parseArguments(): ParsedArguments {
    const raw = process.argv.slice(2).filter((argument) => argument !== "--");
    let coreTarball: string | undefined;
    let receiptPath: string | undefined;
    let engines: EngineName[] = ["chromium"];
    let traceDirectory: string | undefined;
    let pdfExportDirectory: string | undefined;
    for (let index = 0; index < raw.length; index++) {
        const argument = raw[index];
        if (argument === "--receipt") {
            receiptPath = raw[index + 1];
            assert.ok(receiptPath !== undefined, "--receipt requires a path");
            index++;
        } else if (argument === "--trace-dir") {
            const value = raw[index + 1];
            assert.ok(value !== undefined, "--trace-dir requires a path");
            traceDirectory = resolve(value);
            index++;
        } else if (argument === "--pdf-export-dir") {
            const value = raw[index + 1];
            assert.ok(value !== undefined, "--pdf-export-dir requires a path");
            pdfExportDirectory = resolve(value);
            index++;
        } else if (argument === "--engine") {
            const value = raw[index + 1];
            assert.ok(value !== undefined, "--engine requires a value");
            engines = parseEngineSelection(value);
            index++;
        } else if (argument !== undefined && !argument.startsWith("--")) {
            assert.ok(coreTarball === undefined, "at most one core tarball may be supplied");
            coreTarball = resolve(argument);
        } else {
            throw new Error(`unknown argument: ${argument ?? ""}`);
        }
    }
    if (coreTarball !== undefined) {
        assert.ok(existsSync(coreTarball), "core tarball does not exist: " + coreTarball);
    }
    return { coreTarball, receiptPath, engines, traceDirectory, pdfExportDirectory };
}

function writeBrowserConsumerPackage(consumerDirectory: string, coreTarballPath: string): void {
    writeFileSync(
        join(consumerDirectory, "package.json"),
        JSON.stringify(
            {
                name: "pdf-rfc3161-browser-consumer",
                private: true,
                type: "module",
                packageManager,
                dependencies: {
                    "pdf-rfc3161": "file:" + coreTarballPath,
                },
            },
            null,
            4
        ) + "\n",
        "utf8"
    );
}

function candidateVersion(candidateDirectory: string): string {
    const manifest = JSON.parse(readFileSync(join(candidateDirectory, "package.json"), "utf8")) as {
        version?: unknown;
    };
    const version = manifest.version;
    if (typeof version !== "string" || version.length === 0) {
        throw new Error(join(candidateDirectory, "package.json") + " has no string version");
    }
    return version;
}

async function closeServer(server: Server): Promise<void> {
    server.closeAllConnections();
    await new Promise<void>((resolvePromise, reject) => {
        server.close((error) => {
            if (error) reject(error);
            else resolvePromise();
        });
    });
}

// Overall bound for the page-driven journeys: a hung evaluation must
// fail the gate instead of hanging CI. main's finally block still
// closes the browser and both servers on this path.
const RUNNER_DEADLINE_MS = 10 * 60 * 1000;

async function withDeadline<T>(work: Promise<T>, ms: number, label: string): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
        return await Promise.race([
            work,
            new Promise<never>((_resolve, reject) => {
                timer = setTimeout(() => {
                    reject(new Error(`${label} exceeded the ${ms.toString()}ms runner deadline`));
                }, ms);
            }),
        ]);
    } finally {
        if (timer !== undefined) clearTimeout(timer);
    }
}

/** Built once per gate run and shared by every engine. */
interface SharedGate {
    temporaryDirectory: string;
    bundles: BrowserBundles;
    inputs: Record<string, number[]>;
    modern: Uint8Array;
    /** T01 poison material, generated once and shared by every engine. */
    trustTarget: { rootDer: Uint8Array; intermediateDer: Uint8Array };
    /** When set, a Playwright trace zip per failed engine is saved here (save-on-failure only). */
    traceDirectory: string | undefined;
    /** When set, candidate-produced PDFs plus a SHA-256 hash manifest are exported here. */
    pdfExportDirectory: string | undefined;
    exportedCases: ExportedPdfCase[];
}

/**
 * Exports one engine's candidate-produced PDFs for the native-reader
 * handoff. The manifest itself is written by main after the engine
 * loop (partial on failure), so this only stages files and records.
 */
function exportEnginePdfs(
    engine: EngineName,
    shared: SharedGate,
    outputs: { name: string; bytes: Uint8Array }[]
): void {
    const directory = shared.pdfExportDirectory;
    if (directory === undefined) return;
    mkdirSync(directory, { recursive: true });
    for (const output of outputs) {
        const file = `${engine}-${output.name}.pdf`;
        writeFileSync(join(directory, file), output.bytes);
        shared.exportedCases.push({
            engine,
            case: output.name,
            file,
            sha256: sha256(output.bytes),
            bytes: output.bytes.length,
        });
    }
    progress(`[${engine}] exported ${outputs.length.toString()} PDFs`);
}

/**
 * WebKit reports CORS-blocked fetches as pageerror events ("Fetch API
 * cannot load ... due to access control checks") while Chromium and
 * Firefox only log them to the console. A denial message is expected
 * only for the two deliberately CORS-denied endpoints; the caller
 * additionally asserts exact counts against server-side observations,
 * so an extra or missing denial still fails the gate.
 */
function isExpectedCorsDenial(message: string): boolean {
    if (!message.includes("due to access control checks")) return false;
    const deniedTsa = message.includes(TSA_HOST) && message.includes("/tsa-no-cors");
    const deniedOcsp = message.includes(OCSP_HOST) && message.includes("/ocsp");
    return (deniedTsa || deniedOcsp) && !(deniedTsa && deniedOcsp);
}

function assertEngineUserAgent(engine: EngineName, userAgent: string, label: string): void {
    if (engine === "chromium") {
        assert.ok(userAgent.includes("Chrome"), `${label} must run in Chromium`);
    } else if (engine === "firefox") {
        assert.ok(userAgent.includes("Firefox"), `${label} must run in Firefox`);
    } else {
        assert.ok(userAgent.includes("AppleWebKit"), `${label} must run in WebKit`);
        assert.ok(!userAgent.includes("Chrome"), `${label} must not be Chromium`);
    }
}

/**
 * Executes the full gate (journeys, assertions, oracle cases) on one
 * engine with its own TSA/page/proxy servers and returns that engine's
 * receipt. Engines run sequentially so every count below is attributable
 * to exactly one engine; a failure aborts the gate immediately.
 */
async function runEngine(engine: EngineName, shared: SharedGate): Promise<EngineReceipt> {
    progress(`starting engine: ${engine}`);
    let browser: import("playwright").Browser | undefined;
    let context: import("playwright").BrowserContext | undefined;
    let tsaServer: Server | undefined;
    let pageServer: Server | undefined;
    let proxyServer: Server | undefined;
    let tracingStarted = false;
    let enginePassed = false;
    try {
        const tsaDirectory = join(shared.temporaryDirectory, `tsa-${engine}`);
        const tsaAiaDirectory = join(shared.temporaryDirectory, `tsa-aia-${engine}`);
        mkdirSync(tsaDirectory, { recursive: true });
        mkdirSync(tsaAiaDirectory, { recursive: true });
        const world: TsaWorld = {
            tsa: undefined,
            tsaAia: undefined,
            tsaDirectory,
            tsaAiaDirectory,
            trustTargetIntermediate: shared.trustTarget.intermediateDer,
            requests: [],
            acceptedTokens: [],
            ocspHits: [],
            opaqueHits: [],
            redirectHits: [],
            preflights: [],
        };
        tsaServer = createTsaServer(world);
        const tsaPort = await listen(tsaServer);
        world.tsa = createLocalTsa(tsaDirectory);
        world.tsaAia = createLocalTsa(tsaAiaDirectory, {
            ocspUrl: `http://${OCSP_HOST}:${tsaPort.toString()}/ocsp`,
        });

        pageServer = createPageServer(shared.bundles);
        const pagePort = await listen(pageServer);
        const pageOrigin = `http://127.0.0.1:${pagePort.toString()}`;
        const tsaOrigin = `http://${TSA_HOST}:${tsaPort.toString()}`;
        const urls: T00Urls = {
            tsa: `${tsaOrigin}/tsa`,
            tsaAia: `${tsaOrigin}/tsa-aia`,
            rejectDigest: `${tsaOrigin}/reject/digest`,
            rejectNonce: `${tsaOrigin}/reject/nonce`,
            rejectSignature: `${tsaOrigin}/reject/signature`,
            rejectEss: `${tsaOrigin}/reject/ess`,
            rejectEku: `${tsaOrigin}/reject/eku`,
            craftedValid: `${tsaOrigin}/hook/crafted-valid`,
            trustTarget: `${tsaOrigin}/hook/trust-target`,
            expiredSigner: `${tsaOrigin}/hook/expired-signer`,
            tsaNoCors: `${tsaOrigin}/tsa-no-cors`,
            redirect: `${tsaOrigin}/tsa-redirect`,
            stall: `${tsaOrigin}/tsa-stall`,
            opaque: `${tsaOrigin}/tsa-opaque`,
        };

        let routing: string;
        let proxy: ForwardProxy | undefined;
        if (engine === "chromium") {
            routing =
                "Chromium --host-resolver-rules maps the test TSA/OCSP hostnames to loopback; " +
                "product URL validation is unchanged and browser CORS remains enabled";
            browser = await chromium.launch({
                headless: true,
                args: [
                    `--host-resolver-rules=MAP ${TSA_HOST} 127.0.0.1, MAP ${OCSP_HOST} 127.0.0.1`,
                    "--no-proxy-server",
                ],
            });
        } else {
            proxy = createForwardProxy();
            const proxyUrl = await startForwardProxy(proxy);
            proxyServer = proxy.server;
            routing =
                `harness-local forward proxy (${proxyUrl}) maps the test TSA/OCSP hostnames ` +
                "to loopback and refuses every other host; product URL validation is " +
                "unchanged and browser CORS remains enabled";
            browser = await (engine === "firefox" ? firefox : webkit).launch({
                headless: true,
                proxy: { server: proxyUrl },
            });
        }
        // A dedicated context (not browser.newPage) so the gate can
        // trace per engine and save the trace on failure below.
        context = await browser.newContext();
        if (shared.traceDirectory !== undefined) {
            await context.tracing.start({ screenshots: true, snapshots: true, sources: true });
            tracingStarted = true;
        }
        const page = await context.newPage();
        const pageErrors: string[] = [];
        page.on("pageerror", (error) => {
            pageErrors.push(String(error));
        });
        // Passive observation only: active route interception would bypass
        // the browser's native CORS preflight dispatch, and this gate
        // requires real enforcement. Unexpected hosts fail the gate below.
        const observedHosts = new Set<string>();
        page.on("request", (request) => {
            observedHosts.add(new URL(request.url()).hostname);
        });
        await page.goto(pageOrigin);
        await page.waitForFunction(() => {
            const api = (globalThis as unknown as { __T00__?: unknown }).__T00__;
            return typeof api === "object" && api !== null;
        });

        // The TSA fixtures are assigned after the TSA server binds and
        // never cleared; those assignments dominate this use.
        const tsa = world.tsa;
        const tsaAia = world.tsaAia;
        progress(`[${engine}] browser launched`);
        const { driven, resourceLimit, placeholderBounds } = await withDeadline(
            (async () => {
                const completed = await driveJourneys(page, {
                    inputs: shared.inputs,
                    urls,
                    policy: TSA_POLICY,
                    tsaSignerCert: Array.from(pemToDer(tsa.tsaCert)),
                    // The post-embed verification runs on the revocation-journey
                    // PDF, which the AIA TSA signed under its own root.
                    rootDer: Array.from(pemToDer(tsaAia.rootCert)),
                    trustTargetRootDer: Array.from(shared.trustTarget.rootDer),
                    workerUrl: `${pageOrigin}/worker.js`,
                });
                // Bounded resource-limit probe, isolated so the harness
                // can assert it issued zero TSA requests.
                const requestsBefore = world.requests.length;
                const limit = await page.evaluate(
                    (arg: { input: number[]; tsaUrl: string }) => {
                        const api = (globalThis as unknown as { __T00__: PageApi }).__T00__;
                        return api.probeResourceLimit(arg.input, arg.tsaUrl);
                    },
                    { input: Array.from(shared.modern), tsaUrl: urls.tsa }
                );
                progress(`[${engine}] resource-limit probe ok`);
                assert.equal(
                    world.requests.length,
                    requestsBefore,
                    "the resource-limit probe must issue zero TSA requests"
                );
                // T03 placeholder-bounds probe, isolated under the same
                // zero-TSA-request assertion.
                const boundsRequestsBefore = world.requests.length;
                const bounds = await page.evaluate(
                    (arg: { input: number[]; tsaUrl: string }) => {
                        const api = (globalThis as unknown as { __T00__: PageApi }).__T00__;
                        return api.probePlaceholderBounds(arg.input, arg.tsaUrl);
                    },
                    { input: Array.from(shared.modern), tsaUrl: urls.tsa }
                );
                progress(`[${engine}] placeholder-bounds probe ok`);
                assert.equal(
                    world.requests.length,
                    boundsRequestsBefore,
                    "the placeholder-bounds probe must issue zero TSA requests"
                );
                return { driven: completed, resourceLimit: limit, placeholderBounds: bounds };
            })(),
            RUNNER_DEADLINE_MS,
            `browser journeys (${engine})`
        );
        const unexpectedPageErrors = pageErrors.filter((message) => !isExpectedCorsDenial(message));
        assert.deepEqual(unexpectedPageErrors, [], "page must report no unexpected page errors");
        if (engine === "webkit") {
            const denials = pageErrors.filter((message) => isExpectedCorsDenial(message));
            const tsaDenials = denials.filter((message) => message.includes("/tsa-no-cors"));
            const ocspDenials = denials.filter((message) => message.includes("/ocsp"));
            assert.equal(tsaDenials.length, 1, "WebKit must surface the denied-TSA fetch once");
            assert.equal(
                ocspDenials.length,
                world.ocspHits.length,
                "WebKit must surface one denial per blocked OCSP attempt"
            );
        } else {
            assert.deepEqual(
                pageErrors,
                [],
                "non-WebKit engines must not surface fetch denials as page errors"
            );
        }
        const allowedHosts = new Set(["127.0.0.1", TSA_HOST, OCSP_HOST]);
        for (const hostname of observedHosts) {
            assert.ok(allowedHosts.has(hostname), `unexpected request host: ${hostname}`);
        }
        assert.ok(observedHosts.has(TSA_HOST), "the page must fetch the controlled TSA");
        if (proxy !== undefined) {
            assert.deepEqual(
                proxy.deniedHosts,
                [],
                "the forward proxy must see no unexpected host"
            );
        }

        assertTsaRequests(world, pageOrigin, TSA_POLICY);
        assertPreflights(world, pageOrigin);
        assertRejections(driven.rejections);
        assertResourceLimit(resourceLimit);
        assertPlaceholderBounds(placeholderBounds);
        assertCors(driven.cors);
        assertTransportHooks(driven.transportHooks);
        assertTrustTarget(driven.trustTarget);
        assert.ok(
            world.ocspHits.length > 0,
            "the revocation journey must attempt the AIA OCSP fetch"
        );
        assert.equal(
            world.opaqueHits.length,
            1,
            "the opaque probe must issue one no-cors TSA request"
        );

        const expectedNames = [
            "modern-one-call-ltv",
            "classic-one-call-ltv",
            "modern-second-timestamp",
            "modern-manual-session",
            "modern-default-ltv",
        ];
        assert.deepEqual(
            driven.positives.map((output) => output.name),
            expectedNames,
            "positive journey names"
        );
        // Expected downstream shapes, mirroring the page-side
        // recordPositive expectations: every LTV output trails its DSS
        // append (or a later timestamp) and embeds a DSS.
        const singleModernLtv: OracleExpectation = {
            count: 1,
            trailingKinds: ["appended-data"],
            coversWholeFile: [false],
            dss: "present",
        };
        const oracleShapes = new Map<string, OracleExpectation>([
            ["modern-one-call-ltv", singleModernLtv],
            [
                "classic-one-call-ltv",
                {
                    count: 1,
                    trailingKinds: ["signature-update"],
                    coversWholeFile: [false],
                    dss: "present",
                },
            ],
            [
                "modern-second-timestamp",
                {
                    count: 2,
                    trailingKinds: ["signature-update", "appended-data"],
                    coversWholeFile: [false, false],
                    dss: "present",
                },
            ],
            ["modern-manual-session", singleModernLtv],
            ["modern-default-ltv", singleModernLtv],
        ]);
        const cases: OracleCase[] = [];
        const positiveBytes = new Map<string, Uint8Array>();
        for (const output of driven.positives) {
            const shape = oracleShapes.get(output.name);
            assert.ok(shape !== undefined, `known positive journey: ${output.name}`);
            const bytes = new Uint8Array(output.bytes);
            positiveBytes.set(output.name, bytes);
            cases.push(await assertOracle(output.name, bytes, world.acceptedTokens, shape));
        }
        // The second timestamp must preserve the entire first sealed
        // output, DSS append included.
        const firstSealed = positiveBytes.get("modern-one-call-ltv");
        const secondSealed = positiveBytes.get("modern-second-timestamp");
        assert.ok(firstSealed !== undefined && secondSealed !== undefined, "sealed outputs exist");
        assert.ok(
            firstSealed.every((value, index) => secondSealed[index] === value),
            "second timestamp must preserve the first sealed PDF bytes"
        );
        assert.equal(
            driven.certReqFalse.name,
            "modern-manual-certreq-false",
            "certReq=false journey name"
        );
        const certlessManual = await assertCertless(driven.certReqFalse, world.acceptedTokens);
        assert.equal(
            driven.craftedValid.session.name,
            "crafted-valid-session",
            "crafted-valid session name"
        );
        assert.equal(
            driven.craftedValid.oneCall.name,
            "crafted-valid-one-call",
            "crafted-valid one-call name"
        );
        const craftedValid = {
            session: await assertCraftedValid(driven.craftedValid.session, world.acceptedTokens),
            oneCall: await assertCraftedValid(driven.craftedValid.oneCall, world.acceptedTokens),
        };
        cases.push(
            await assertOracle(
                "cors-revocation-denied-ltv",
                new Uint8Array(driven.cors.revocationDeniedPdf),
                world.acceptedTokens,
                singleModernLtv
            )
        );
        cases.push(
            await assertOracle(
                "worker-one-call",
                new Uint8Array(driven.worker.pdf),
                world.acceptedTokens,
                singleModernLtv
            )
        );
        assertEngineUserAgent(engine, driven.userAgent, "page");
        assertEngineUserAgent(engine, driven.worker.workerUserAgent, "worker");

        progress(
            `[${engine}] passed: ${cases.length.toString()} oracle cases, ` +
                `${world.requests.length.toString()} TSA requests, ` +
                `${driven.rejections.length.toString()} rejections`
        );
        exportEnginePdfs(engine, shared, [
            ...[...positiveBytes.entries()].map(
                ([name, bytes]): { name: string; bytes: Uint8Array } => ({ name, bytes })
            ),
            { name: driven.certReqFalse.name, bytes: new Uint8Array(driven.certReqFalse.bytes) },
            {
                name: driven.craftedValid.session.name,
                bytes: new Uint8Array(driven.craftedValid.session.bytes),
            },
            {
                name: driven.craftedValid.oneCall.name,
                bytes: new Uint8Array(driven.craftedValid.oneCall.bytes),
            },
            {
                name: "cors-revocation-denied-ltv",
                bytes: new Uint8Array(driven.cors.revocationDeniedPdf),
            },
            { name: "worker-one-call", bytes: new Uint8Array(driven.worker.pdf) },
        ]);
        const engineReceipt: EngineReceipt = {
            engine,
            version: browser.version(),
            userAgent: driven.userAgent,
            routing,
            counts: {
                tsaRequests: world.requests.length,
                positiveOutputs: driven.positives.length,
                certReqFalseOutputs: 1,
                craftedValidCases: 2,
                rejectionCases: driven.rejections.length,
                resourceLimitCases: 1,
                placeholderBoundsCases: placeholderBounds.length,
                corsCases: 2,
                trustTargetCases: 1,
                workerOutputs: 1,
                oracleCases: cases.length,
                pageTamperControls: driven.positives.length,
                nodeTamperControls: cases.length,
            },
            cases,
            certlessManual,
            craftedValid,
            requests: world.requests,
            rejections: driven.rejections,
            resourceLimit,
            placeholderBounds,
            cors: {
                tsaDenied: driven.cors.tsaDenied,
                revocationDeniedLtv: driven.cors.revocationDeniedLtv,
                defaultVerify: driven.cors.defaultVerify,
                nullTrustStoreVerify: driven.cors.nullTrustStoreVerify,
                customTrustStoreVerify: driven.cors.customTrustStoreVerify,
            },
            signerValidityHook: driven.signerValidityHook,
            trustTarget: driven.trustTarget,
            transportHooks: driven.transportHooks,
            ocspHits: world.ocspHits,
            opaqueHits: world.opaqueHits,
            redirectHits: world.redirectHits,
            redirectFollowUps: world.requests.filter((captured) => captured.viaRedirect).length,
            preflights: world.preflights,
            observedHosts: [...observedHosts].sort(),
            proxiedHosts: proxy === undefined ? [] : [...new Set(proxy.forwardedHosts)].sort(),
            proxyDeniedHosts: proxy === undefined ? [] : [...proxy.deniedHosts],
            pageErrors: [...pageErrors],
        };
        enginePassed = true;
        return engineReceipt;
    } finally {
        if (context !== undefined) {
            if (tracingStarted && shared.traceDirectory !== undefined) {
                if (enginePassed) {
                    // Save-on-failure only: discard the passing trace.
                    await context.tracing.stop();
                } else {
                    try {
                        mkdirSync(shared.traceDirectory, { recursive: true });
                        await context.tracing.stop({
                            path: join(shared.traceDirectory, traceFileName(engine)),
                        });
                        progress(`[${engine}] failure trace saved`);
                    } catch (traceError: unknown) {
                        progress(`[${engine}] failure trace save failed: ${String(traceError)}`);
                    }
                }
            }
            await context.close();
        }
        if (browser !== undefined) await browser.close();
        if (pageServer !== undefined) await closeServer(pageServer);
        if (tsaServer !== undefined) await closeServer(tsaServer);
        if (proxyServer !== undefined) await closeServer(proxyServer);
    }
}

async function main(): Promise<void> {
    const pnpmVersion = runPnpm(PNPM_ENTRYPOINT, ["--version"], REPOSITORY_ROOT);
    commandSucceeded(pnpmVersion);
    assert.equal(
        commandOutput(pnpmVersion.result).trim(),
        ROOT_PNPM_VERSION,
        "pnpm version must match root packageManager"
    );
    if (!opensslTimestampAvailable()) {
        throw new Error(
            "OpenSSL with the `ts` subcommand is required for the browser gate: " +
                "the controlled TSA cannot sign responses without it."
        );
    }
    const { coreTarball, receiptPath, engines, traceDirectory, pdfExportDirectory } =
        parseArguments();
    const testsRequire = createRequire(import.meta.url);
    const enginePath = testsRequire.resolve("verifiedby");
    const engineSha256 = sha256(readFileSync(enginePath));
    assert.equal(
        engineSha256,
        VERIFIEDBY_ENGINE_SHA256,
        "installed verifiedby engine must match the pinned C04 engine"
    );

    let temporaryDirectory: string | undefined;
    try {
        temporaryDirectory = mkdtempSync(join(tmpdir(), "pdf-rfc3161-browser-consumer-"));
        const tarballPath =
            coreTarball ??
            packPackage(PNPM_ENTRYPOINT, CORE_DIRECTORY, join(temporaryDirectory, "pack"));
        const tarballSha256 = sha256(readFileSync(tarballPath));
        progress(`candidate packed (${tarballSha256.slice(0, 12)})`);
        const consumerDirectory = join(temporaryDirectory, "consumer");
        mkdirSync(consumerDirectory, { recursive: true });
        writeBrowserConsumerPackage(consumerDirectory, tarballPath);
        installConsumer(PNPM_ENTRYPOINT, consumerDirectory);
        progress("consumer installed");
        const candidateDirectory = join(consumerDirectory, "node_modules", "pdf-rfc3161");
        const candidateIndex = join(candidateDirectory, "dist", "index.js");
        assert.ok(existsSync(candidateIndex), "candidate ESM bundle must exist: " + candidateIndex);
        const distSha256 = sha256(readFileSync(candidateIndex));
        const version = candidateVersion(candidateDirectory);

        // Stage the fixtures inside the isolated consumer so the bare
        // "pdf-rfc3161" import resolves through normal package
        // resolution (the candidate's own exports map), not a harness
        // alias to a hardcoded dist path.
        const fixtureDirectory = join(consumerDirectory, "t00-fixtures");
        mkdirSync(fixtureDirectory, { recursive: true });
        for (const fixture of ["signer.spec.ts", "signer-worker.ts"]) {
            const staged = join(fixtureDirectory, fixture);
            writeFileSync(staged, readFileSync(join(BROWSER_DIRECTORY, fixture)));
            assert.equal(
                sha256(readFileSync(staged)),
                sha256(readFileSync(join(BROWSER_DIRECTORY, fixture))),
                `staged fixture must match the workspace source: ${fixture}`
            );
        }

        const modern = await twoPageInput(true);
        const classic = await twoPageInput(false);
        const inputs: Record<string, number[]> = {
            modern: Array.from(modern),
            classic: Array.from(classic),
        };

        const bundles = await bundleFixtures(
            fixtureDirectory,
            candidateDirectory,
            candidateIndex,
            enginePath
        );
        progress("fixtures bundled");
        const trustTarget = await createTrustTargetMaterial();
        progress("trust-target material generated");

        // One candidate, every requested engine: each run gets its
        // own servers and receipt. Dispositions for all requested
        // engines are initialized up front; each completed engine
        // checkpoints the receipt and manifest, and a failure persists
        // the failed/not-run states before propagating (exit stays
        // nonzero, and the always() CI upload still has a file).
        const shared: SharedGate = {
            temporaryDirectory,
            bundles,
            inputs,
            modern,
            trustTarget,
            traceDirectory,
            pdfExportDirectory,
            exportedCases: [],
        };
        const dispositions: EngineDisposition[] = engines.map((name) => ({
            engine: name,
            status: "not-run",
            reason: "engine did not execute",
        }));
        const engineReceipts: EngineReceipt[] = [];
        const writeManifest = (): string | undefined => {
            if (pdfExportDirectory === undefined) return undefined;
            mkdirSync(pdfExportDirectory, { recursive: true });
            const manifest: PdfExportManifest = {
                gate: "T18",
                hashAlgorithm: "SHA-256",
                candidate: { tarballSha256, distSha256, version },
                files: [...shared.exportedCases],
            };
            const manifestJson = `${JSON.stringify(manifest, null, 4)}\n`;
            writeFileSync(join(pdfExportDirectory, PDF_EXPORT_MANIFEST), manifestJson, "utf8");
            return sha256(manifestJson);
        };
        const writeReceipt = (manifestSha256: string | undefined): string => {
            const receipt: BrowserReceipt = {
                gate: "T18",
                node: process.version,
                engines: engineReceipts,
                dispositions: dispositions.map((entry) => ({ ...entry })),
                pdfExport:
                    manifestSha256 === undefined
                        ? null
                        : {
                              manifest: PDF_EXPORT_MANIFEST,
                              manifestSha256,
                              files: [...shared.exportedCases],
                          },
                candidate: { tarballSha256, distSha256, version },
                bundles: {
                    pageSha256: sha256(bundles.pageBundle),
                    workerSha256: sha256(bundles.workerBundle),
                },
                engine: {
                    verifiedbyCommit: VERIFIEDBY_COMMIT,
                    engineSha256,
                    truedocCommit: TRUEDOC_COMMIT,
                    truedocUiExecuted: false,
                },
                fixture:
                    "two-page table/stream PDFs; RSA-2048 openssl TSA; two-certificate chain; " +
                    "OCSP AIA only on the revocation-journey TSA",
            };
            const receiptJson = `${JSON.stringify(receipt, null, 4)}\n`;
            if (receiptPath !== undefined) writeFileSync(receiptPath, receiptJson, "utf8");
            return receiptJson;
        };
        let failure: Error | undefined;
        let receiptJson = "";
        for (const engineName of engines) {
            const disposition = dispositions.find((entry) => entry.engine === engineName);
            assert.ok(disposition !== undefined, `disposition exists for ${engineName}`);
            try {
                engineReceipts.push(await runEngine(engineName, shared));
                disposition.status = "pass";
                delete disposition.reason;
            } catch (error: unknown) {
                disposition.status = "fail";
                disposition.reason = error instanceof Error ? error.message : String(error);
                if (traceDirectory !== undefined) {
                    const tracePath = join(traceDirectory, traceFileName(engineName));
                    if (existsSync(tracePath)) disposition.trace = tracePath;
                }
                failure = error instanceof Error ? error : new Error(String(error));
                receiptJson = writeReceipt(writeManifest());
                break;
            }
            // Checkpoint after every completed engine: passing engines
            // keep their evidence even if a later engine fails.
            receiptJson = writeReceipt(writeManifest());
        }
        if (failure !== undefined) {
            const outcome = dispositions
                .map((entry) => `${entry.engine}:${entry.status}`)
                .join(" ");
            process.stdout.write(
                `Browser gate failed: ${outcome}, candidate ${tarballSha256.slice(0, 12)}\n` +
                    receiptJson
            );
            throw failure;
        }
        const summary = engineReceipts
            .map(
                (engineReceipt) =>
                    `${engineReceipt.engine} ${engineReceipt.version} ` +
                    `(${engineReceipt.cases.length.toString()} oracle cases, ` +
                    `${engineReceipt.requests.length.toString()} TSA requests, ` +
                    `${engineReceipt.rejections.length.toString()} rejections)`
            )
            .join("; ");
        process.stdout.write(
            `Browser gate passed: ${summary}, candidate ${tarballSha256.slice(0, 12)}\n` +
                receiptJson
        );
    } finally {
        // Engines close their own browsers and servers; only the shared
        // temporary directory (packed candidate, consumer, TSA fixtures)
        // is cleaned up here.
        if (temporaryDirectory !== undefined) {
            rmSync(temporaryDirectory, { force: true, recursive: true });
        }
    }
}

main().catch((error: unknown) => {
    console.error("Browser consumer test failed:", error);
    process.exitCode = 1;
});
