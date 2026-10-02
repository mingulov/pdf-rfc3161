import { describe, expect, it } from "vitest";
import * as fc from "fast-check";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { createTimestampRequest } from "../../../core/src/tsa/request.js";
import { validateTimestampToken } from "../../../core/src/tsa/token-validation.js";
import { TimestampErrorCode, type HashAlgorithm } from "../../../core/src/types.js";
import { toArrayBuffer } from "../../../core/src/utils.js";
import { createRFC3161TokenFixtureFromRequest } from "../fixtures/rfc3161-token.js";

// T14: deterministic digest/nonce binding properties (TSQ <-> TSR).
//
// Valid structures and targeted invalid mutations are generated
// SEPARATELY. Every run uses a fixed checked-in seed. Independent
// oracles (hand-rolled DER reader, node:crypto digests, pkijs decode,
// OpenSSL CLI) keep the properties from degenerating into
// own-builder/own-parser roundtrips. Fixture TSA keys are generated
// once per file inside the fixture module, never per generated case.

const SEED_RB_VALID = 14001;
const SEED_RB_MUTATION = 14002;
const VALID_RUNS = 30;
const MUTATION_RUNS = 24;

const ID_DATA = "1.2.840.113549.1.7.1";
const ID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const ID_CT_TST_INFO = "1.2.840.113549.1.9.16.1.4";
const HASH_OIDS: Readonly<Record<HashAlgorithm, string>> = {
    "SHA-256": "2.16.840.1.101.3.4.2.1",
    "SHA-384": "2.16.840.1.101.3.4.2.2",
    "SHA-512": "2.16.840.1.101.3.4.2.3",
};
const NODE_HASH: Readonly<Record<HashAlgorithm, string>> = {
    "SHA-256": "sha256",
    "SHA-384": "sha384",
    "SHA-512": "sha512",
};

// ---------------------------------------------------------------------------
// Hand-rolled DER reader (independent oracle: raw TLV walk, no asn1js/pkijs).
// ---------------------------------------------------------------------------

interface DerNode {
    tagClass: number;
    constructed: boolean;
    tagNumber: number;
    length: number;
    valueOffset: number;
    totalLength: number;
}

function readDerNode(bytes: Uint8Array, offset: number): DerNode {
    const tagByte = bytes[offset];
    if (tagByte === undefined) throw new Error("hand DER: truncated tag");
    const tagClass = (tagByte & 0xc0) >> 6;
    const constructed = (tagByte & 0x20) !== 0;
    let tagNumber = tagByte & 0x1f;
    let cursor = offset + 1;
    if (tagNumber === 0x1f) {
        tagNumber = 0;
        for (let index = 0; index < 4; index++) {
            const next = bytes[cursor];
            if (next === undefined) throw new Error("hand DER: truncated high tag");
            cursor++;
            tagNumber = tagNumber * 128 + (next & 0x7f);
            if ((next & 0x80) === 0) break;
            if (index === 3) throw new Error("hand DER: tag number too large");
        }
    }
    const lengthByte = bytes[cursor];
    if (lengthByte === undefined) throw new Error("hand DER: truncated length");
    cursor++;
    let length = 0;
    if (lengthByte < 0x80) {
        length = lengthByte;
    } else {
        if (lengthByte === 0x80) throw new Error("hand DER: indefinite length rejected");
        const octets = lengthByte & 0x7f;
        if (octets < 1 || octets > 4) throw new Error("hand DER: bad length octets");
        for (let index = 0; index < octets; index++) {
            const octet = bytes[cursor];
            if (octet === undefined) throw new Error("hand DER: truncated long length");
            cursor++;
            length = length * 256 + octet;
        }
    }
    if (cursor + length > bytes.length) throw new Error("hand DER: value overruns input");
    return {
        tagClass,
        constructed,
        tagNumber,
        length,
        valueOffset: cursor,
        totalLength: cursor + length - offset,
    };
}

function derChildren(bytes: Uint8Array, node: DerNode): DerNode[] {
    if (!node.constructed) throw new Error("hand DER: primitive has no children");
    const out: DerNode[] = [];
    let cursor = node.valueOffset;
    const end = node.valueOffset + node.length;
    while (cursor < end) {
        const child = readDerNode(bytes, cursor);
        out.push(child);
        cursor += child.totalLength;
    }
    if (cursor !== end) throw new Error("hand DER: child overrun");
    return out;
}

function expectUniversal(node: DerNode, tagNumber: number, what: string): void {
    if (node.tagClass !== 0 || node.tagNumber !== tagNumber) {
        throw new Error(`hand DER: expected ${what}`);
    }
}

function oidBytesToString(bytes: Uint8Array): string {
    const first = bytes[0];
    if (first === undefined) throw new Error("hand DER: empty OID");
    const head = Math.min(2, Math.floor(first / 40));
    const parts: number[] = [head, first - head * 40];
    let value = 0;
    let pending = false;
    for (let index = 1; index < bytes.length; index++) {
        const octet = bytes[index];
        if (octet === undefined) throw new Error("hand DER: OID overrun");
        value = value * 128 + (octet & 0x7f);
        pending = true;
        if ((octet & 0x80) === 0) {
            parts.push(value);
            value = 0;
            pending = false;
        }
    }
    if (pending) throw new Error("hand DER: truncated OID subidentifier");
    return parts.map((part) => part.toString(10)).join(".");
}

interface ParsedImprint {
    algorithmOid: string;
    digest: Uint8Array;
    nonce: Uint8Array | undefined;
}

function directIntegers(bytes: Uint8Array, outer: DerNode): Uint8Array[] {
    return derChildren(bytes, outer)
        .filter((child) => child.tagClass === 0 && child.tagNumber === 2 && !child.constructed)
        .map((child) => bytes.slice(child.valueOffset, child.valueOffset + child.length));
}

function parseMessageImprint(bytes: Uint8Array, imprint: DerNode): Omit<ParsedImprint, "nonce"> {
    expectUniversal(imprint, 16, "MessageImprint SEQUENCE");
    const parts = derChildren(bytes, imprint);
    const hashAlg = parts[0];
    const hashedMessage = parts[1];
    if (hashAlg === undefined || hashedMessage === undefined || parts.length !== 2) {
        throw new Error("hand DER: MessageImprint shape");
    }
    const algChildren = derChildren(bytes, hashAlg);
    const oidNode = algChildren[0];
    if (oidNode?.tagClass !== 0 || oidNode.tagNumber !== 6) {
        throw new Error("hand DER: hash algorithm OID");
    }
    expectUniversal(hashedMessage, 4, "hashedMessage OCTET STRING");
    return {
        algorithmOid: oidBytesToString(
            bytes.slice(oidNode.valueOffset, oidNode.valueOffset + oidNode.length)
        ),
        digest: bytes.slice(
            hashedMessage.valueOffset,
            hashedMessage.valueOffset + hashedMessage.length
        ),
    };
}

/** Extracts the message imprint + nonce from raw TimeStampReq bytes. */
function handParseTsq(bytes: Uint8Array): ParsedImprint {
    const outer = readDerNode(bytes, 0);
    expectUniversal(outer, 16, "TimeStampReq SEQUENCE");
    if (!outer.constructed || outer.totalLength !== bytes.length) {
        throw new Error("hand DER: TimeStampReq framing");
    }
    const kids = derChildren(bytes, outer);
    const imprintNode = kids[1];
    if (imprintNode === undefined) throw new Error("hand DER: TimeStampReq has no imprint");
    const imprint = parseMessageImprint(bytes, imprintNode);
    // Direct INTEGER children after version: the request nonce is the
    // second one (reqPolicy is an OID, certReq a BOOLEAN).
    const integers = directIntegers(bytes, outer);
    const nonce = integers[1];
    return { ...imprint, nonce };
}

/** Extracts the encapsulated TSTInfo bytes from a raw token or TimeStampResp. */
function handExtractTstInfoBytes(token: Uint8Array): Uint8Array {
    const outer = readDerNode(token, 0);
    expectUniversal(outer, 16, "token SEQUENCE");
    const outerKids = derChildren(token, outer);
    const first = outerKids[0];
    if (first === undefined) throw new Error("hand DER: empty token");
    // ContentInfo starts with an OID; TimeStampResp starts with a SEQUENCE.
    const contentInfo = first.tagClass === 0 && first.tagNumber === 6 ? outer : outerKids[1];
    if (contentInfo === undefined) throw new Error("hand DER: TimeStampResp has no token");
    const ciKids = derChildren(token, contentInfo);
    const contentType = ciKids[0];
    const explicit = ciKids[1];
    if (
        contentType === undefined ||
        explicit === undefined ||
        contentType.tagClass !== 0 ||
        contentType.tagNumber !== 6
    ) {
        throw new Error("hand DER: ContentInfo shape");
    }
    const contentTypeOid = oidBytesToString(
        token.slice(contentType.valueOffset, contentType.valueOffset + contentType.length)
    );
    if (contentTypeOid !== ID_SIGNED_DATA) throw new Error("hand DER: not signedData");
    if (explicit.tagClass !== 2 || explicit.tagNumber !== 0) {
        throw new Error("hand DER: ContentInfo explicit content");
    }
    const signedDataKids = derChildren(token, explicit);
    const signedData = signedDataKids[0];
    if (signedData === undefined) throw new Error("hand DER: missing SignedData");
    const sdKids = derChildren(token, signedData);
    const encap = sdKids[2];
    if (encap === undefined) throw new Error("hand DER: missing encapContentInfo");
    const encapKids = derChildren(token, encap);
    const eContentType = encapKids[0];
    const eContentExplicit = encapKids[1];
    if (eContentType === undefined || eContentExplicit === undefined) {
        throw new Error("hand DER: encapContentInfo shape");
    }
    const eContentOid = oidBytesToString(
        token.slice(eContentType.valueOffset, eContentType.valueOffset + eContentType.length)
    );
    if (eContentOid !== ID_CT_TST_INFO) throw new Error("hand DER: not id-ct-TSTInfo");
    const eContentKids = derChildren(token, eContentExplicit);
    const eContent = eContentKids[0];
    if (eContent?.tagClass !== 0 || eContent.tagNumber !== 4) {
        throw new Error("hand DER: eContent is not an OCTET STRING");
    }
    if (!eContent.constructed) {
        return token.slice(eContent.valueOffset, eContent.valueOffset + eContent.length);
    }
    const segments = derChildren(token, eContent);
    let total = 0;
    for (const segment of segments) total += segment.length;
    const out = new Uint8Array(total);
    let cursor = 0;
    for (const segment of segments) {
        out.set(token.subarray(segment.valueOffset, segment.valueOffset + segment.length), cursor);
        cursor += segment.length;
    }
    return out;
}

/** Extracts the eContentType OID without assuming it is TSTInfo (mutation oracle). */
function handExtractEContentType(token: Uint8Array): string {
    const outer = readDerNode(token, 0);
    const outerKids = derChildren(token, outer);
    const first = outerKids[0];
    if (first === undefined) throw new Error("hand DER: empty token");
    const contentInfo = first.tagClass === 0 && first.tagNumber === 6 ? outer : outerKids[1];
    if (contentInfo === undefined) throw new Error("hand DER: TimeStampResp has no token");
    const ciKids = derChildren(token, contentInfo);
    const explicit = ciKids[1];
    if (explicit === undefined) throw new Error("hand DER: ContentInfo shape");
    const signedDataKids = derChildren(token, explicit);
    const signedData = signedDataKids[0];
    if (signedData === undefined) throw new Error("hand DER: missing SignedData");
    const sdKids = derChildren(token, signedData);
    const encap = sdKids[2];
    if (encap === undefined) throw new Error("hand DER: missing encapContentInfo");
    const encapKids = derChildren(token, encap);
    const eContentType = encapKids[0];
    if (eContentType === undefined) throw new Error("hand DER: missing eContentType");
    return oidBytesToString(
        token.slice(eContentType.valueOffset, eContentType.valueOffset + eContentType.length)
    );
}

/** Parses TSTInfo bytes: imprint, policy OID, and optional nonce. */
function handParseTstInfo(bytes: Uint8Array): ParsedImprint & { policy: string } {
    const outer = readDerNode(bytes, 0);
    expectUniversal(outer, 16, "TSTInfo SEQUENCE");
    const kids = derChildren(bytes, outer);
    const policyNode = kids[1];
    const imprintNode = kids[2];
    if (policyNode === undefined || imprintNode === undefined) {
        throw new Error("hand DER: TSTInfo shape");
    }
    if (policyNode.tagClass !== 0 || policyNode.tagNumber !== 6) {
        throw new Error("hand DER: TSTInfo policy OID");
    }
    const imprint = parseMessageImprint(bytes, imprintNode);
    // Direct INTEGER children: version, serialNumber, then optional nonce.
    const integers = directIntegers(bytes, outer);
    const nonce = integers[2];
    return {
        ...imprint,
        nonce,
        policy: oidBytesToString(
            bytes.slice(policyNode.valueOffset, policyNode.valueOffset + policyNode.length)
        ),
    };
}

function nodeDigest(data: Uint8Array, algorithm: HashAlgorithm): Uint8Array {
    return new Uint8Array(createHash(NODE_HASH[algorithm]).update(data).digest());
}

function isHexChar(char: string): boolean {
    return (
        (char >= "0" && char <= "9") || (char >= "a" && char <= "f") || (char >= "A" && char <= "F")
    );
}

// ---------------------------------------------------------------------------
// Generators: valid structures.
// ---------------------------------------------------------------------------

const hashArb: fc.Arbitrary<HashAlgorithm> = fc.constantFrom("SHA-256", "SHA-384", "SHA-512");
const policyArb = fc.option(fc.constantFrom("1.2.3.4.5", "1.2.3.4.5.6"), { nil: undefined });
const formArb = fc.constantFrom("raw", "response") as fc.Arbitrary<"raw" | "response">;

const validInputArb = fc.record({
    data: fc.uint8Array({ minLength: 1, maxLength: 64 }),
    hashAlgorithm: hashArb,
    policy: policyArb,
    requestCertificate: fc.boolean(),
    form: formArb,
});

// ---------------------------------------------------------------------------
// Generators: targeted invalid mutations (separate from valid inputs).
// ---------------------------------------------------------------------------

const mutationKindArb = fc.constantFrom(
    "wrong-digest",
    "wrong-nonce",
    "wrong-econtenttype",
    "wrong-policy"
) as fc.Arbitrary<"wrong-digest" | "wrong-nonce" | "wrong-econtenttype" | "wrong-policy">;

const mutationInputArb = fc.record({
    data: fc.uint8Array({ minLength: 1, maxLength: 32 }),
    hashAlgorithm: hashArb,
    kind: mutationKindArb,
    // Candidate replacement nonce; forced positive-nonzero and forced to
    // differ from the request nonce before use.
    nonceBytes: fc.uint8Array({ minLength: 8, maxLength: 8 }),
});

const MUTATION_POLICY = "1.2.3.4.5";
const MUTATION_WRONG_POLICY = "1.2.3.4.6";

function distinctPositiveNonce(candidate: Uint8Array, requestNonce: Uint8Array): Uint8Array {
    const out = new Uint8Array(candidate);
    const first = out[0] ?? 0;
    out[0] = first & 0x7f || 1;
    let equal = out.length === requestNonce.length;
    if (equal) {
        for (let index = 0; index < out.length; index++) {
            if (out[index] !== requestNonce[index]) {
                equal = false;
                break;
            }
        }
    }
    if (equal) {
        const last = out[out.length - 1] ?? 0;
        out[out.length - 1] = last ^ 0xff;
    }
    return out;
}

describe("request binding properties (T14)", () => {
    it("binds TSQ digest/nonce/policy to the TSR across generated inputs", async () => {
        const seenHashes = new Set<string>();
        const seenPolicies = new Set<string>();
        const seenCertReq = new Set<boolean>();
        const seenForms = new Set<string>();

        await fc.assert(
            fc.asyncProperty(validInputArb, async (input) => {
                seenHashes.add(input.hashAlgorithm);
                seenPolicies.add(input.policy ?? "<absent>");
                seenCertReq.add(input.requestCertificate);
                seenForms.add(input.form);

                const { request, nonce } = await createTimestampRequest(input.data, {
                    hashAlgorithm: input.hashAlgorithm,
                    ...(input.policy === undefined ? {} : { policy: input.policy }),
                    requestCertificate: input.requestCertificate,
                });

                const fixture = await createRFC3161TokenFixtureFromRequest(request, {
                    form: input.form,
                    ...(input.requestCertificate ? {} : { certificates: "none" as const }),
                });

                const validated = await validateTimestampToken(
                    fixture.input,
                    {
                        data: input.data,
                        hashAlgorithm: input.hashAlgorithm,
                        nonce,
                        ...(input.policy === undefined ? {} : { policy: input.policy }),
                        requestCertificate: input.requestCertificate,
                    },
                    input.requestCertificate
                        ? {}
                        : { signerCertificates: [fixture.signerCertificate] }
                );
                expect(validated.info.hashAlgorithm).toBe(input.hashAlgorithm);

                // Independent oracle 1: hand-rolled DER over the raw TSQ.
                const tsq = handParseTsq(request);
                expect(tsq.algorithmOid).toBe(HASH_OIDS[input.hashAlgorithm]);
                expect(tsq.digest).toEqual(nodeDigest(input.data, input.hashAlgorithm));
                expect(tsq.nonce).toEqual(nonce);

                // Independent oracle 2: hand-rolled DER over the TSTInfo
                // inside the token, compared against node:crypto bytes.
                const tstInfoBytes = handExtractTstInfoBytes(fixture.input);
                const tstInfo = handParseTstInfo(tstInfoBytes);
                expect(tstInfo.algorithmOid).toBe(HASH_OIDS[input.hashAlgorithm]);
                expect(tstInfo.digest).toEqual(nodeDigest(input.data, input.hashAlgorithm));
                expect(tstInfo.digest).toEqual(tsq.digest);
                expect(tstInfo.nonce).toEqual(nonce);
                if (input.policy !== undefined) {
                    expect(tstInfo.policy).toBe(input.policy);
                }

                // Independent oracle 3: pkijs decode of the request (the
                // library binds via its own path; pkijs re-decodes here).
                const parsed = asn1js.fromBER(toArrayBuffer(request));
                expect(parsed.offset).toBe(request.length);
                const tsReq = new pkijs.TimeStampReq({ schema: parsed.result });
                expect(tsReq.messageImprint.hashAlgorithm.algorithmId).toBe(
                    HASH_OIDS[input.hashAlgorithm]
                );
                expect(
                    new Uint8Array(tsReq.messageImprint.hashedMessage.valueBlock.valueHexView)
                ).toEqual(nodeDigest(input.data, input.hashAlgorithm));
            }),
            { seed: SEED_RB_VALID, numRuns: VALID_RUNS }
        );

        // No vacuous coverage: every axis must actually execute.
        expect([...seenHashes].sort()).toEqual(["SHA-256", "SHA-384", "SHA-512"]);
        expect(seenCertReq.has(true) && seenCertReq.has(false)).toBe(true);
        expect(seenPolicies.has("<absent>")).toBe(true);
        expect(seenPolicies.size).toBeGreaterThan(1);
        expect([...seenForms].sort()).toEqual(["raw", "response"]);
    }, 60000);

    it("rejects targeted digest/nonce/eContentType/policy mutations", async () => {
        const seenKinds = new Set<string>();

        await fc.assert(
            fc.asyncProperty(mutationInputArb, async (input) => {
                seenKinds.add(input.kind);

                const { request, nonce } = await createTimestampRequest(input.data, {
                    hashAlgorithm: input.hashAlgorithm,
                    policy: MUTATION_POLICY,
                    requestCertificate: true,
                });

                const expectedDigest = nodeDigest(input.data, input.hashAlgorithm);
                let fixture: Awaited<ReturnType<typeof createRFC3161TokenFixtureFromRequest>>;
                let expectedCode = TimestampErrorCode.VERIFICATION_FAILED;
                switch (input.kind) {
                    case "wrong-digest":
                        fixture = await createRFC3161TokenFixtureFromRequest(request, {
                            imprint: "mismatch",
                        });
                        break;
                    case "wrong-nonce":
                        fixture = await createRFC3161TokenFixtureFromRequest(request, {
                            responseNonce: distinctPositiveNonce(input.nonceBytes, nonce),
                        });
                        break;
                    case "wrong-econtenttype":
                        fixture = await createRFC3161TokenFixtureFromRequest(request, {
                            eContentType: "data",
                        });
                        expectedCode = TimestampErrorCode.MALFORMED_RESPONSE;
                        break;
                    case "wrong-policy":
                        fixture = await createRFC3161TokenFixtureFromRequest(request, {
                            responsePolicy: MUTATION_WRONG_POLICY,
                        });
                        break;
                }

                // The mutation must really be on the wire (hand-rolled
                // oracle), otherwise the rejection below proves nothing.
                if (input.kind === "wrong-econtenttype") {
                    expect(handExtractEContentType(fixture.input)).toBe(ID_DATA);
                } else {
                    const tstInfo = handParseTstInfo(handExtractTstInfoBytes(fixture.input));
                    if (input.kind === "wrong-digest") {
                        expect(tstInfo.digest).not.toEqual(expectedDigest);
                        expect(tstInfo.nonce).toEqual(nonce);
                    } else if (input.kind === "wrong-nonce") {
                        expect(tstInfo.digest).toEqual(expectedDigest);
                        expect(tstInfo.nonce).not.toEqual(nonce);
                    } else {
                        expect(tstInfo.policy).toBe(MUTATION_WRONG_POLICY);
                        expect(tstInfo.digest).toEqual(expectedDigest);
                    }
                }

                await expect(
                    validateTimestampToken(fixture.input, {
                        data: input.data,
                        hashAlgorithm: input.hashAlgorithm,
                        nonce,
                        policy: MUTATION_POLICY,
                        requestCertificate: true,
                    })
                ).rejects.toMatchObject({ code: expectedCode });
            }),
            { seed: SEED_RB_MUTATION, numRuns: MUTATION_RUNS }
        );

        expect([...seenKinds].sort()).toEqual([
            "wrong-digest",
            "wrong-econtenttype",
            "wrong-nonce",
            "wrong-policy",
        ]);
    }, 60000);

    it("cross-checks one fixed vector with the OpenSSL CLI", async () => {
        const probe = spawnSync("openssl", ["version"], { encoding: "utf8" });
        if (probe.status !== 0) {
            throw new Error("OpenSSL CLI is required for the T14 cross-check oracle");
        }
        const data = new TextEncoder().encode("T14 openssl golden vector");
        const { request } = await createTimestampRequest(data, {
            hashAlgorithm: "SHA-256",
            requestCertificate: true,
        });
        const fixture = await createRFC3161TokenFixtureFromRequest(request, { form: "response" });

        const tempDir = mkdtempSync(join(tmpdir(), "pdf-rfc3161-t14-ossl-"));
        try {
            const queryPath = join(tempDir, "tsq.der");
            const replyPath = join(tempDir, "tsr.der");
            const caPath = join(tempDir, "tsa.pem");
            writeFileSync(queryPath, request);
            writeFileSync(replyPath, fixture.input);
            const pemBody = Buffer.from(fixture.signerCertificate).toString("base64");
            const pemLines = pemBody.match(/.{1,64}/g) ?? [];
            writeFileSync(
                caPath,
                `-----BEGIN CERTIFICATE-----\n${pemLines.join("\n")}\n-----END CERTIFICATE-----\n`
            );

            const verify = spawnSync(
                "openssl",
                ["ts", "-verify", "-queryfile", queryPath, "-in", replyPath, "-CAfile", caPath],
                { encoding: "utf8" }
            );
            const verifyOutput = `${verify.stdout}${verify.stderr}`;
            expect(verify.status, `openssl ts -verify failed: ${verifyOutput}`).toBe(0);
            expect(verifyOutput).toMatch(/Verification:\s*OK/);

            const text = spawnSync("openssl", ["ts", "-reply", "-in", replyPath, "-text"], {
                encoding: "utf8",
            });
            expect(text.status).toBe(0);
            const expectedHex = Buffer.from(nodeDigest(data, "SHA-256")).toString("hex");
            // OpenSSL prints the imprint as "Message data:" followed by
            // "0000 - xx xx ..." lines; scope the hex scrape to that block
            // so serial/signature hex cannot join the stream.
            const lines = text.stdout.split("\n");
            const start = lines.findIndex((line) => line.includes("Message data:"));
            expect(start).toBeGreaterThanOrEqual(0);
            let scraped = "";
            for (let index = start + 1; index < lines.length; index++) {
                const trimmed = (lines[index] ?? "").trim();
                if (!/^[0-9a-fA-F]{4} - /.test(trimmed)) break;
                // "0000 - 84 27 ... ac-34 ..." plus an ASCII dump; read
                // only the hex field so dump letters cannot join the bytes.
                const rest = trimmed.slice(7);
                let cursor = 0;
                while (cursor + 1 < rest.length) {
                    const hi = rest[cursor] ?? "";
                    const lo = rest[cursor + 1] ?? "";
                    if (!isHexChar(hi) || !isHexChar(lo)) break;
                    scraped += hi + lo;
                    cursor += 2;
                    const sep = rest[cursor] ?? "";
                    if (sep === " " || sep === "-") cursor += 1;
                    else break;
                }
            }
            expect(scraped.toLowerCase()).toBe(expectedHex);

            // The hand reader must agree with OpenSSL on the same bytes.
            const tstInfo = handParseTstInfo(handExtractTstInfoBytes(fixture.input));
            expect(Buffer.from(tstInfo.digest).toString("hex")).toBe(expectedHex);
        } finally {
            rmSync(tempDir, { force: true, recursive: true });
        }
    }, 60000);
});
