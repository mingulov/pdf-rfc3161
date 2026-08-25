import { spawn } from "node:child_process";
import { createServer, type Server } from "node:http";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PDFArray, PDFDict, PDFDocument, PDFName, PDFRef } from "pdf-lib-incremental-save";
import {
    CLI_PADES_INPUT_PDF,
    CLI_PADES_ROOT_CERTIFICATE,
    CLI_PADES_TIMESTAMP_GEN_TIME,
    CLI_PADES_TIMESTAMP_RESPONSE,
} from "../fixtures/cli-pades/cli-pades-response-fixture.js";
import { extractTimestamps } from "pdf-rfc3161";

const TEST_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(TEST_DIRECTORY, "../../../..");
const CLI_PATH = join(REPOSITORY_ROOT, "packages/cli/dist/cli.cjs");
const DETERMINISTIC_WEBCRYPTO_PRELOAD = join(
    TEST_DIRECTORY,
    "../fixtures/cli-pades/deterministic-webcrypto.cjs"
);
const OMIT_M_CASES: [string, string[]][] = [
    ["default", []],
    ["--omit-m", ["--omit-m"]],
];

interface CliResult {
    code: number;
    stdout: string;
    stderr: string;
}

function runCli(args: string[]): Promise<CliResult> {
    return new Promise((resolveResult) => {
        const child = spawn(process.execPath, [CLI_PATH, ...args], {
            cwd: REPOSITORY_ROOT,
            env: {
                ...process.env,
                // The CLI child can only find Node itself. A regression that
                // starts an ambient `openssl` executable fails immediately.
                PATH: dirname(process.execPath),
                OPENSSL: "/nonexistent/pdf-rfc3161-openssl",
                NODE_OPTIONS: [
                    process.env.NODE_OPTIONS,
                    "--require",
                    DETERMINISTIC_WEBCRYPTO_PRELOAD,
                ]
                    .filter((value): value is string => value !== undefined)
                    .join(" "),
            },
            stdio: ["ignore", "pipe", "pipe"],
        });
        let stdout = "";
        let stderr = "";
        child.stdout.on("data", (data: Buffer) => {
            stdout += data.toString();
        });
        child.stderr.on("data", (data: Buffer) => {
            stderr += data.toString();
        });
        child.on("close", (code) => {
            resolveResult({ code: code ?? 1, stdout, stderr });
        });
        child.on("error", (error) => {
            resolveResult({ code: 1, stdout, stderr: error.message });
        });
    });
}

function writeInputPdf(path: string): void {
    writeFileSync(path, CLI_PADES_INPUT_PDF);
}

async function signatureDictionary(path: string): Promise<PDFDict> {
    const document = await PDFDocument.load(readFileSync(path), { updateMetadata: false });
    const acroForm = document.catalog.lookup(PDFName.of("AcroForm"), PDFDict);
    const fields = acroForm.lookup(PDFName.of("Fields"), PDFArray);
    const fieldRef = fields.get(0);
    if (!(fieldRef instanceof PDFRef)) throw new Error("Timestamp field must be indirect");
    const field = document.context.lookup(fieldRef, PDFDict);
    const signatureRef = field.get(PDFName.of("V"));
    if (!(signatureRef instanceof PDFRef)) throw new Error("Timestamp value must be indirect");
    return document.context.lookup(signatureRef, PDFDict);
}

describe.sequential("CLI PAdES safety", () => {
    let server: Server;
    let tsaUrl: string;
    let directory: string;
    let rootCertificatePath: string;

    beforeAll(async () => {
        directory = mkdtempSync(join(tmpdir(), "pdf-rfc3161-cli-pades-"));
        rootCertificatePath = join(directory, "root.pem");
        writeFileSync(rootCertificatePath, CLI_PADES_ROOT_CERTIFICATE);
        server = createServer((request, response) => {
            if (request.method !== "POST") {
                response.writeHead(405).end();
                return;
            }
            response.writeHead(200, { "content-type": "application/timestamp-reply" });
            response.end(CLI_PADES_TIMESTAMP_RESPONSE);
        });
        await new Promise<void>((resolveServer, rejectServer) => {
            server.once("error", rejectServer);
            server.listen(0, "::1", () => {
                server.off("error", rejectServer);
                resolveServer();
            });
        });
        const address = server.address();
        if (!address || typeof address === "string") throw new Error("Local TSA has no TCP address");
        // `.localhost` is a special-use loopback domain. Unlike an IP literal,
        // it exercises the public CLI without adding a test-only SSRF bypass.
        tsaUrl = `http://tsa.localhost:${String(address.port)}/tsr`;
    });

    afterAll(async () => {
        await new Promise<void>((resolveServer) => server.close(() => resolveServer()));
        rmSync(directory, { force: true, recursive: true });
    });

    it.each(OMIT_M_CASES)("omits /M from real timestamp output by %s", async (_: string, flags: string[]) => {
        const input = join(directory, `input-${flags.length.toString()}.pdf`);
        const output = join(directory, `output-${flags.length.toString()}.pdf`);
        writeInputPdf(input);

        const result = await runCli([
            "timestamp",
            tsaUrl,
            input,
            output,
            "--no-ltv",
            ...flags,
        ]);

        expect(result).toMatchObject({ code: 0, stderr: "" });
        expect(result.stdout).toContain("SUCCESS: Timestamp added successfully!");
        expect(result.stdout).toContain(CLI_PADES_TIMESTAMP_GEN_TIME);
        expect((await signatureDictionary(output)).get(PDFName.of("M"))).toBeUndefined();
        const timestamps = await extractTimestamps(readFileSync(output));
        expect(timestamps).toHaveLength(1);
        expect(timestamps[0]?.info.genTime.toISOString()).toBe(CLI_PADES_TIMESTAMP_GEN_TIME);
    });

    it("states the trust boundary accurately and does not mislabel certificate order", async () => {
        const input = join(directory, "verify-input.pdf");
        const output = join(directory, "verify-output.pdf");
        writeInputPdf(input);
        const timestamped = await runCli([
            "timestamp",
            tsaUrl,
            input,
            output,
            "--no-ltv",
        ]);
        expect(timestamped).toMatchObject({ code: 0, stderr: "" });

        const withoutTrust = await runCli(["verify", output]);
        expect(withoutTrust).toMatchObject({ code: 0, stderr: "" });
        expect(withoutTrust.stdout).toContain("Cryptographically consistent; TSA trust NOT EVALUATED");
        expect(withoutTrust.stdout).not.toContain("[OK] Verified");
        expect(withoutTrust.stdout).not.toContain("TSA Name:");
        expect(withoutTrust.stdout).toContain("Certificates:");

        const withTrust = await runCli(["verify", output, "--trust-store", rootCertificatePath]);
        expect(withTrust).toMatchObject({ code: 0, stderr: "" });
        expect(withTrust.stdout).toContain("trusted under supplied policy");
    });
});
