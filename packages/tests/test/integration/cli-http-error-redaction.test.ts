import { spawn } from "node:child_process";
import { createServer, type Server } from "node:http";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { assertCliDistIsFresh, CLI_DIST_PATH } from "../utils/cli-dist.js";
import { makeInput } from "../utils/timestamp-fixtures.js";

const TEST_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(TEST_DIRECTORY, "../../../..");
const CLI_PATH = CLI_DIST_PATH;
// These cases run the built bundle, so a stale dist would test old code.
assertCliDistIsFresh();

// sol-pr85 I1: the HTTP reason phrase is responder-controlled. The CLI must
// not print reflected secrets on stdout or stderr, with or without --verbose.
const URL_MARKER = "cli-url-marker";
const REASON_MARKER = "cli-reason-marker";
const POISONED_REASON =
    `Rejected https://reason-user:reason-pass@tsa.example.test/path` +
    `?token=${REASON_MARKER}#frag`;

const VERBOSE_CASES: [string, string[]][] = [
    ["default", []],
    ["verbose", ["--verbose"]],
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

describe("CLI HTTP error redaction", { concurrent: false }, () => {
    let server: Server;
    let tsaUrl: string;
    let directory: string;

    beforeAll(async () => {
        directory = mkdtempSync(join(tmpdir(), "pdf-rfc3161-cli-redaction-"));
        server = createServer((_request, response) => {
            response.writeHead(404, POISONED_REASON);
            response.end("nope");
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
        tsaUrl = `http://tsa.localhost:${String(address.port)}/tsr?token=${URL_MARKER}`;
    });

    afterAll(async () => {
        await new Promise<void>((resolveServer) => server.close(() => resolveServer()));
        rmSync(directory, { force: true, recursive: true });
    });

    it.each(VERBOSE_CASES)("omits reflected secrets from CLI output (%s)", async (_: string, flags: string[]) => {
        const input = join(directory, `input-${String(flags.length)}.pdf`);
        const output = join(directory, `output-${String(flags.length)}.pdf`);
        writeFileSync(input, await makeInput(true));

        const result = await runCli(["timestamp", tsaUrl, input, output, "--no-ltv", "--retry", "0", ...flags]);

        expect(result.code).toBe(1);
        expect(result.stderr).toContain("NETWORK_ERROR");
        expect(result.stderr).toContain("HTTP 404");
        expect(result.stderr).not.toContain(URL_MARKER);
        expect(result.stderr).not.toContain(REASON_MARKER);
        expect(result.stderr).not.toContain("reason-user");
        expect(result.stderr).not.toContain("reason-pass");
        expect(result.stdout).not.toContain(URL_MARKER);
        expect(result.stdout).not.toContain(REASON_MARKER);
    });
});
