import { spawnSync } from "node:child_process";
import { runInNewContext } from "node:vm";
import { describe, expect, it, vi } from "vitest";
import * as commandUtils from "../../../demo/src/utils.js";

const HOSTILE_URLS = [
    "https://example.invalid/crl;printf${IFS}INJECTED;#",
    "https://example.invalid/crl?one=1&two=2",
    "https://example.invalid/$(printf INJECTED)",
    "https://example.invalid/`printf INJECTED`",
    "https://example.invalid/'single'\"double\"\\backslash",
    "https://example.invalid/path\nprintf INJECTED",
    "https://example.invalid/{one,two}/[1-9]",
];

describe("demo POSIX curl commands", () => {
    it.skipIf(process.platform === "win32").each(HOSTILE_URLS)(
        "passes the exact URL as one shell argument: %s",
        (url) => {
            expect(commandUtils.generateCurlCommand).toBeTypeOf("function");
            const command = commandUtils.generateCurlCommand(url, "crl.der");
            // Replace curl with an argument printer: no network or file writes.
            const result = spawnSync(
                "sh",
                ["-c", `curl() { printf '%s\\0' "$@"; }; ${command}`],
                { encoding: "utf8" }
            );
            expect(result.status).toBe(0);
            expect(result.stderr).toBe("");
            expect(result.stdout.split("\0")).toEqual([
                "--globoff", "--output", "crl.der", "--", url, "",
            ]);
        }
    );

    it("includes quoted POST content type and request filename", () => {
        expect(commandUtils.generateCurlCommand).toBeTypeOf("function");
        const command = commandUtils.generateCurlCommand(
            "https://example.invalid/ocsp", "ocsp_resp.der", "ocsp_req.der",
            "application/ocsp-request"
        );
        expect(command).toContain("-H 'Content-Type: application/ocsp-request'");
        expect(command).toContain("--data-binary '@ocsp_req.der'");
        expect(command).toContain("--output 'ocsp_resp.der' -- 'https://example.invalid/ocsp'");
    });

    it.each(["file:///etc/passwd", "--config=evil", "not a URL"])(
        "does not generate an executable command for %s",
        (url) => {
            expect(commandUtils.generateCurlCommand).toBeTypeOf("function");
            expect(commandUtils.generateCurlCommand(url, "out.der")).toBe(
                "# Invalid URL: only HTTP(S) URLs are supported."
            );
        }
    );
});

describe("demo browser-console scripts", () => {
    const url = 'https://example.invalid/");globalThis.injected = true; //';

    it.each([
        commandUtils.generateFetchConsoleScript,
        commandUtils.generateFetchConsoleScriptOneLiner,
    ])("keeps URL text inside its JavaScript string", async (generate) => {
        const fetch = vi.fn().mockResolvedValue({ arrayBuffer: () => new ArrayBuffer(0) });
        const sandbox = {
            fetch,
            btoa: () => "",
            console: { log: vi.fn() },
            navigator: { clipboard: { writeText: vi.fn() } },
            injected: false,
        };
        await runInNewContext(generate(url), sandbox);
        expect(sandbox.injected).toBe(false);
        expect(fetch).toHaveBeenCalledWith(url, expect.objectContaining({ method: "GET" }));
    });

    it("quotes the diagnostic label and content type too", async () => {
        const label = '");globalThis.injected = true; //';
        const contentType = '" }, body: (globalThis.injected = true), x: "';
        const fetch = vi.fn().mockResolvedValue({ arrayBuffer: () => new ArrayBuffer(0) });
        const sandbox = {
            fetch,
            btoa: () => "",
            console: { log: vi.fn() },
            navigator: { clipboard: { writeText: vi.fn() } },
            injected: false,
        };
        await runInNewContext(
            commandUtils.generateFetchConsoleScript(
                "https://example.invalid/tsr", Uint8Array.of(1), label, contentType
            ),
            sandbox
        );
        expect(sandbox.injected).toBe(false);
        expect(fetch).toHaveBeenCalledWith(
            "https://example.invalid/tsr",
            expect.objectContaining({ headers: { "Content-Type": contentType } })
        );
    });
});
