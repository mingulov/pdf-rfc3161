import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const TEST_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const SCRIPTS_DIRECTORY = resolve(TEST_DIRECTORY, "../../scripts");
const SCRIPT_EXTENSIONS = [".ts", ".mts", ".cts", ".js", ".mjs", ".cjs"];
// Fully bounded (no quantifiers): interpolation of an error binding.
const ERROR_INTERPOLATION = /\$\{(?:error|err|exception)[}.]/;

/**
 * CodeQL js/stack-trace-exposure backstop: harness HTTP fixtures must
 * never send error-derived text (messages, stacks) in responses. Log
 * server-side via console.error; responses stay opaque static strings.
 */
function sendsErrorDerivedBody(line: string): boolean {
    if (!line.includes(".end(")) {
        return false;
    }
    return (
        line.includes("String(err") ||
        line.includes(".end(error)") ||
        line.includes(".end(err)") ||
        ERROR_INTERPOLATION.test(line)
    );
}

describe("harness error-response policy", () => {
    it("flags error-derived response bodies", () => {
        expect(sendsErrorDerivedBody("            response.end(String(error));")).toBe(true);
        expect(
            sendsErrorDerivedBody(
                "            response.end(`proxy: upstream failed: ${String(error)}`);"
            )
        ).toBe(true);
        expect(sendsErrorDerivedBody('            response.end("tsa: internal error");')).toBe(
            false
        );
    });

    it("keeps fixture HTTP responses free of error-derived text", () => {
        const violations: string[] = [];
        for (const entry of readdirSync(SCRIPTS_DIRECTORY)) {
            if (!SCRIPT_EXTENSIONS.some((extension) => entry.endsWith(extension))) {
                continue;
            }
            const content = readFileSync(join(SCRIPTS_DIRECTORY, entry), "utf8");
            const lines = content.split("\n");
            for (let index = 0; index < lines.length; index++) {
                const line = lines[index];
                if (line === undefined) {
                    continue;
                }
                if (sendsErrorDerivedBody(line)) {
                    violations.push(`${entry}:${(index + 1).toString()}: ${line.trim()}`);
                }
            }
        }
        expect(violations).toEqual([]);
    });
});
