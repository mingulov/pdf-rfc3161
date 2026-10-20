import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../../..");
const workflow = readFileSync(join(ROOT, ".github/workflows/ci.yml"), "utf8");
const job = workflow.split("  node-runtime-floor:")[1]?.split("\n  package-gates:")[0] ?? "";

function stepRun(name: string): string {
    const step = job.split(`      - name: ${name}\n`)[1]?.split("\n      - ")[0] ?? "";
    const lines = step.split("\n");
    const index = lines.findIndex((line) => line.startsWith("        run:"));
    const run = lines[index]?.slice("        run:".length).trim();
    expect(run, `${name} must have an executable run step`).toBeTruthy();
    return run === "|"
        ? lines
              .slice(index + 1)
              .filter((line) => line.startsWith("          "))
              .map((line) => line.slice(10))
              .join("\n")
        : (run ?? "");
}

describe("minimum runtime artifact policy", () => {
    // This executes the Ubuntu-only workflow shell (bash + GNU sha256sum).
    // Keep local Windows/macOS suites independent of Linux command availability.
    it.runIf(process.platform === "linux")(
        "packs on Node 26 and verifies those exact bytes after switching runtimes",
        () => {
            const pack = stepRun("Pack runtime-floor candidates on build Node");
            const verify = stepRun("Verify packed consumer at runtime floor");
            expect(job.indexOf("Pack runtime-floor candidates on build Node")).toBeLessThan(
                job.indexOf("Setup minimum supported runtime")
            );
            const directory = mkdtempSync(join(tmpdir(), "runtime floor policy "));
            try {
                const bin = join(directory, "bin");
                mkdirSync(bin);
                writeFileSync(
                    join(bin, "pnpm"),
                    `#!/usr/bin/env node
const fs = require("node:fs"), path = require("node:path"), assert = require("node:assert/strict");
const args = process.argv.slice(2);
if (args.includes("pack")) {
    assert.equal(process.env.TEST_NODE_VERSION, "26", "packing must use build runtime");
    const destination = args[args.indexOf("--pack-destination") + 1];
    const name = args[args.indexOf("--filter") + 1];
    fs.writeFileSync(path.join(destination, name + ".tgz"), name + " built on Node 26");
} else {
    assert(args.includes("test:package"));
    assert.equal(process.env.TEST_NODE_VERSION, "22.18.0");
    const positional = args.slice(args.indexOf("--") + 1, args.indexOf("--receipt"));
    assert.equal(positional.length, 2, "consumer must receive exact core and CLI tarballs");
    assert.equal(fs.readFileSync(positional[0], "utf8"), "pdf-rfc3161 built on Node 26");
    assert.equal(fs.readFileSync(positional[1], "utf8"), "pdf-rfc3161-cli built on Node 26");
    fs.writeFileSync(args[args.indexOf("--receipt") + 1], JSON.stringify({ paths: positional }));
}
`,
                    { mode: 0o755 }
                );
                const environment = {
                    ...process.env,
                    PATH: bin + ":" + (process.env.PATH ?? ""),
                    RUNNER_TEMP: directory,
                    GITHUB_ENV: join(directory, "environment"),
                    TEST_NODE_VERSION: "26",
                };
                const packed = spawnSync("bash", ["-euo", "pipefail", "-c", pack], {
                    env: environment,
                    encoding: "utf8",
                });
                expect(packed.status, packed.stderr).toBe(0);
                const values = Object.fromEntries(
                    readFileSync(environment.GITHUB_ENV, "utf8")
                        .trim()
                        .split("\n")
                        .map((line) => {
                            const separator = line.indexOf("=");
                            return [line.slice(0, separator), line.slice(separator + 1)];
                        })
                );
                const consumerEnvironment = {
                    ...environment,
                    ...values,
                    TEST_NODE_VERSION: "22.18.0",
                };
                const verified = spawnSync("bash", ["-euo", "pipefail", "-c", verify], {
                    env: consumerEnvironment,
                    encoding: "utf8",
                });
                expect(verified.status, verified.stderr).toBe(0);
                writeFileSync(values.CORE_TARBALL ?? "", "substituted artifact");
                const tampered = spawnSync("bash", ["-euo", "pipefail", "-c", verify], {
                    env: consumerEnvironment,
                    encoding: "utf8",
                });
                expect(tampered.status).not.toBe(0);
                expect(tampered.stdout + tampered.stderr).toContain("FAILED");
            } finally {
                rmSync(directory, { recursive: true, force: true });
            }
        }
    );

    it("pins the externalized ASN1.js consumer to the core dependency floor", () => {
        const core = JSON.parse(readFileSync(join(ROOT, "packages/core/package.json"), "utf8")) as {
            dependencies: { asn1js: string };
        };
        const source = readFileSync(
            join(ROOT, "packages/tests/scripts/test-packed-consumer.ts"),
            "utf8"
        );
        const pin = /asn1js: "([0-9.]{1,30})"/.exec(source)?.[1] ?? "";
        expect(pin).not.toBe("");
        expect(core.dependencies.asn1js).toBe("^" + pin);
    });
});
