import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
    PADES_ORACLE_ARTIFACTS,
    PADES_ORACLE_POLICY,
    assertPadesOracleTools,
    padesOraclePaths,
    type OracleCommandRunner,
} from "../../scripts/pades-oracles.js";

const TEST_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(TEST_DIRECTORY, "../../../..");

function pinnedOracleRunner(overrides: Record<string, string> = {}): OracleCommandRunner {
    const paths = padesOraclePaths();
    return (command, args) => {
        const key = `${command} ${args.join(" ")}`;
        const responses: Record<string, string> = {
            "qpdf --version": `qpdf version ${PADES_ORACLE_POLICY.qpdf.commandVersion}\nRun qpdf --copyright\n`,
            "openssl version": `OpenSSL ${PADES_ORACLE_POLICY.openssl.commandVersion} 30 Jan 2024\n`,
            [`ldd ${join(paths.bin, "qpdf")}`]: `libqpdf.so.29 => ${join(paths.library, "libqpdf.so.29")} (0x1)\n`,
            [`ldd ${join(paths.bin, "openssl")}`]: [
                `libssl.so.3 => ${join(paths.library, "libssl.so.3")} (0x1)`,
                `libcrypto.so.3 => ${join(paths.library, "libcrypto.so.3")} (0x2)`,
            ].join("\n"),
            ...Object.fromEntries(
                PADES_ORACLE_ARTIFACTS.flatMap((artifact) => {
                    const artifactPath = join(paths.artifacts, artifact.filename);
                    return [
                        [`sha256sum ${artifactPath}`, `${artifact.sha256}  ${artifactPath}\n`],
                        [
                            `dpkg-deb --field ${artifactPath} Package Version Architecture`,
                            [
                                `Package: ${artifact.package}`,
                                `Version: ${artifact.packageVersion}`,
                                `Architecture: ${PADES_ORACLE_POLICY.architecture}`,
                            ].join("\n"),
                        ],
                    ];
                })
            ),
            ...overrides,
        };
        return { status: 0, stdout: responses[key] ?? "", stderr: "" };
    };
}

describe("offline PAdES oracle policy", () => {
    it("accepts only hash-pinned artifacts, local libraries, and executable banners", () => {
        expect(() => assertPadesOracleTools(pinnedOracleRunner())).not.toThrow();
        expect(() =>
            assertPadesOracleTools(
                pinnedOracleRunner({
                    "qpdf --version": "qpdf version 12.0.0\n",
                })
            )
        ).toThrow(/Pinned qpdf banner mismatch/);
        const firstArtifact = PADES_ORACLE_ARTIFACTS[0];
        if (firstArtifact === undefined) throw new Error("Pinned oracle artifact is required");
        expect(() =>
            assertPadesOracleTools(
                pinnedOracleRunner({
                    [`sha256sum ${join(padesOraclePaths().artifacts, firstArtifact.filename)}`]:
                        "00  artifact.deb\n",
                })
            )
        ).toThrow(/SHA-256 mismatch/);
    });

    it("keeps CI, release, and publish on the one pinned installation policy", () => {
        for (const workflow of ["ci.yml", "release.yml", "publish.yml"]) {
            const content = readFileSync(
                resolve(REPOSITORY_ROOT, ".github/workflows", workflow),
                "utf8"
            );
            expect(content).toContain(`runs-on: ${PADES_ORACLE_POLICY.ubuntuRunner}`);
            expect(content).not.toContain("ubuntu-latest");
            expect(content).toContain(
                `python-version: '${PADES_ORACLE_POLICY.pythonVersion}'`
            );
            expect(content).toContain("pnpm --filter pdf-rfc3161-tests run install:pades-oracles");
            expect(content).toContain("pnpm --filter pdf-rfc3161-tests run assert:pades-oracles");
        }
    });

    it("downloads fixed official artifacts, verifies them, and extracts without host installation", () => {
        for (const artifact of PADES_ORACLE_ARTIFACTS) {
            const url = new URL(artifact.url);
            expect(url.protocol).toBe("https:");
            expect(["archive.ubuntu.com", "security.ubuntu.com"]).toContain(url.hostname);
            expect(url.pathname).toContain(artifact.filename);
            expect(artifact.sha256).toMatch(/^[a-f0-9]{64}$/);
        }

        const installer = readFileSync(
            resolve(REPOSITORY_ROOT, "packages/tests/scripts/install-pades-oracles.ts"),
            "utf8"
        );
        expect(installer).toContain('redirect: "error"');
        expect(installer).toContain("SHA-256 mismatch");
        expect(installer).toContain('run("dpkg-deb", ["--extract"');
        expect(installer).toContain("GITHUB_ENV");
        expect(installer).toContain("GITHUB_PATH");
        expect(installer).not.toContain("apt-get");
        expect(installer).not.toContain("sudo");
        expect(installer).not.toContain('"--install"');
        expect(installer.indexOf("const actualSha256 = hash.digest")).toBeLessThan(
            installer.indexOf('run("dpkg-deb", ["--extract"')
        );
    });

    it("asserts the same local policy before the conformance harness touches an oracle", () => {
        const harness = readFileSync(
            resolve(REPOSITORY_ROOT, "packages/tests/scripts/offline-pades-conformance.ts"),
            "utf8"
        );
        const activation = harness.indexOf("activatePadesOracleEnvironment();");
        const assertion = harness.indexOf("assertPadesOracleTools();");
        const localTsa = harness.indexOf("const { rootCert, config } = createLocalTsa");
        expect(activation).toBeGreaterThan(-1);
        expect(assertion).toBeGreaterThan(activation);
        expect(localTsa).toBeGreaterThan(assertion);
        expect(harness).toContain("PINNED_ORACLE_INSTALLATION_GUIDANCE");
        expect(harness).toContain("Expected Python ${PADES_ORACLE_POLICY.pythonVersion}");
        expect(harness).not.toContain("apt-get");

        const documentation = readFileSync(
            resolve(REPOSITORY_ROOT, "docs/pades-oracle-tools.md"),
            "utf8"
        );
        expect(documentation).toContain(PADES_ORACLE_POLICY.qpdf.packageVersion);
        expect(documentation).toContain(PADES_ORACLE_POLICY.openssl.packageVersion);
        expect(documentation).toContain(PADES_ORACLE_POLICY.opensslRuntime.package);
        expect(documentation).toMatch(
            /dynamic loader and remaining transitive system libraries are\s+host-runner dependencies/
        );
        for (const artifact of PADES_ORACLE_ARTIFACTS) {
            expect(documentation).toContain(artifact.url);
            expect(documentation).toContain(artifact.sha256);
        }
        expect(documentation).toContain("Bumping the policy");
    });

    it("keeps the normal CLI PAdES regression independent from ambient OpenSSL", () => {
        const cliPadesTest = readFileSync(
            resolve(REPOSITORY_ROOT, "packages/tests/test/integration/cli-pades-safety.test.ts"),
            "utf8"
        );
        expect(cliPadesTest).not.toContain("local-tsa-fixture");
        expect(cliPadesTest).toContain("cli-pades-response-fixture");
        expect(cliPadesTest).toContain("deterministic-webcrypto.cjs");
        expect(cliPadesTest).toContain("PATH: dirname(process.execPath)");

        const fixtureReadme = readFileSync(
            resolve(REPOSITORY_ROOT, "packages/tests/test/fixtures/cli-pades/README.md"),
            "utf8"
        );
        expect(fixtureReadme).toContain("project-generated");
        expect(fixtureReadme).toContain("OpenSSL is not required to run this fixture");
        expect(fixtureReadme).toContain("approximately 100-year");

        const limitations = readFileSync(
            resolve(REPOSITORY_ROOT, "docs/pdf-lib-incremental-save-limitations.md"),
            "utf8"
        );
        expect(limitations).toContain("raw active offsets or revision ownership");
        expect(limitations).toContain("ambiguous project signature occurrence fails closed");
        expect(limitations).toMatch(/targeted ByteRange checks do not harden the loader/i);
        expect(limitations).toMatch(/future work\s+separate/);
    });
});
