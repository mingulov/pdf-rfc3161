import { spawnSync } from "node:child_process";
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

describe("offline PAdES validation-tool policy", () => {
    it("keeps the legacy conformance command as an interoperability alias", () => {
        const packageJson = JSON.parse(
            readFileSync(resolve(REPOSITORY_ROOT, "packages/tests/package.json"), "utf8")
        ) as { scripts?: Record<string, string> };

        expect(packageJson.scripts?.["test:interoperability"]).toBe(
            "tsx scripts/offline-pades-conformance.ts"
        );
        expect(packageJson.scripts?.["test:conformance"]).toBe(
            packageJson.scripts?.["test:interoperability"]
        );
    });

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
        if (firstArtifact === undefined) throw new Error("Pinned validation artifact is required");
        expect(() =>
            assertPadesOracleTools(
                pinnedOracleRunner({
                    [`sha256sum ${join(padesOraclePaths().artifacts, firstArtifact.filename)}`]:
                        "00  artifact.deb\n",
                })
            )
        ).toThrow(/SHA-256 mismatch/);
    });

    it("keeps CI and release on the one pinned installation policy", () => {
        for (const workflow of ["ci.yml", "release.yml"]) {
            const content = readFileSync(
                resolve(REPOSITORY_ROOT, ".github/workflows", workflow),
                "utf8"
            );
            expect(content).toContain(`runs-on: ${PADES_ORACLE_POLICY.ubuntuRunner}`);
            expect(content).not.toContain("ubuntu-latest");
            expect(
                content.includes(`python-version: '${PADES_ORACLE_POLICY.pythonVersion}'`) ||
                    content.includes(`python-version: "${PADES_ORACLE_POLICY.pythonVersion}"`)
            ).toBe(true);
            expect(content).toContain("pnpm --filter pdf-rfc3161-tests run install:pades-oracles");
            expect(content).toContain("pnpm --filter pdf-rfc3161-tests run assert:pades-oracles");
        }
    });

    it("builds workspace declarations before type-aware release lint", () => {
        const workflow = readFileSync(
            resolve(REPOSITORY_ROOT, ".github/workflows/release.yml"),
            "utf8"
        );
        const buildStep = workflow.indexOf("- name: Build");
        const lintStep = workflow.indexOf("- name: Lint");

        expect(buildStep).toBeGreaterThan(-1);
        expect(lintStep).toBeGreaterThan(buildStep);
    });

    it("isolates npm trusted staging and stages pnpm-normalized tarballs", () => {
        const workflow = readFileSync(
            resolve(REPOSITORY_ROOT, ".github/workflows/release.yml"),
            "utf8"
        );
        const changesetConfig = JSON.parse(
            readFileSync(resolve(REPOSITORY_ROOT, ".changeset/config.json"), "utf8")
        ) as { fixed?: string[][] };
        const contributing = readFileSync(resolve(REPOSITORY_ROOT, "CONTRIBUTING.md"), "utf8");
        const triggerBlock = workflow.slice(
            workflow.indexOf("on:"),
            workflow.indexOf("concurrency:")
        );
        const triggerKeyLines = triggerBlock
            .split("\n")
            .filter((line) => /^\s+[a-z_]+:/.test(line));
        const triggerIndent = Math.min(...triggerKeyLines.map((line) => line.search(/\S/)));
        const triggerKeys = triggerKeyLines
            .filter((line) => line.search(/\S/) === triggerIndent)
            .map((line) => line.trim().split(":", 1)[0]);
        const coreJob = workflow.indexOf("  stage-core:");
        const cliJob = workflow.indexOf("  stage-cli:");
        const coreStage = workflow.indexOf(
            "npm stage publish release-artifacts/core/*.tgz --access public"
        );
        const cliStage = workflow.indexOf(
            "npm stage publish release-artifacts/cli/*.tgz --access public"
        );

        expect(workflow).toContain("name: Verify and package");
        expect(triggerKeys).toEqual(["workflow_dispatch"]);
        expect(workflow).toContain("description: Package version to stage (for example, 0.2.0)");
        expect(workflow).toContain("EXPECTED_VERSION: ${{ inputs.version }}");
        expect(workflow).toContain("does not match requested release");
        expect(workflow).toContain("if: github.ref == 'refs/heads/main'");
        expect(workflow).toContain("name: Reject unapplied changesets");
        expect(workflow).toContain("Run pnpm changeset version before releasing");
        expect(workflow).toContain("Public package versions must match");
        expect(workflow).toContain("name: Lint");
        expect(workflow).toContain("run: pnpm lint");
        expect(workflow).toContain("name: Audit packed package contents");
        expect(workflow).toContain("Unexpected file in pdf-rfc3161 tarball");
        expect(workflow).toContain("Expected 27 files in pdf-rfc3161 tarball");
        expect(workflow).toContain("required_core=(");
        expect(workflow).toContain("dist/[a-z][a-z0-9-]{0,63}-[A-Za-z0-9_-]{8}");
        expect(workflow).toContain("workspace:");
        expect(workflow).toContain("name: Stage pdf-rfc3161@${{ inputs.version }} on npm");
        expect(workflow).toContain("name: Stage pdf-rfc3161-cli@${{ inputs.version }} on npm");
        expect(workflow).toContain("name: Verify npm supports staged publishing");
        expect(workflow).toContain("npm 11.15.0 or newer is required");
        expect(workflow).toContain("package-manager-cache: false");
        expect(workflow).toContain(
            "pnpm --filter pdf-rfc3161 pack --pack-destination release-artifacts/core"
        );
        expect(workflow).toContain(
            "pnpm --filter pdf-rfc3161-cli pack --pack-destination release-artifacts/cli"
        );
        expect(coreJob).toBeGreaterThan(-1);
        expect(cliJob).toBeGreaterThan(coreJob);
        expect(workflow.slice(coreJob, cliJob)).toContain("needs: verify");
        expect(workflow.slice(cliJob)).toContain("needs: [verify, stage-core]");
        expect(workflow.match(/id-token: write/g)).toHaveLength(2);
        expect(coreStage).toBeGreaterThan(coreJob);
        expect(coreStage).toBeLessThan(cliJob);
        expect(cliStage).toBeGreaterThan(cliJob);
        expect(workflow).not.toContain("npm publish ");
        expect(workflow).not.toContain("run: npm stage approve");
        expect(workflow).not.toContain("run: npm stage reject");
        expect(workflow).not.toContain("NPM_TOKEN");
        expect(workflow).not.toContain("NODE_AUTH_TOKEN");
        expect(workflow).not.toContain("changesets/action");
        expect(workflow).not.toContain("pnpm -r publish");
        expect(workflow).toContain("retention-days: 7");
        expect(contributing).toContain("./pdf-rfc3161-0.2.0-*.tgz");
        expect(contributing).toContain("./pdf-rfc3161-cli-0.2.0-*.tgz");
        expect(changesetConfig.fixed).toEqual([["pdf-rfc3161", "pdf-rfc3161-cli"]]);
    });

    it("emits newline-terminated package identity records for Bash read", () => {
        const workflow = readFileSync(
            resolve(REPOSITORY_ROOT, ".github/workflows/release.yml"),
            "utf8"
        );
        const auditStart = workflow.indexOf("- name: Audit packed package contents");
        const auditEnd = workflow.indexOf("- name: Test exact release artifacts", auditStart);
        const audit = workflow.slice(auditStart, auditEnd);
        const parsers = [...audit.matchAll(/node -e '\n([\s\S]*?)\n\s*'/g)].map(
            (match) => match[1] ?? ""
        );
        const manifests = [
            { name: "pdf-rfc3161", version: "0.2.0" },
            {
                name: "pdf-rfc3161-cli",
                version: "0.2.0",
                dependencies: { "pdf-rfc3161": "0.2.0" },
            },
        ];

        expect(parsers).toHaveLength(manifests.length);
        for (const [index, parser] of parsers.entries()) {
            const manifest = manifests[index];
            if (manifest === undefined) throw new Error("Release manifest fixture is required");
            const node = spawnSync(process.execPath, ["-e", parser], {
                input: JSON.stringify(manifest),
                encoding: "utf8",
            });
            expect(node.status).toBe(0);

            const bash = spawnSync(
                "bash",
                ["-euo", "pipefail", "-c", "read -r name version dependency < <(printf %s \"$IDENTITY\")"],
                { env: { ...process.env, IDENTITY: node.stdout }, encoding: "utf8" }
            );
            expect(bash.status).toBe(0);
        }
    });

    it("binds staged releases to the exact audited tarballs", () => {
        const workflow = readFileSync(
            resolve(REPOSITORY_ROOT, ".github/workflows/release.yml"),
            "utf8"
        );
        const contributing = readFileSync(resolve(REPOSITORY_ROOT, "CONTRIBUTING.md"), "utf8");
        const compatibilityJob = workflow.indexOf("  compatibility:");
        const verifyJob = workflow.indexOf("  verify:");
        const pack = workflow.indexOf("- name: Pack public packages");
        const audit = workflow.indexOf("- name: Audit packed package contents");
        const packedConsumer = workflow.indexOf("- name: Test exact release artifacts");
        const checksums = workflow.indexOf("- name: Generate SHA256SUMS and SHA512SUMS");
        const upload = workflow.indexOf("- name: Upload release artifacts");
        const coreJob = workflow.indexOf("  stage-core:");
        const cliJob = workflow.indexOf("  stage-cli:");
        const coreStage = workflow.indexOf(
            "npm stage publish release-artifacts/core/*.tgz --access public"
        );
        const cliStage = workflow.indexOf(
            "npm stage publish release-artifacts/cli/*.tgz --access public"
        );

        expect(compatibilityJob).toBeGreaterThan(-1);
        expect(verifyJob).toBeGreaterThan(compatibilityJob);
        expect(workflow.slice(compatibilityJob, verifyJob)).toContain(
            "node-version: ${{ matrix.node }}"
        );
        expect(workflow.slice(compatibilityJob, verifyJob)).toContain("node: [20, 22, 24]");
        expect(workflow.slice(verifyJob, coreJob)).toContain("needs: compatibility");
        expect(pack).toBeGreaterThan(verifyJob);
        expect(audit).toBeGreaterThan(pack);
        expect(packedConsumer).toBeGreaterThan(audit);
        expect(checksums).toBeGreaterThan(packedConsumer);
        expect(upload).toBeGreaterThan(checksums);
        expect(workflow.slice(packedConsumer, checksums)).toContain(
            'pnpm --filter pdf-rfc3161-tests test:package -- "$GITHUB_WORKSPACE"/release-artifacts/core/*.tgz "$GITHUB_WORKSPACE"/release-artifacts/cli/*.tgz'
        );
        expect(workflow.slice(audit, packedConsumer)).toContain("package/README.md");
        expect(workflow.slice(audit, packedConsumer)).toContain("package/dist/cli.cjs");
        expect(workflow.slice(audit, packedConsumer)).not.toContain("package/dist/cli.js");
        expect(workflow.slice(audit, packedConsumer)).toContain("pdf-rfc3161-cli tarball name");
        expect(workflow.slice(audit, packedConsumer)).toContain(
            "CLI tarball pdf-rfc3161 dependency"
        );
        expect(workflow.slice(checksums, upload)).toContain(
            "sha256sum core/*.tgz cli/*.tgz > SHA256SUMS"
        );
        expect(workflow.slice(checksums, upload)).toContain(
            "sha512sum core/*.tgz cli/*.tgz > SHA512SUMS"
        );

        for (const [job, stage] of [
            [coreJob, coreStage],
            [cliJob, cliStage],
        ]) {
            const jobContent = workflow.slice(job, stage);
            expect(jobContent).toContain("sha256sum --check SHA256SUMS");
            expect(jobContent).toContain("sha512sum --check SHA512SUMS");
        }

        expect(contributing).toContain("SHA-256/SHA-512 digest");
        expect(contributing).toContain("npm stage download <core-stage-id>");
        expect(contributing).toContain("npm stage download <cli-stage-id>");
    });

    it("downloads fixed official snapshot artifacts, verifies them, and extracts without host installation", () => {
        const snapshot = PADES_ORACLE_POLICY.ubuntuSnapshot;
        expect(snapshot).toMatch(/^\d{8}T\d{6}Z$/);

        for (const artifact of PADES_ORACLE_ARTIFACTS) {
            const url = new URL(artifact.url);
            expect(url.protocol).toBe("https:");
            expect(url.hostname).toBe("snapshot.ubuntu.com");
            expect(url.pathname.startsWith(`/ubuntu/${snapshot}/pool/`)).toBe(true);
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

    it("asserts the same local policy before the interoperability harness uses a tool", () => {
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
        expect(documentation).toContain("Node.js 24 with Corepack");
        expect(documentation).toContain("`uv` 0.12.5");
        expect(documentation).toContain("corepack pnpm@10.30.3 install --frozen-lockfile");
        expect(documentation).toContain("uv python install 3.12.14");
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
