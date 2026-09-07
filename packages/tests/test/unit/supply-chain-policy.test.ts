import { readFileSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const TEST_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(TEST_DIRECTORY, "../../../..");
const packageFiles = [
    "package.json",
    "packages/core/package.json",
    "packages/cli/package.json",
    "packages/demo/package.json",
    "packages/tests/package.json",
];
const compatibilityClaimFiles = [
    "packages/core/src/tsa/client.ts",
    "packages/core/src/tsa/request.ts",
    "packages/core/src/pki/default-trust-store.ts",
    "packages/core/src/utils/bounded-fetch.ts",
    "packages/tests/test/setup.ts",
    "README.md",
    "CONTRIBUTING.md",
];
const nonMatrixWorkflowFiles = [
    ".github/workflows/ci.yml",
    ".github/workflows/release.yml",
    ".github/workflows/security.yml",
    ".github/workflows/size.yml",
    ".github/workflows/deploy-demo.yml",
];
const maintainedDocumentationFiles = [
    "README.md",
    "CONTRIBUTING.md",
    "MIGRATION.md",
    "docs/pades-oracle-tools.md",
    "docs/validation-tools.md",
    "docs/manual-acrobat-validation.md",
];
const obsoleteNodeSupportClaim =
    /Node(?:\.js)?[^\n]{0,30}(?:18|20)(?:\+|\.0\.0| or later| or newer| minimum| support)/i;
const immutableActionReference = /^[^\s@]+@[0-9a-f]{40}\s+#\s+.+$/;

function readRepositoryFile(path: string): string {
    return readFileSync(resolve(REPOSITORY_ROOT, path), "utf8");
}

describe("supply-chain runtime policy", () => {
    it("requires supported Node, pnpm, and workflow declarations", () => {
        const manifests = packageFiles.map(
            (path) =>
                JSON.parse(readRepositoryFile(path)) as {
                    devDependencies: Record<string, string>;
                    engines: { node: string };
                    packageManager?: string;
                }
        );
        const ciWorkflow = readRepositoryFile(".github/workflows/ci.yml");
        const releaseWorkflow = readRepositoryFile(".github/workflows/release.yml");

        expect(manifests[0]?.packageManager).toMatch(/^pnpm@\d{1,5}\.\d{1,5}\.\d{1,5}$/);
        const nodeEngine = manifests[0]?.engines.node;
        expect(nodeEngine).toMatch(/^>=22\.\d{1,5}\.\d{1,5}$/);
        expect(manifests.map((manifest) => manifest.engines.node)).toEqual(
            manifests.map(() => nodeEngine)
        );
        expect(readRepositoryFile(".nvmrc").trim()).toBe("26");

        const nativeTypeScript = manifests[0]?.devDependencies["@typescript/native"];
        const typeScriptApiBridge = manifests[0]?.devDependencies.typescript;
        expect(nativeTypeScript?.startsWith("npm:typescript@7.")).toBe(true);
        expect(typeScriptApiBridge?.startsWith("npm:@typescript/typescript6@6.")).toBe(true);

        for (const manifest of manifests.slice(1)) {
            expect(manifest.devDependencies["@typescript/native"]).toBe(nativeTypeScript);
            expect(manifest.devDependencies.typescript).toBe(typeScriptApiBridge);
        }

        for (const workflow of [ciWorkflow, releaseWorkflow]) {
            expect(workflow).toMatch(/node: \[22, 24, 26\]/);
            expect(workflow).not.toContain("node: [20");
        }

        for (const path of nonMatrixWorkflowFiles) {
            expect(readRepositoryFile(path)).not.toMatch(/node-version:\s{1,20}["']?24/);
        }

        for (const workflowFile of readdirSync(resolve(REPOSITORY_ROOT, ".github/workflows"))) {
            if (!workflowFile.endsWith(".yml")) continue;
            expect(readRepositoryFile(`.github/workflows/${workflowFile}`)).not.toMatch(
                /uses:\s{1,100}pnpm\/action-setup@[^\n]{1,100}\n\s{1,100}with:\n\s{1,100}version:/
            );
        }

        for (const path of compatibilityClaimFiles) {
            expect(readRepositoryFile(path)).not.toMatch(obsoleteNodeSupportClaim);
        }
    });

    it("keeps Python, pnpm, and documentation version authorities reproducible", () => {
        const requirementsInput = "packages/tests/python/requirements.in";
        const requirements = readRepositoryFile(requirementsInput);
        const packedConsumer = readRepositoryFile("packages/tests/scripts/test-packed-consumer.ts");
        const rootPackage = JSON.parse(readRepositoryFile("package.json")) as {
            packageManager?: unknown;
        };

        expect(requirements.startsWith("pyHanko==")).toBe(true);
        expect(requirements.endsWith("\n")).toBe(true);
        expect(requirements.trim().split("\n")).toHaveLength(1);
        const pyHankoVersionParts = requirements.trim().slice("pyHanko==".length).split(".");
        expect(pyHankoVersionParts).toHaveLength(3);
        for (const part of pyHankoVersionParts) expect(part).toMatch(/^\d{1,5}$/);
        expect(typeof rootPackage.packageManager).toBe("string");
        const packageManager = String(rootPackage.packageManager);
        expect(packageManager).toMatch(/^pnpm@\d{1,5}\.\d{1,5}\.\d{1,5}$/);
        expect(packedConsumer).toContain(
            'const REPOSITORY_ROOT = resolve(SCRIPT_DIRECTORY, "../../..");'
        );
        expect(packedConsumer).toContain('readFileSync(join(REPOSITORY_ROOT, "package.json"), "utf8")');
        expect(packedConsumer).toContain('packageManager.startsWith("pnpm@")');
        expect(packedConsumer).toContain(
            'const ROOT_PNPM_VERSION = packageManager.slice("pnpm@".length);'
        );
        expect(packedConsumer).toContain("process.env.npm_execpath");
        expect(packedConsumer).toContain("packageManager: packageManager");
        expect(packedConsumer).toContain('["exec", "pdf-rfc3161", "--version"]');
        expect(packedConsumer).toContain("pnpm version must match root packageManager");
        expect(packedConsumer).not.toContain('"pnpm.cmd"');
        expect(packedConsumer).not.toContain('"corepack.cmd"');

        for (const path of maintainedDocumentationFiles) {
            const content = readRepositoryFile(path);
            expect(content).not.toContain("corepack");
        }
        expect(readRepositoryFile("CONTRIBUTING.md")).toContain("root `packageManager`");
    });

    it("keeps CodeQL steps on the same revision and groups their updates", () => {
        const workflow = readRepositoryFile(".github/workflows/security.yml");
        const revisions = Array.from(
            workflow.matchAll(/github\/codeql-action\/(?:init|autobuild|analyze)@([a-f0-9]{40})/g),
            (match) => match[1]
        );
        expect(revisions).toHaveLength(3);
        expect(new Set(revisions).size).toBe(1);
        expect(readRepositoryFile(".github/dependabot.yml")).toContain(
            '      codeql:\n        patterns:\n          - "github/codeql-action/*"'
        );
    });

    it("requires immutable actions, least-privilege defaults, and a blocking dependency audit", () => {
        const workflowDirectory = resolve(REPOSITORY_ROOT, ".github/workflows");
        const workflowFiles = readdirSync(workflowDirectory).filter((path) => path.endsWith(".yml"));
        const workflows = workflowFiles.map((path) => ({
            path,
            content: readFileSync(resolve(workflowDirectory, path), "utf8"),
        }));

        for (const { content } of workflows) {
            const actionReferences = content
                .split("\n")
                .map((line) => line.trim().replace(/^-\s/, ""))
                .flatMap((line) => {
                    const match = /^uses:\s+(.+)$/.exec(line);
                    return match?.[1] === undefined ? [] : [match[1].trim()];
                })
                .filter((reference) => !reference.startsWith("./"));

            for (const reference of actionReferences) {
                expect(reference).toMatch(immutableActionReference);
            }
        }

        for (const path of ["ci.yml", "security.yml", "size.yml"]) {
            const content = workflows.find((workflow) => workflow.path === path)?.content;
            expect(content?.split("\njobs:", 1)[0]).toContain("permissions:\n  contents: read");
        }

        const securityWorkflow = readRepositoryFile(".github/workflows/security.yml");
        const securityWorkflowLines = securityWorkflow.split("\n");
        const auditStepStart = securityWorkflowLines.findIndex(
            (line) => line.trim() === "- name: Run pnpm audit"
        );
        const auditStepEnd = securityWorkflowLines.findIndex(
            (line, index) => index > auditStepStart && line.trimStart().startsWith("- name:")
        );
        const auditStep = securityWorkflowLines
            .slice(auditStepStart, auditStepEnd === -1 ? undefined : auditStepEnd)
            .join("\n");
        const auditCommands = securityWorkflowLines
            .map((line) => line.trim())
            .filter((line) => line.startsWith("run: pnpm audit"));

        expect(auditStep).toContain("run: pnpm audit --audit-level=moderate");
        expect(auditStep).not.toContain("continue-on-error");
        expect(auditCommands).toEqual(["run: pnpm audit --audit-level=moderate"]);
        expect(securityWorkflow).not.toContain("@master");
        expect(readRepositoryFile(".github/workflows/finalize-release.yml")).not.toMatch(
            /node-version:\s{1,20}["']?24/
        );
    });
});
