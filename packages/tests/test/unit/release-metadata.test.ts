import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const TEST_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(TEST_DIRECTORY, "../../../..");
const RELEASE_METADATA_SCRIPT = resolve(
    REPOSITORY_ROOT,
    "packages/tests/scripts/release-metadata.ts"
);
const FINALIZE_WORKFLOW = resolve(
    REPOSITORY_ROOT,
    ".github/workflows/finalize-release.yml"
);

interface ReleaseMetadataModule {
    assertSuccessfulReleaseRun?: (
        run: unknown,
        options: {
            expectedCommit: string;
            expectedWorkflowId: number;
            version: string;
        }
    ) => void;
    prepareReleaseMetadata(options: {
        changelog: string;
        cliVersion: string;
        coreVersion: string;
        version: string;
    }): {
        notes: string;
        tag: string;
        title: string;
    };
}

async function loadReleaseMetadataModule(): Promise<ReleaseMetadataModule | undefined> {
    expect(existsSync(RELEASE_METADATA_SCRIPT)).toBe(true);
    if (!existsSync(RELEASE_METADATA_SCRIPT)) return undefined;
    return (await import(pathToFileURL(RELEASE_METADATA_SCRIPT).href)) as ReleaseMetadataModule;
}

describe("release finalization metadata", () => {
    it("extracts one finalized version while requiring an empty Unreleased section", async () => {
        const releaseMetadata = await loadReleaseMetadataModule();
        if (releaseMetadata === undefined) return;
        const changelog = [
            "# Changelog",
            "",
            "## [Unreleased]",
            "",
            "## [1.2.3]",
            "",
            "### Added",
            "",
            "- Safer releases.",
            "",
            "## [0.1.4] - 2026-01-14",
            "",
            "- Previous release.",
            "",
        ].join("\n");

        expect(
            releaseMetadata.prepareReleaseMetadata({
                changelog,
                cliVersion: "1.2.3",
                coreVersion: "1.2.3",
                version: "1.2.3",
            })
        ).toEqual({
            notes: [
                "## [1.2.3]",
                "",
                "### Added",
                "",
                "- Safer releases.",
                "",
            ].join("\n"),
            tag: "v1.2.3",
            title: "pdf-rfc3161 v1.2.3",
        });
    });

    it("rejects mismatched manifests and unreleased release notes", async () => {
        const releaseMetadata = await loadReleaseMetadataModule();
        if (releaseMetadata === undefined) return;
        const finalized = "## [Unreleased]\n\n## [0.2.0] - 2026-08-28\n\n- Ready.\n";
        const stillUnreleased =
            "## [Unreleased]\n\n- Not finalized.\n\n## [0.2.0] - 2026-08-28\n\n- Ready.\n";

        expect(() =>
            releaseMetadata.prepareReleaseMetadata({
                changelog: finalized,
                cliVersion: "0.2.0",
                coreVersion: "0.1.4",
                version: "0.2.0",
            })
        ).toThrow(/Package versions must both equal 0\.2\.0/);
        expect(() =>
            releaseMetadata.prepareReleaseMetadata({
                changelog: stillUnreleased,
                cliVersion: "0.2.0",
                coreVersion: "0.2.0",
                version: "0.2.0",
            })
        ).toThrow(/Unreleased section must be empty/);
    });

    it("requires the exact main-branch workflow and both successful staging jobs", async () => {
        const releaseMetadata = await loadReleaseMetadataModule();
        if (releaseMetadata === undefined) return;
        expect(typeof releaseMetadata.assertSuccessfulReleaseRun).toBe("function");
        if (releaseMetadata.assertSuccessfulReleaseRun === undefined) return;
        const run = {
            conclusion: "success",
            event: "workflow_dispatch",
            headBranch: "main",
            headSha: "abc123",
            jobs: [
                { conclusion: "success", name: "Stage pdf-rfc3161@1.2.3 on npm" },
                { conclusion: "success", name: "Stage pdf-rfc3161-cli@1.2.3 on npm" },
            ],
            workflowDatabaseId: 42,
        };
        const options = {
            expectedCommit: "abc123",
            expectedWorkflowId: 42,
            version: "1.2.3",
        };

        expect(() => releaseMetadata.assertSuccessfulReleaseRun?.(run, options)).not.toThrow();
        expect(() =>
            releaseMetadata.assertSuccessfulReleaseRun?.(
                { ...run, headBranch: "release-test" },
                options
            )
        ).toThrow(/main branch/);
        expect(() =>
            releaseMetadata.assertSuccessfulReleaseRun?.(
                { ...run, workflowDatabaseId: 41 },
                options
            )
        ).toThrow(/workflow ID/);
        expect(() =>
            releaseMetadata.assertSuccessfulReleaseRun?.(
                {
                    ...run,
                    jobs: [
                        run.jobs[0],
                        { conclusion: "skipped", name: "Stage pdf-rfc3161-cli@1.2.3 on npm" },
                    ],
                },
                options
            )
        ).toThrow(/Both npm staging jobs must succeed/);
    });

    it("uses a manual finalizer that cannot publish or approve npm packages", () => {
        expect(existsSync(FINALIZE_WORKFLOW)).toBe(true);
        if (!existsSync(FINALIZE_WORKFLOW)) return;
        const workflow = readFileSync(FINALIZE_WORKFLOW, "utf8");

        expect(workflow).toContain("workflow_dispatch:");
        expect(workflow).toContain("release_run_id:");
        expect(workflow).toContain("actions: read");
        expect(workflow).toContain("contents: write");
        expect(workflow.match(/contents: write/g)).toHaveLength(1);
        expect(workflow).toContain("persist-credentials: false");
        expect(workflow).toContain("Require main branch");
        expect(workflow).toContain("workflowDatabaseId");
        expect(workflow).toContain("Verify successful staging run");
        expect(workflow).toContain("Verify packages are public on npm");
        expect(workflow).toContain("Create GitHub release and tag");
        expect(workflow).not.toContain("id-token: write");
        expect(workflow).not.toContain("pnpm install");
        expect(workflow).not.toContain("npm stage approve");
        expect(workflow).not.toContain("npm publish");
    });
});
