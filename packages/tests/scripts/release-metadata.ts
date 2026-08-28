import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(SCRIPT_DIRECTORY, "../../..");
const STABLE_VERSION = /^(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})$/;

export interface ReleaseMetadataOptions {
    changelog: string;
    cliVersion: string;
    coreVersion: string;
    version: string;
}

export interface ReleaseMetadata {
    notes: string;
    tag: string;
    title: string;
}

interface ReleaseRunJob {
    conclusion?: unknown;
    name?: unknown;
}

interface ReleaseRun {
    conclusion?: unknown;
    event?: unknown;
    headBranch?: unknown;
    headSha?: unknown;
    jobs?: unknown;
    workflowDatabaseId?: unknown;
}

export interface SuccessfulReleaseRunOptions {
    expectedCommit: string;
    expectedWorkflowId: number;
    version: string;
}

function releaseSectionStart(lines: string[], version: string): number {
    const heading = "## [" + version + "]";
    return lines.findIndex((line) => line === heading || line.startsWith(heading + " - "));
}

export function prepareReleaseMetadata(options: ReleaseMetadataOptions): ReleaseMetadata {
    const { changelog, cliVersion, coreVersion, version } = options;
    if (!STABLE_VERSION.test(version)) {
        throw new Error("Release version must be a stable semantic version, received " + version);
    }
    if (coreVersion !== version || cliVersion !== version) {
        throw new Error(
            "Package versions must both equal " +
                version +
                ": core=" +
                coreVersion +
                " cli=" +
                cliVersion
        );
    }

    const lines = changelog.split("\n");
    const unreleasedStart = lines.indexOf("## [Unreleased]");
    const releaseStart = releaseSectionStart(lines, version);
    if (unreleasedStart === -1) {
        throw new Error("CHANGELOG.md must contain an Unreleased section");
    }
    if (releaseStart === -1) {
        throw new Error("CHANGELOG.md has no " + version + " release section");
    }
    if (unreleasedStart >= releaseStart) {
        throw new Error("Unreleased section must precede the finalized release");
    }
    if (lines.slice(unreleasedStart + 1, releaseStart).some((line) => line.trim().length > 0)) {
        throw new Error("Unreleased section must be empty before finalizing a release");
    }

    const nextRelease = lines.findIndex(
        (line, index) => index > releaseStart && line.startsWith("## [")
    );
    const releaseLines = lines.slice(
        releaseStart,
        nextRelease === -1 ? lines.length : nextRelease
    );
    while (releaseLines.at(-1)?.trim() === "") releaseLines.pop();
    if (releaseLines.length < 2) {
        throw new Error("CHANGELOG.md " + version + " release section has no notes");
    }

    return {
        notes: releaseLines.join("\n") + "\n",
        tag: "v" + version,
        title: "pdf-rfc3161 v" + version,
    };
}

export function assertSuccessfulReleaseRun(
    value: unknown,
    options: SuccessfulReleaseRunOptions
): void {
    if (typeof value !== "object" || value === null) {
        throw new Error("Release run response must be an object");
    }
    const run = value as ReleaseRun;
    if (run.headBranch !== "main") {
        throw new Error("Release run must target the main branch");
    }
    if (run.headSha !== options.expectedCommit) {
        throw new Error(
            "Release run commit " +
                String(run.headSha) +
                " does not match finalizer commit " +
                options.expectedCommit
        );
    }
    if (run.workflowDatabaseId !== options.expectedWorkflowId) {
        throw new Error(
            "Release run workflow ID " +
                String(run.workflowDatabaseId) +
                " does not match release.yml workflow ID " +
                String(options.expectedWorkflowId)
        );
    }
    if (run.conclusion !== "success" || run.event !== "workflow_dispatch") {
        throw new Error("Release run must be a successful manual workflow dispatch");
    }
    if (!Array.isArray(run.jobs)) {
        throw new Error("Release run response must include jobs");
    }
    const jobs = run.jobs as ReleaseRunJob[];
    const requiredJobs = [
        "Stage pdf-rfc3161@" + options.version + " on npm",
        "Stage pdf-rfc3161-cli@" + options.version + " on npm",
    ];
    if (
        requiredJobs.some(
            (requiredName) =>
                !jobs.some(
                    (job) => job.name === requiredName && job.conclusion === "success"
                )
        )
    ) {
        throw new Error("Both npm staging jobs must succeed for the requested version");
    }
}

function readPackageVersion(relativePath: string): string {
    const manifest = JSON.parse(
        readFileSync(resolve(REPOSITORY_ROOT, relativePath), "utf8")
    ) as { version?: unknown };
    if (typeof manifest.version !== "string") {
        throw new Error(relativePath + " has no string version");
    }
    return manifest.version;
}

function main(): void {
    const [command, ...args] = process.argv.slice(2);
    if (command === "verify-run") {
        const [version, expectedCommit, expectedWorkflowIdText] = args;
        const expectedWorkflowId = Number(expectedWorkflowIdText);
        if (
            version === undefined ||
            expectedCommit === undefined ||
            !Number.isSafeInteger(expectedWorkflowId)
        ) {
            throw new Error(
                "Usage: release-metadata.ts verify-run <version> <commit> <workflow-id>"
            );
        }
        assertSuccessfulReleaseRun(JSON.parse(readFileSync(0, "utf8")) as unknown, {
            expectedCommit,
            expectedWorkflowId,
            version,
        });
        process.stdout.write("Release staging run verified\n");
        return;
    }
    if (command !== "prepare") {
        throw new Error(
            "Usage: release-metadata.ts prepare <version> <release-notes-path>"
        );
    }
    const [version, outputPath] = args;
    if (version === undefined || outputPath === undefined) {
        throw new Error(
            "Usage: release-metadata.ts prepare <version> <release-notes-path>"
        );
    }
    const metadata = prepareReleaseMetadata({
        changelog: readFileSync(resolve(REPOSITORY_ROOT, "CHANGELOG.md"), "utf8"),
        cliVersion: readPackageVersion("packages/cli/package.json"),
        coreVersion: readPackageVersion("packages/core/package.json"),
        version,
    });
    writeFileSync(outputPath, metadata.notes);
    process.stdout.write("Prepared release metadata for " + metadata.tag + "\n");
}

const entryPoint = process.argv[1];
if (
    entryPoint !== undefined &&
    import.meta.url === pathToFileURL(resolve(entryPoint)).href
) {
    main();
}
