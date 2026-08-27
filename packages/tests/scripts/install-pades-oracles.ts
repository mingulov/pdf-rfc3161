import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
    appendFileSync,
    createWriteStream,
    mkdirSync,
    mkdtempSync,
    renameSync,
    rmSync,
} from "node:fs";
import { join } from "node:path";
import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import {
    PADES_ORACLE_ARTIFACTS,
    PADES_ORACLE_POLICY,
    activatePadesOracleEnvironment,
    assertPadesOracleTools,
    padesOraclePaths,
    type PadesOracleArtifact,
} from "./pades-oracles.js";

const MAX_ARTIFACT_SIZE = 16 * 1024 * 1024;
const OFFICIAL_UBUNTU_HOSTS = new Set(["snapshot.ubuntu.com"]);

function run(command: string, args: string[]): void {
    const result = spawnSync(command, args, { encoding: "utf8", stdio: "inherit" });
    if (result.error) throw new Error(`${command} could not be started: ${result.error.message}`);
    if (result.status !== 0)
        throw new Error(`${command} exited with status ${String(result.status)}`);
}

function assertOfficialArtifactUrl(artifact: PadesOracleArtifact): void {
    const url = new URL(artifact.url);
    if (url.protocol !== "https:" || !OFFICIAL_UBUNTU_HOSTS.has(url.hostname)) {
        throw new Error(
            `Validation artifact URL is not an official Ubuntu HTTPS URL: ${artifact.url}`
        );
    }
    if (!/^[a-f0-9]{64}$/.test(artifact.sha256)) {
        throw new Error(`Validation artifact SHA-256 is invalid for ${artifact.filename}`);
    }
}

async function downloadVerifiedArtifact(
    artifact: PadesOracleArtifact,
    destination: string
): Promise<void> {
    assertOfficialArtifactUrl(artifact);
    const response = await fetch(artifact.url, {
        redirect: "error",
        signal: AbortSignal.timeout(60_000),
    });
    if (!response.ok || !response.body) {
        throw new Error(
            `Could not download ${artifact.filename}: HTTP ${response.status.toString()}`
        );
    }

    const advertisedLength = response.headers.get("content-length");
    if (advertisedLength !== null && Number(advertisedLength) > MAX_ARTIFACT_SIZE) {
        throw new Error(`Validation artifact is unexpectedly large: ${artifact.filename}`);
    }

    const hash = createHash("sha256");
    let received = 0;
    const sizeAndHash = new Transform({
        transform(chunk: Buffer, _encoding, callback) {
            received += chunk.length;
            if (received > MAX_ARTIFACT_SIZE) {
                callback(
                    new Error(`Validation artifact is unexpectedly large: ${artifact.filename}`)
                );
                return;
            }
            hash.update(chunk);
            callback(null, chunk);
        },
    });
    await pipeline(
        // Node's fetch body is async-iterable at runtime, while its DOM and
        // Node stream declarations differ in the test tsconfig.
        Readable.from(response.body as unknown as AsyncIterable<Uint8Array>),
        sizeAndHash,
        createWriteStream(destination, { flags: "wx", mode: 0o600 })
    );

    const actualSha256 = hash.digest("hex");
    if (actualSha256 !== artifact.sha256) {
        throw new Error(
            `SHA-256 mismatch for ${artifact.filename}: expected ${artifact.sha256}, got ${actualSha256}`
        );
    }
}

function assertArtifactMetadata(artifact: PadesOracleArtifact, artifactPath: string): void {
    const result = spawnSync(
        "dpkg-deb",
        ["--field", artifactPath, "Package", "Version", "Architecture"],
        { encoding: "utf8" }
    );
    if (result.error || result.status !== 0) {
        throw new Error(`Could not inspect ${artifact.filename} Debian package metadata`);
    }
    const metadata = typeof result.stdout === "string" ? result.stdout.trim() : "";
    const expected = [
        `Package: ${artifact.package}`,
        `Version: ${artifact.packageVersion}`,
        `Architecture: ${PADES_ORACLE_POLICY.architecture}`,
    ].join("\n");
    if (metadata !== expected) {
        throw new Error(`Unexpected package metadata for ${artifact.filename}`);
    }
}

function exportGithubActionsEnvironment(): void {
    const paths = padesOraclePaths();
    if (process.env.GITHUB_ENV !== undefined) {
        appendFileSync(
            process.env.GITHUB_ENV,
            `PDF_RFC3161_PADES_ORACLE_HOME=${paths.root}\nLD_LIBRARY_PATH=${paths.library}\n`
        );
    }
    if (process.env.GITHUB_PATH !== undefined) {
        appendFileSync(process.env.GITHUB_PATH, `${paths.bin}\n`);
    }
}

async function main(): Promise<void> {
    if (process.platform !== "linux") {
        throw new Error("Pinned PAdES tool installation requires the Ubuntu 24.04 CI runner");
    }
    if (process.arch !== "x64") {
        throw new Error(
            `Pinned PAdES tool installation requires ${PADES_ORACLE_POLICY.architecture}`
        );
    }

    const paths = padesOraclePaths();
    mkdirSync(paths.artifacts, { recursive: true });
    mkdirSync(paths.rootfs, { recursive: true });
    const downloadDirectory = mkdtempSync(join(paths.root, ".download-"));
    try {
        for (const artifact of PADES_ORACLE_ARTIFACTS) {
            const downloadedPath = join(downloadDirectory, artifact.filename);
            await downloadVerifiedArtifact(artifact, downloadedPath);
            assertArtifactMetadata(artifact, downloadedPath);
            // Atomic replacement only targets this policy-versioned artifact.
            renameSync(downloadedPath, join(paths.artifacts, artifact.filename));
        }

        for (const artifact of PADES_ORACLE_ARTIFACTS) {
            // Extraction never executes package maintainer scripts and never
            // changes the runner's dpkg database or system toolchain.
            run("dpkg-deb", ["--extract", join(paths.artifacts, artifact.filename), paths.rootfs]);
        }
    } finally {
        // This directory is freshly created by mkdtempSync immediately above.
        rmSync(downloadDirectory, { force: true, recursive: true });
    }

    activatePadesOracleEnvironment();
    exportGithubActionsEnvironment();
    assertPadesOracleTools();
}

void main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
});
