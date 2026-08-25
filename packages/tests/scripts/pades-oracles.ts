import { spawnSync } from "node:child_process";
import { timingSafeEqual } from "node:crypto";
import { dirname, join, delimiter } from "node:path";
import { fileURLToPath } from "node:url";

export interface PadesOracleArtifact {
    package: string;
    packageVersion: string;
    filename: string;
    url: string;
    sha256: string;
}

/**
 * Pinned external-tool policy for the offline PAdES interoperability gate.
 * Values are Ubuntu Noble package revisions and SHA-256-pinned binary
 * artifacts, not merely upstream banners.
 */
export const PADES_ORACLE_POLICY = {
    ubuntuRunner: "ubuntu-24.04",
    architecture: "amd64",
    pythonVersion: "3.12.14",
    qpdf: {
        package: "qpdf",
        packageVersion: "11.9.0-1.1ubuntu0.1",
        commandVersion: "11.9.0",
        artifact: {
            package: "qpdf",
            packageVersion: "11.9.0-1.1ubuntu0.1",
            filename: "qpdf_11.9.0-1.1ubuntu0.1_amd64.deb",
            url: "https://archive.ubuntu.com/ubuntu/pool/universe/q/qpdf/qpdf_11.9.0-1.1ubuntu0.1_amd64.deb",
            sha256: "b50d1aca530cd8f7b68214f8b19bdf348c6c01b7110ca1c335e6662cdb442af8",
        },
    },
    qpdfRuntime: {
        package: "libqpdf29t64",
        packageVersion: "11.9.0-1.1ubuntu0.1",
        artifact: {
            package: "libqpdf29t64",
            packageVersion: "11.9.0-1.1ubuntu0.1",
            filename: "libqpdf29t64_11.9.0-1.1ubuntu0.1_amd64.deb",
            url: "https://archive.ubuntu.com/ubuntu/pool/main/q/qpdf/libqpdf29t64_11.9.0-1.1ubuntu0.1_amd64.deb",
            sha256: "8ffa418e72ab62013d7bd97b737f6eac8311853e50e4972b3db414c6fdbab445",
        },
    },
    openssl: {
        package: "openssl",
        packageVersion: "3.0.13-0ubuntu3.12",
        commandVersion: "3.0.13",
        artifact: {
            package: "openssl",
            packageVersion: "3.0.13-0ubuntu3.12",
            filename: "openssl_3.0.13-0ubuntu3.12_amd64.deb",
            url: "https://security.ubuntu.com/ubuntu/pool/main/o/openssl/openssl_3.0.13-0ubuntu3.12_amd64.deb",
            sha256: "321b30ad5a1c3783cb3d73ae439f824f6d3874d76a93a62f4a984959b490aa7b",
        },
    },
    opensslRuntime: {
        package: "libssl3t64",
        packageVersion: "3.0.13-0ubuntu3.12",
        artifact: {
            package: "libssl3t64",
            packageVersion: "3.0.13-0ubuntu3.12",
            filename: "libssl3t64_3.0.13-0ubuntu3.12_amd64.deb",
            url: "https://security.ubuntu.com/ubuntu/pool/main/o/openssl/libssl3t64_3.0.13-0ubuntu3.12_amd64.deb",
            sha256: "6a963adb1106fca567d24d4a1e5da0bad25de79ac2564cd1ba846e677e1c951b",
        },
    },
} as const;

/** Extract runtime dependencies before their command-line consumers. */
export const PADES_ORACLE_ARTIFACTS: readonly PadesOracleArtifact[] = [
    PADES_ORACLE_POLICY.qpdfRuntime.artifact,
    PADES_ORACLE_POLICY.qpdf.artifact,
    PADES_ORACLE_POLICY.opensslRuntime.artifact,
    PADES_ORACLE_POLICY.openssl.artifact,
];

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const ORACLE_POLICY_DIRECTORY = [
    PADES_ORACLE_POLICY.architecture,
    `qpdf-${PADES_ORACLE_POLICY.qpdf.packageVersion}`,
    `openssl-${PADES_ORACLE_POLICY.openssl.packageVersion}`,
].join("-");

export interface PadesOraclePaths {
    root: string;
    artifacts: string;
    rootfs: string;
    bin: string;
    library: string;
}

/**
 * A policy-versioned local extraction directory. It is deliberately inside
 * the test package rather than the runner's package database, so no CI job
 * modifies the host OpenSSL or qpdf installation.
 */
export function padesOraclePaths(): PadesOraclePaths {
    const root = join(SCRIPT_DIRECTORY, "..", ".pades-oracles", ORACLE_POLICY_DIRECTORY);
    const rootfs = join(root, "rootfs");
    return {
        root,
        artifacts: join(root, "artifacts"),
        rootfs,
        bin: join(rootfs, "usr", "bin"),
        library: join(rootfs, "usr", "lib", "x86_64-linux-gnu"),
    };
}

/** Makes command execution prefer the isolated, hash-verified tools. */
export function padesOracleEnvironment(
    environment: NodeJS.ProcessEnv = process.env
): NodeJS.ProcessEnv {
    const paths = padesOraclePaths();
    return {
        ...environment,
        PDF_RFC3161_PADES_ORACLE_HOME: paths.root,
        PATH: [paths.bin, environment.PATH].filter((value) => value !== undefined).join(delimiter),
        // System default directories remain available after this search path.
        LD_LIBRARY_PATH: paths.library,
    };
}

/** Activates the isolated tools for helpers that spawn commands directly. */
export function activatePadesOracleEnvironment(): PadesOraclePaths {
    const paths = padesOraclePaths();
    const environment = padesOracleEnvironment();
    process.env.PDF_RFC3161_PADES_ORACLE_HOME = paths.root;
    process.env.PATH = environment.PATH;
    process.env.LD_LIBRARY_PATH = environment.LD_LIBRARY_PATH;
    return paths;
}

export interface OracleCommandResult {
    status: number | null;
    stdout: string;
    stderr: string;
    error?: Error;
}

export type OracleCommandRunner = (command: string, args: string[]) => OracleCommandResult;

function runOracleCommand(command: string, args: string[]): OracleCommandResult {
    const result = spawnSync(command, args, {
        encoding: "utf8",
        env: padesOracleEnvironment(),
    });
    return {
        status: result.status,
        stdout: typeof result.stdout === "string" ? result.stdout : "",
        stderr: typeof result.stderr === "string" ? result.stderr : "",
        ...(result.error instanceof Error ? { error: result.error } : {}),
    };
}

function output(result: OracleCommandResult): string {
    return [result.stdout, result.stderr].filter((value) => value.length > 0).join("\n").trim();
}

function assertSuccess(
    runner: OracleCommandRunner,
    command: string,
    args: string[],
    description: string
): OracleCommandResult {
    const result = runner(command, args);
    if (result.error) {
        throw new Error(`${description} could not be started: ${result.error.message}`);
    }
    if (result.status !== 0) {
        throw new Error(`${description} failed: ${output(result)}`);
    }
    return result;
}

function artifactPath(artifact: PadesOracleArtifact): string {
    return join(padesOraclePaths().artifacts, artifact.filename);
}

function checksumsMatch(actual: string | undefined, expected: string): boolean {
    if (actual?.length !== expected.length) return false;
    return timingSafeEqual(Buffer.from(actual, "ascii"), Buffer.from(expected, "ascii"));
}

function assertArtifactIntegrity(runner: OracleCommandRunner, artifact: PadesOracleArtifact): void {
    const path = artifactPath(artifact);
    const hash = assertSuccess(runner, "sha256sum", [path], `SHA-256 check for ${artifact.package}`)
        .stdout.trim()
        .split(" ")[0];
    if (!checksumsMatch(hash, artifact.sha256)) {
        throw new Error(
            `Pinned ${artifact.package} artifact SHA-256 mismatch: expected ${artifact.sha256}, got ${hash ?? "none"}`
        );
    }

    const metadata = assertSuccess(
        runner,
        "dpkg-deb",
        ["--field", path, "Package", "Version", "Architecture"],
        `package metadata for ${artifact.package}`
    ).stdout.trim();
    const expectedMetadata = [
        `Package: ${artifact.package}`,
        `Version: ${artifact.packageVersion}`,
        `Architecture: ${PADES_ORACLE_POLICY.architecture}`,
    ].join("\n");
    if (metadata !== expectedMetadata) {
        throw new Error(
            `Pinned ${artifact.package} package metadata mismatch: expected ${expectedMetadata}, got ${metadata || "none"}`
        );
    }
}

function assertLinkedLibrary(
    runner: OracleCommandRunner,
    binary: string,
    libraryFilename: string
): void {
    const paths = padesOraclePaths();
    const expectedLibrary = join(paths.library, libraryFilename);
    const linkage = assertSuccess(runner, "ldd", [binary], `dynamic linker check for ${binary}`);
    if (!linkage.stdout.includes(`=> ${expectedLibrary} `)) {
        throw new Error(
            `Pinned validation binary ${binary} is not linked to ${expectedLibrary}: ${output(linkage)}`
        );
    }
}

/**
 * Verifies every retained artifact's hash and Debian metadata, the local
 * dynamic-library resolution, and executable banners before an external PDF
 * or RFC 3161 validator is used. Keep this at the start of every interoperability run
 * so a runner-image update cannot silently alter results.
 */
export function assertPadesOracleTools(runner: OracleCommandRunner = runOracleCommand): void {
    for (const artifact of PADES_ORACLE_ARTIFACTS) {
        assertArtifactIntegrity(runner, artifact);
    }

    const paths = padesOraclePaths();
    assertLinkedLibrary(runner, join(paths.bin, "qpdf"), "libqpdf.so.29");
    assertLinkedLibrary(runner, join(paths.bin, "openssl"), "libssl.so.3");
    assertLinkedLibrary(runner, join(paths.bin, "openssl"), "libcrypto.so.3");

    const qpdf = assertSuccess(runner, "qpdf", ["--version"], "qpdf");
    const expectedQpdf = `qpdf version ${PADES_ORACLE_POLICY.qpdf.commandVersion}`;
    const qpdfBanner = qpdf.stdout.trim().split("\n")[0];
    if (qpdfBanner !== expectedQpdf) {
        throw new Error(`Pinned qpdf banner mismatch: expected ${expectedQpdf}, got ${output(qpdf)}`);
    }

    const openssl = assertSuccess(runner, "openssl", ["version"], "OpenSSL");
    const expectedOpenSslPrefix = `OpenSSL ${PADES_ORACLE_POLICY.openssl.commandVersion} `;
    if (!openssl.stdout.trim().startsWith(expectedOpenSslPrefix)) {
        throw new Error(
            `Pinned OpenSSL banner mismatch: expected prefix ${expectedOpenSslPrefix}, got ${output(openssl)}`
        );
    }
}
