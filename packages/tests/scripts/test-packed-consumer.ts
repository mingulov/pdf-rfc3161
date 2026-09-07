// Packs the public packages, installs them into a throwaway consumer, and
// checks the published contract end to end: tarball contents, ESM/CJS/type
// resolution, a browser bundle, the CLI binary, and one real timestamping call.
//
// External tools:
//   - pnpm, tar, tsc, vite  -- required everywhere.
//   - OpenSSL WITH the `ts` subcommand -- required for the timestamp-behavior
//     check only. Stock macOS ships LibreSSL, which has no `ts` app, so that
//     one check is skipped (loudly) on such machines while every
//     openssl-independent check still runs. Under CI it stays a hard
//     requirement: every CI job runs on ubuntu-24.04 with full OpenSSL, so a
//     missing `ts` there means a broken runner, not an unsupported laptop.
import assert from "node:assert/strict";
import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import {
    existsSync,
    mkdtempSync,
    mkdirSync,
    readFileSync,
    readdirSync,
    realpathSync,
    rmSync,
    writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { basename, dirname, extname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { PDFDocument } from "pdf-lib-incremental-save";
import { lastXrefFormat, xrefSections } from "../test/utils/xref-format";
import { createLocalTsa } from "./local-tsa-fixture";
import { writeConsumerWorkspace } from "./packed-consumer-config";

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(SCRIPT_DIRECTORY, "../../..");
const CORE_DIRECTORY = resolve(SCRIPT_DIRECTORY, "../../core");
const CLI_DIRECTORY = resolve(SCRIPT_DIRECTORY, "../../cli");
const rootPackage = JSON.parse(
    readFileSync(join(REPOSITORY_ROOT, "package.json"), "utf8")
) as { packageManager?: unknown };
const packageManager = rootPackage.packageManager;
if (typeof packageManager !== "string" || !packageManager.startsWith("pnpm@")) {
    throw new Error("root package.json packageManager must be a pnpm version");
}
const ROOT_PNPM_VERSION = packageManager.slice("pnpm@".length);
function requirePnpmEntrypoint(): string {
    const entrypoint = process.env.npm_execpath;
    if (!entrypoint) throw new Error("Run this check through pnpm run test:package");
    return entrypoint;
}
const PNPM_ENTRYPOINT = requirePnpmEntrypoint();
const CORE_EXPORTS = [
    ["pdf-rfc3161", "timestampPdf"],
    ["pdf-rfc3161/advanced", "ValidationSession"],
    ["pdf-rfc3161/internals", "addVRIForSignature"],
    ["pdf-rfc3161/rfcs/rfc5544", "createTimeStampedData"],
    ["pdf-rfc3161/rfcs/rfc8933", "validateRFC8933Compliance"],
] as const;

interface CommandResult {
    command: string;
    args: string[];
    result: SpawnSyncReturns<string>;
}

interface PackedArtifacts {
    coreTarballPath: string;
    cliTarballPath: string;
}

interface PackageManifest {
    bin?: unknown;
    dependencies?: Record<string, string>;
    exports?: unknown;
    version?: unknown;
}

function commandOutput(result: SpawnSyncReturns<string>): string {
    return [result.stdout, result.stderr]
        .filter((value): value is string => typeof value === "string" && value.length > 0)
        .join("\n");
}

const RUNNING_IN_CI = (process.env.CI ?? "") !== "";

/**
 * Whether this machine's `openssl` has the `ts` application. LibreSSL (the
 * stock macOS build) does not: it exits nonzero with "'ts' is an invalid
 * command". OpenSSL prints the usage summary and exits 0, so the exit status is
 * the primary signal; the usage text is accepted as well because a few older
 * OpenSSL builds print help and still exit nonzero.
 */
function opensslTimestampAvailable(): boolean {
    const probe = spawnSync("openssl", ["ts", "-help"], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
    });
    if (probe.error) return false;
    return probe.status === 0 || commandOutput(probe).includes("-queryfile");
}

function run(command: string, args: string[], cwd: string, env?: NodeJS.ProcessEnv): CommandResult {
    const result = spawnSync(command, args, {
        cwd,
        env,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
    });
    if (result.error) {
        throw new Error(command + " could not start: " + result.error.message);
    }
    return { command, args, result };
}

function runPnpm(
    args: string[],
    cwd: string,
    env?: NodeJS.ProcessEnv
): CommandResult {
    const extension = extname(PNPM_ENTRYPOINT).toLowerCase();
    return [".js", ".cjs", ".mjs"].includes(extension)
        ? run(process.execPath, [PNPM_ENTRYPOINT, ...args], cwd, env)
        : run(PNPM_ENTRYPOINT, args, cwd, env);
}

function commandSucceeded(commandResult: CommandResult): void {
    const output = commandOutput(commandResult.result);
    assert.equal(
        commandResult.result.status,
        0,
        commandResult.command +
            " " +
            commandResult.args.join(" ") +
            " failed" +
            (output ? ":\n" + output : "")
    );
}

function packPackage(packageDirectory: string, packRoot: string): string {
    const destination = join(packRoot, basename(packageDirectory));
    mkdirSync(destination, { recursive: true });
    commandSucceeded(runPnpm(["pack", "--pack-destination", destination], packageDirectory));
    const tarballs = readdirSync(destination).filter((file) => file.endsWith(".tgz"));
    assert.equal(tarballs.length, 1, "expected one tarball for " + packageDirectory);
    const tarballPath = join(destination, tarballs[0] ?? "");
    assert(existsSync(tarballPath), "tarball does not exist: " + tarballPath);
    return tarballPath;
}

function packedArtifacts(temporaryDirectory: string): PackedArtifacts {
    const supplied = process.argv.slice(2).filter((argument) => argument !== "--");
    assert(
        supplied.length === 0 || supplied.length === 2,
        "test:package accepts either no tarballs or exact core and CLI tarball paths"
    );
    if (supplied.length === 2) {
        const coreTarballPath = resolve(supplied[0] ?? "");
        const cliTarballPath = resolve(supplied[1] ?? "");
        assert(existsSync(coreTarballPath), "core tarball does not exist: " + coreTarballPath);
        assert(existsSync(cliTarballPath), "CLI tarball does not exist: " + cliTarballPath);
        return { coreTarballPath, cliTarballPath };
    }
    const packRoot = join(temporaryDirectory, "pack");
    return {
        coreTarballPath: packPackage(CORE_DIRECTORY, packRoot),
        cliTarballPath: packPackage(CLI_DIRECTORY, packRoot),
    };
}

function tarballFiles(tarballPath: string): string[] {
    const result = run("tar", ["-tzf", tarballPath], dirname(tarballPath));
    commandSucceeded(result);
    return commandOutput(result.result)
        .split("\n")
        .map((file) => file.trim())
        .filter((file) => file.startsWith("package/") && !file.endsWith("/"))
        .map((file) => file.slice("package/".length))
        .sort();
}

function manifest(packageDirectory: string): PackageManifest {
    return JSON.parse(
        readFileSync(join(packageDirectory, "package.json"), "utf8")
    ) as PackageManifest;
}

function manifestVersion(packageDirectory: string): string {
    const version = manifest(packageDirectory).version;
    if (typeof version !== "string" || version.length === 0) {
        throw new Error(join(packageDirectory, "package.json") + " has no string version");
    }
    return version;
}

function declaredExportFiles(value: unknown, files: Set<string>): void {
    if (typeof value === "string") {
        files.add(value.replace(/^\.\//, ""));
    } else if (typeof value === "object" && value !== null) {
        for (const child of Object.values(value)) {
            declaredExportFiles(child, files);
        }
    }
}

function packageContract(artifacts: PackedArtifacts): string[] {
    const failures: string[] = [];
    const coreFiles = tarballFiles(artifacts.coreTarballPath);
    for (const requiredFile of ["README.md", "LICENSE", "package.json"]) {
        if (!coreFiles.includes(requiredFile)) {
            failures.push("core tarball is missing " + requiredFile);
        }
    }
    if (coreFiles.some((file) => file.endsWith(".map"))) {
        failures.push("core tarball contains a source map");
    }

    const cliFiles = tarballFiles(artifacts.cliTarballPath);
    const expectedCliFiles = ["LICENSE", "README.md", "dist/cli.cjs", "package.json"];
    if (JSON.stringify(cliFiles) !== JSON.stringify(expectedCliFiles)) {
        failures.push(
            "CLI tarball files must be " +
                JSON.stringify(expectedCliFiles) +
                ", received " +
                JSON.stringify(cliFiles)
        );
    }
    return failures;
}

function writeConsumerPackage(consumerDirectory: string, artifacts: PackedArtifacts): void {
    writeFileSync(
        join(consumerDirectory, "package.json"),
        JSON.stringify(
            {
                name: "pdf-rfc3161-packed-consumer",
                private: true,
                type: "module",
                packageManager: packageManager,
                dependencies: {
                    "pdf-rfc3161": "file:" + artifacts.coreTarballPath,
                    "pdf-rfc3161-cli": "file:" + artifacts.cliTarballPath,
                },
                devDependencies: {
                    "@types/node": "25.9.1",
                    typescript: "5.9.3",
                    vite: "8.2.2",
                },
            },
            null,
            4
        ) + "\n",
        "utf8"
    );
}

function writeChecks(consumerDirectory: string): { cjsPath: string; esmPath: string } {
    const esmPath = join(consumerDirectory, "check-esm.mjs");
    writeFileSync(
        esmPath,
        [
            'import { createRequire } from "node:module";',
            'import { realpathSync } from "node:fs";',
            'import { isAbsolute, relative, sep } from "node:path";',
            'import { fileURLToPath } from "node:url";',
            "",
            "const require = createRequire(import.meta.url);",
            "const consumerRoot = realpathSync(process.env.CONSUMER_ROOT);",
            "const assertResolvedInsideConsumer = (path) => {",
            "    const relativePath = relative(consumerRoot, realpathSync(path));",
            '    if (isAbsolute(relativePath) || relativePath === ".." || relativePath.startsWith(".." + sep)) {',
            '        throw new Error("resolved module is outside temporary consumer: " + path);',
            "    }",
            "};",
            "for (const [specifier, exportName] of " + JSON.stringify(CORE_EXPORTS) + ") {",
            "    const exported = await import(specifier);",
            '    if (typeof exported[exportName] !== "function") throw new Error("missing ESM export " + exportName);',
            "    assertResolvedInsideConsumer(fileURLToPath(import.meta.resolve(specifier)));",
            "    assertResolvedInsideConsumer(require.resolve(specifier));",
            "}",
        ].join("\n"),
        "utf8"
    );

    const cjsPath = join(consumerDirectory, "check-cjs.cjs");
    writeFileSync(
        cjsPath,
        [
            'const { realpathSync } = require("node:fs");',
            'const { isAbsolute, relative, sep } = require("node:path");',
            "const consumerRoot = realpathSync(process.env.CONSUMER_ROOT);",
            "const assertResolvedInsideConsumer = (path) => {",
            "    const relativePath = relative(consumerRoot, realpathSync(path));",
            '    if (isAbsolute(relativePath) || relativePath === ".." || relativePath.startsWith(".." + sep)) {',
            '        throw new Error("resolved module is outside temporary consumer: " + path);',
            "    }",
            "};",
            "for (const [specifier, exportName] of " + JSON.stringify(CORE_EXPORTS) + ") {",
            "    const exported = require(specifier);",
            '    if (typeof exported[exportName] !== "function") throw new Error("missing CJS export " + exportName);',
            "    assertResolvedInsideConsumer(require.resolve(specifier));",
            "}",
        ].join("\n"),
        "utf8"
    );
    return { cjsPath, esmPath };
}

function writeTypeChecks(consumerDirectory: string): { ctsPath: string; mtsPath: string } {
    const mtsPath = join(consumerDirectory, "check-types.mts");
    writeFileSync(
        mtsPath,
        [
            'import { timestampPdf } from "pdf-rfc3161";',
            'import { ValidationSession } from "pdf-rfc3161/advanced";',
            'import { addVRIForSignature } from "pdf-rfc3161/internals";',
            'import { createTimeStampedData } from "pdf-rfc3161/rfcs/rfc5544";',
            'import { validateRFC8933Compliance } from "pdf-rfc3161/rfcs/rfc8933";',
            "void [timestampPdf, ValidationSession, addVRIForSignature, createTimeStampedData, validateRFC8933Compliance];",
            "",
        ].join("\n"),
        "utf8"
    );
    const ctsPath = join(consumerDirectory, "check-types.cts");
    writeFileSync(
        ctsPath,
        [
            'import core = require("pdf-rfc3161");',
            'import advanced = require("pdf-rfc3161/advanced");',
            'import internals = require("pdf-rfc3161/internals");',
            'import rfc5544 = require("pdf-rfc3161/rfcs/rfc5544");',
            'import rfc8933 = require("pdf-rfc3161/rfcs/rfc8933");',
            "void [core.timestampPdf, advanced.ValidationSession, internals.addVRIForSignature, rfc5544.createTimeStampedData, rfc8933.validateRFC8933Compliance];",
            "",
        ].join("\n"),
        "utf8"
    );
    return { ctsPath, mtsPath };
}

function writeViteEntry(consumerDirectory: string): string {
    const sourceDirectory = join(consumerDirectory, "src");
    const entryPath = join(sourceDirectory, "main.js");
    mkdirSync(sourceDirectory, { recursive: true });
    writeFileSync(
        join(consumerDirectory, "index.html"),
        '<!doctype html>\n<html><body><script type="module" src="/src/main.js"></script></body></html>\n',
        "utf8"
    );
    writeFileSync(
        entryPath,
        'import { preparePdfForTimestamp } from "pdf-rfc3161/internals";\n' +
            'if (typeof preparePdfForTimestamp !== "function") throw new Error("missing browser export");\n',
        "utf8"
    );
    return entryPath;
}

/**
 * Builds the smallest PDF that pdf-lib writes with a cross-reference stream
 * (its default). Timestamping such a file is the packaging-sensitive path: the
 * signature dictionary must stay out of object streams for the raw
 * /ByteRange//Contents placeholder bytes to keep physical file offsets, and
 * that must hold for the published tarball, whose pdf-lib-incremental-save
 * copy is installed straight from the registry.
 */
async function writeXrefStreamInput(consumerDirectory: string): Promise<string> {
    const document = await PDFDocument.create();
    document.addPage([200, 200]);
    const inputPath = join(consumerDirectory, "xref-stream-input.pdf");
    writeFileSync(inputPath, await document.save({ useObjectStreams: true }));
    return inputPath;
}

/**
 * Serializes one of the shared cross-reference helpers into the generated
 * check script. The generated file cannot import from this repository -- it
 * runs inside the temporary consumer, whose only dependency is the packed
 * tarball -- so the classifier is emitted from its single source of truth in
 * `test/utils/xref-format.ts` rather than hand-copied into a string literal
 * that can drift away from the suites that assert the same property.
 *
 * Both helpers are transpiled to plain function declarations, and
 * `lastXrefFormat` calls `xrefSections` by name, so emitting both in order
 * reproduces the module scope they rely on. The name check makes a transpiler
 * that ever wraps or renames them fail here, with an explanation, rather than
 * inside the generated script.
 */
function emitFunction(fn: (bytes: Uint8Array) => unknown, name: string): string {
    const source = String(fn);
    assert(
        source.startsWith("function " + name + "("),
        "expected " + name + " to transpile to a plain function declaration, got: " + source
    );
    return source;
}

/**
 * Writes the consumer-side timestamp check. It runs inside the temporary
 * consumer so it exercises the installed tarball, and it answers the library's
 * TSA request from the OpenSSL fixture TSA instead of the network.
 */
function writeTimestampCheck(consumerDirectory: string, inputPath: string): string {
    const checkPath = join(consumerDirectory, "check-timestamp.mjs");
    writeFileSync(
        checkPath,
        [
            'import { spawnSync } from "node:child_process";',
            'import { readFileSync, writeFileSync } from "node:fs";',
            'import { join } from "node:path";',
            'import { timestampPdf } from "pdf-rfc3161";',
            "",
            "const tsaDirectory = process.env.TSA_DIRECTORY;",
            "const tsaConfig = process.env.TSA_CONFIG;",
            "const input = new Uint8Array(readFileSync(" + JSON.stringify(inputPath) + "));",
            "",
            "// Format of the section the last startxref points at: a classic table",
            '// starts with the "xref" keyword, a cross-reference stream with an',
            "// indirect object header. Emitted from test/utils/xref-format.ts.",
            emitFunction(xrefSections, "xrefSections"),
            emitFunction(lastXrefFormat, "lastXrefFormat"),
            "",
            'if (lastXrefFormat(input) !== "stream") {',
            '    throw new Error("fixture input is not a cross-reference-stream PDF");',
            "}",
            "",
            "globalThis.fetch = async (_url, options) => {",
            "    if (!(options?.body instanceof ArrayBuffer)) {",
            '        throw new Error("expected the TSA request as an ArrayBuffer");',
            "    }",
            '    const requestPath = join(tsaDirectory, "packed-consumer.tsq");',
            '    const responsePath = join(tsaDirectory, "packed-consumer.tsr");',
            "    writeFileSync(requestPath, new Uint8Array(options.body));",
            "    const reply = spawnSync(",
            '        "openssl",',
            '        ["ts", "-reply", "-queryfile", requestPath, "-config", tsaConfig, "-out", responsePath],',
            '        { encoding: "utf8" }',
            "    );",
            "    if (reply.status !== 0) {",
            '        throw new Error("openssl ts -reply failed: " + (reply.stderr ?? reply.error?.message));',
            "    }",
            "    return new Response(new Uint8Array(readFileSync(responsePath)), {",
            '        headers: { "content-type": "application/timestamp-reply" },',
            "    });",
            "};",
            "",
            "const result = await timestampPdf({",
            "    pdf: input,",
            '    tsa: { url: "http://tsa.invalid/packed-consumer", retry: 0 },',
            "    enableLTV: false,",
            "});",
            "",
            "if (!(result.pdf instanceof Uint8Array) || result.pdf.length <= input.length) {",
            '    throw new Error("timestampPdf did not append a revision");',
            "}",
            'if (lastXrefFormat(result.pdf) !== "stream") {',
            "    throw new Error(",
            '        "timestamped output ends with a " + lastXrefFormat(result.pdf) + " cross-reference section, expected a stream"',
            "    );",
            "}",
        ].join("\n"),
        "utf8"
    );
    return checkPath;
}

function assertResolvedInsideConsumer(consumerDirectory: string, resolvedPath: string): void {
    const consumerRoot = realpathSync(consumerDirectory);
    const relativePath = relative(consumerRoot, realpathSync(resolvedPath));
    assert(
        relativePath === "" ||
            (!isAbsolute(relativePath) &&
                relativePath !== ".." &&
                !relativePath.startsWith(".." + sep)),
        "resolved path is outside temporary consumer: " + resolvedPath
    );
}

async function checkInstalledConsumer(
    consumerDirectory: string,
    temporaryDirectory: string,
    artifacts: PackedArtifacts,
    failures: string[]
): Promise<void> {
    const coreDirectory = join(consumerDirectory, "node_modules", "pdf-rfc3161");
    const cliDirectory = join(consumerDirectory, "node_modules", "pdf-rfc3161-cli");
    const env = { ...process.env, CONSUMER_ROOT: consumerDirectory };
    for (const path of Object.values(writeChecks(consumerDirectory))) {
        commandSucceeded(run(process.execPath, [path], consumerDirectory, env));
    }

    // Behavioral check: the packed library must timestamp a cross-reference
    // stream PDF. Only an end-to-end call through the installed tarball proves
    // it, because the mechanism that keeps the signature dictionary out of
    // object streams has to live in shipped library code, not in repo-local
    // install configuration such as a pnpm patch.
    //
    // It needs a TSA, and the fixture TSA is `openssl ts`. Where that
    // subcommand does not exist -- stock macOS, whose LibreSSL has no `ts` app
    // -- skip this one check rather than failing the documented `pnpm
    // test:full` on the very platform the xref fix targets. Never skip in CI.
    if (opensslTimestampAvailable()) {
        const tsaDirectory = join(temporaryDirectory, "tsa");
        mkdirSync(tsaDirectory, { recursive: true });
        const tsa = createLocalTsa(tsaDirectory);
        const timestampCheck = writeTimestampCheck(
            consumerDirectory,
            await writeXrefStreamInput(consumerDirectory)
        );
        commandSucceeded(
            run(process.execPath, [timestampCheck], consumerDirectory, {
                ...env,
                TSA_DIRECTORY: tsaDirectory,
                TSA_CONFIG: tsa.config,
            })
        );
    } else if (RUNNING_IN_CI) {
        failures.push(
            "openssl is missing the `ts` subcommand: the packed-consumer timestamp check cannot " +
                "run, and CI must not skip it (all CI jobs are ubuntu-24.04 with full OpenSSL)"
        );
    } else {
        process.stdout.write(
            "SKIPPED: packed-consumer timestamp behavior check (timestampPdf against the local " +
                "fixture TSA, and the cross-reference format of its output).\n" +
                "Reason: this machine's `openssl` has no `ts` subcommand -- stock macOS ships " +
                "LibreSSL, which does not implement RFC 3161 timestamping.\n" +
                "Every packaging check that does not need a TSA still ran. Install OpenSSL " +
                "(for example `brew install openssl@3` and put it first on PATH) for full " +
                "coverage.\n"
        );
    }
    const typeChecks = writeTypeChecks(consumerDirectory);
    commandSucceeded(
        runPnpm(
            [
                "exec",
                "tsc",
                "--noEmit",
                "--module",
                "NodeNext",
                "--moduleResolution",
                "NodeNext",
                "--target",
                "ES2022",
                typeChecks.mtsPath,
                typeChecks.ctsPath,
            ],
            consumerDirectory
        )
    );
    const viteEntry = writeViteEntry(consumerDirectory);
    assert(existsSync(viteEntry), "Vite entry does not exist: " + viteEntry);
    commandSucceeded(
        runPnpm(
            ["exec", "vite", "build", "--outDir", join(consumerDirectory, "vite-dist")],
            consumerDirectory
        )
    );

    const cliManifest = manifest(cliDirectory);
    const coreExportFiles = new Set<string>();
    declaredExportFiles(manifest(coreDirectory).exports, coreExportFiles);
    const coreTarballFiles = tarballFiles(artifacts.coreTarballPath);
    for (const exportFile of coreExportFiles) {
        if (!coreTarballFiles.includes(exportFile)) {
            failures.push("core tarball is missing declared export " + exportFile);
        }
    }
    if (JSON.stringify(cliManifest.bin) !== JSON.stringify({ "pdf-rfc3161": "dist/cli.cjs" })) {
        failures.push("CLI bin must map pdf-rfc3161 to dist/cli.cjs");
    }
    const expectedCoreVersion = manifestVersion(CORE_DIRECTORY);
    if (cliManifest.dependencies?.["pdf-rfc3161"] !== expectedCoreVersion) {
        failures.push("CLI dependency pdf-rfc3161 must be " + expectedCoreVersion);
    }
    const cliBundle = readFileSync(join(cliDirectory, "dist", "cli.cjs"), "utf8");
    const cliBundlePath = join(cliDirectory, "dist", "cli.cjs");
    const cliRequire = createRequire(realpathSync(cliBundlePath));
    assert.equal(
        realpathSync(cliRequire.resolve("pdf-rfc3161")),
        realpathSync(createRequire(join(consumerDirectory, "package.json")).resolve("pdf-rfc3161")),
        "CLI must resolve the same candidate core artifact as the consumer"
    );
    assertResolvedInsideConsumer(consumerDirectory, cliBundlePath);
    assertResolvedInsideConsumer(consumerDirectory, cliRequire.resolve("commander"));
    if (!/require\(["']commander["']\)/.test(cliBundle)) {
        failures.push('CLI bundle must retain external require("commander")');
    }

    for (const packageDirectory of [coreDirectory, cliDirectory]) {
        const runtimeFiles = readdirSync(join(packageDirectory, "dist"), { recursive: true })
            .filter((file): file is string => typeof file === "string")
            .filter((file) => file.endsWith(".cjs") || file.endsWith(".js"));
        for (const runtimeFile of runtimeFiles) {
            const runtimePath = join(packageDirectory, "dist", runtimeFile);
            if (readFileSync(runtimePath, "utf8").includes("sourceMappingURL")) {
                failures.push(
                    relative(consumerDirectory, runtimePath) +
                        " must not contain source-map references"
                );
            }
        }
    }

    const executable = join(
        consumerDirectory,
        "node_modules",
        ".bin",
        process.platform === "win32" ? "pdf-rfc3161.cmd" : "pdf-rfc3161"
    );
    assert(existsSync(executable), "installed CLI executable does not exist: " + executable);
    const version = runPnpm(["exec", "pdf-rfc3161", "--version"], consumerDirectory, env);
    commandSucceeded(version);
    assert.equal(
        commandOutput(version.result).trim(),
        manifestVersion(CLI_DIRECTORY),
        "installed CLI version output"
    );
    const help = runPnpm(["exec", "pdf-rfc3161", "--help"], consumerDirectory, env);
    commandSucceeded(help);
    assert.match(commandOutput(help.result), /Usage: pdf-rfc3161/, "installed CLI help output");
}

async function main(): Promise<void> {
    let temporaryDirectory: string | undefined;
    try {
        const pnpmVersion = runPnpm(["--version"], REPOSITORY_ROOT);
        commandSucceeded(pnpmVersion);
        assert.equal(
            commandOutput(pnpmVersion.result).trim(),
            ROOT_PNPM_VERSION,
            "pnpm version must match root packageManager"
        );
        temporaryDirectory = mkdtempSync(join(tmpdir(), "pdf-rfc3161-packed-consumer-"));
        const consumerDirectory = join(temporaryDirectory, "consumer");
        mkdirSync(consumerDirectory, { recursive: true });
        const artifacts = packedArtifacts(temporaryDirectory);
        const failures = packageContract(artifacts);
        writeConsumerPackage(consumerDirectory, artifacts);
        writeConsumerWorkspace(consumerDirectory, artifacts.coreTarballPath);
        const consumerPnpmVersion = runPnpm(["--version"], consumerDirectory);
        commandSucceeded(consumerPnpmVersion);
        assert.equal(
            commandOutput(consumerPnpmVersion.result).trim(),
            ROOT_PNPM_VERSION,
            "consumer pnpm version must match root packageManager"
        );
        commandSucceeded(
            runPnpm(
                [
                    "install",
                    "--config.node-linker=isolated",
                    "--config.virtual-store-dir=.pnpm",
                ],
                consumerDirectory
            )
        );
        await checkInstalledConsumer(consumerDirectory, temporaryDirectory, artifacts, failures);
        assert.equal(
            failures.length,
            0,
            "Published artifact contract failed:\n" + failures.join("\n")
        );
        process.stdout.write(
            "Packed consumer checks passed for " +
                artifacts.coreTarballPath +
                " and " +
                artifacts.cliTarballPath +
                "\nInstalled packages resolved under " +
                realpathSync(consumerDirectory) +
                "\n"
        );
    } finally {
        if (temporaryDirectory) {
            rmSync(temporaryDirectory, { force: true, recursive: true });
        }
    }
}

main().catch((error: unknown) => {
    console.error("Packed consumer test failed:", error);
    process.exitCode = 1;
});
