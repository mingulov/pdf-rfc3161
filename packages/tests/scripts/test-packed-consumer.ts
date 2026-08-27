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
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const CORE_DIRECTORY = resolve(SCRIPT_DIRECTORY, "../../core");
const CLI_DIRECTORY = resolve(SCRIPT_DIRECTORY, "../../cli");
const PNPM_VERSION = "10.30.3";
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
}

function commandOutput(result: SpawnSyncReturns<string>): string {
    return [result.stdout, result.stderr]
        .filter((value): value is string => typeof value === "string" && value.length > 0)
        .join("\n");
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

function runPnpm(args: string[], cwd: string): CommandResult {
    return run(
        process.platform === "win32" ? "corepack.cmd" : "corepack",
        ["pnpm@" + PNPM_VERSION, ...args],
        cwd
    );
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
                dependencies: {
                    "pdf-rfc3161": "file:" + artifacts.coreTarballPath,
                    "pdf-rfc3161-cli": "file:" + artifacts.cliTarballPath,
                },
                devDependencies: {
                    "@types/node": "25.9.1",
                    typescript: "5.9.3",
                    vite: "8.2.2",
                },
                pnpm: {
                    overrides: {
                        "pdf-rfc3161": "file:" + artifacts.coreTarballPath,
                    },
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

function checkInstalledConsumer(
    consumerDirectory: string,
    artifacts: PackedArtifacts,
    failures: string[]
): void {
    const coreDirectory = join(consumerDirectory, "node_modules", "pdf-rfc3161");
    const cliDirectory = join(consumerDirectory, "node_modules", "pdf-rfc3161-cli");
    const env = { ...process.env, CONSUMER_ROOT: consumerDirectory };
    for (const path of Object.values(writeChecks(consumerDirectory))) {
        commandSucceeded(run(process.execPath, [path], consumerDirectory, env));
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
    if (cliManifest.dependencies?.["pdf-rfc3161"] !== "0.2.0") {
        failures.push("CLI dependency pdf-rfc3161 must be 0.2.0");
    }
    const cliBundle = readFileSync(join(cliDirectory, "dist", "cli.cjs"), "utf8");
    const cliBundlePath = join(cliDirectory, "dist", "cli.cjs");
    const cliRequire = createRequire(realpathSync(cliBundlePath));
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
    const version = run(executable, ["--version"], consumerDirectory, env);
    commandSucceeded(version);
    assert.equal(commandOutput(version.result).trim(), "0.2.0", "installed CLI version output");
    const help = run(executable, ["--help"], consumerDirectory, env);
    commandSucceeded(help);
    assert.match(commandOutput(help.result), /Usage: pdf-rfc3161/, "installed CLI help output");
}

function main(): void {
    let temporaryDirectory: string | undefined;
    try {
        temporaryDirectory = mkdtempSync(join(tmpdir(), "pdf-rfc3161-packed-consumer-"));
        const consumerDirectory = join(temporaryDirectory, "consumer");
        mkdirSync(consumerDirectory, { recursive: true });
        const artifacts = packedArtifacts(temporaryDirectory);
        const failures = packageContract(artifacts);
        writeConsumerPackage(consumerDirectory, artifacts);
        commandSucceeded(
            runPnpm(
                [
                    "install",
                    "--ignore-workspace",
                    "--config.node-linker=isolated",
                    "--config.virtual-store-dir=.pnpm",
                ],
                consumerDirectory
            )
        );
        checkInstalledConsumer(consumerDirectory, artifacts, failures);
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

try {
    main();
} catch (error: unknown) {
    console.error("Packed consumer test failed:", error);
    process.exitCode = 1;
}
