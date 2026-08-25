import assert from "node:assert/strict";
import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import {
    existsSync,
    mkdtempSync,
    mkdirSync,
    readdirSync,
    realpathSync,
    rmSync,
    writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const CORE_DIRECTORY = resolve(SCRIPT_DIRECTORY, "../../core");
const PNPM_VERSION = "10.30.3";

interface CommandResult {
    command: string;
    args: string[];
    result: SpawnSyncReturns<string>;
}

function commandOutput(result: SpawnSyncReturns<string>): string {
    return [result.stdout, result.stderr]
        .filter((value): value is string => typeof value === "string" && value.length > 0)
        .join("\n");
}

function runCommand(
    command: string,
    args: string[],
    options: { cwd: string; env?: NodeJS.ProcessEnv }
): CommandResult {
    const result = spawnSync(command, args, {
        cwd: options.cwd,
        env: options.env,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
    });

    if (result.error) {
        throw new Error(`${command} ${args.join(" ")} could not start: ${result.error.message}`);
    }

    return { command, args, result };
}

function runPnpm(args: string[], cwd: string, env?: NodeJS.ProcessEnv): CommandResult {
    const command = process.platform === "win32" ? "corepack.cmd" : "corepack";
    return runCommand(command, [`pnpm@${PNPM_VERSION}`, ...args], { cwd, env });
}

function assertCommandSucceeded(commandResult: CommandResult): void {
    const { command, args, result } = commandResult;
    assert.equal(
        result.status,
        0,
        `${command} ${args.join(" ")} failed${commandOutput(result) ? `:\n${commandOutput(result)}` : ""}`
    );
}

function writeConsumerPackage(consumerDirectory: string, tarballPath: string): void {
    writeFileSync(
        join(consumerDirectory, "package.json"),
        `${JSON.stringify(
            {
                name: "pdf-rfc3161-packed-consumer",
                private: true,
                type: "module",
                dependencies: {
                    "pdf-rfc3161": `file:${tarballPath}`,
                },
                devDependencies: {
                    vite: "8.2.2",
                },
            },
            null,
            4
        )}\n`,
        "utf8"
    );
}

function writeNodeConsumerChecks(
    consumerDirectory: string,
    packageRoot: string
): { esmPath: string; cjsPath: string } {
    const esmPath = join(consumerDirectory, "check-esm.mjs");
    writeFileSync(
        esmPath,
        `import { createRequire } from "node:module";
import { realpathSync } from "node:fs";
import { isAbsolute, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const packageRootValue = process.env.PACKAGE_ROOT;
if (!packageRootValue) throw new Error("PACKAGE_ROOT is required");
const packageRoot = realpathSync(packageRootValue);
const assertResolvedInsidePackage = (resolvedPath) => {
    const resolved = realpathSync(resolvedPath);
    const relativePath = relative(packageRoot, resolved);
    if (isAbsolute(relativePath) || relativePath === ".." || relativePath.startsWith(".." + sep)) {
        throw new Error("resolved module " + resolved + " is outside installed package " + packageRoot);
    }
};

const esm = await import("pdf-rfc3161");
const internals = await import("pdf-rfc3161/internals");
if (typeof esm.timestampPdf !== "function") throw new Error("ESM timestampPdf export is missing");
if (typeof internals.addVRIForSignature !== "function") {
    throw new Error("ESM addVRIForSignature export is missing");
}
assertResolvedInsidePackage(fileURLToPath(import.meta.resolve("pdf-rfc3161")));
assertResolvedInsidePackage(fileURLToPath(import.meta.resolve("pdf-rfc3161/internals")));
assertResolvedInsidePackage(require.resolve("pdf-rfc3161"));
assertResolvedInsidePackage(require.resolve("pdf-rfc3161/internals"));
`,
        "utf8"
    );

    const cjsPath = join(consumerDirectory, "check-cjs.cjs");
    writeFileSync(
        cjsPath,
        `const { realpathSync } = require("node:fs");
const { isAbsolute, relative, sep } = require("node:path");

const packageRootValue = process.env.PACKAGE_ROOT;
if (!packageRootValue) throw new Error("PACKAGE_ROOT is required");
const packageRoot = realpathSync(packageRootValue);
const assertResolvedInsidePackage = (resolvedPath) => {
    const resolved = realpathSync(resolvedPath);
    const relativePath = relative(packageRoot, resolved);
    if (isAbsolute(relativePath) || relativePath === ".." || relativePath.startsWith(".." + sep)) {
        throw new Error("resolved module " + resolved + " is outside installed package " + packageRoot);
    }
};

const cjs = require("pdf-rfc3161");
const internals = require("pdf-rfc3161/internals");
if (typeof cjs.timestampPdf !== "function") throw new Error("CJS timestampPdf export is missing");
if (typeof internals.addVRIForSignature !== "function") {
    throw new Error("CJS addVRIForSignature export is missing");
}
assertResolvedInsidePackage(require.resolve("pdf-rfc3161"));
assertResolvedInsidePackage(require.resolve("pdf-rfc3161/internals"));
`,
        "utf8"
    );

    assert(existsSync(packageRoot), `installed package path does not exist: ${packageRoot}`);
    return { esmPath, cjsPath };
}

function writeViteEntry(consumerDirectory: string): { entryPath: string; outputDirectory: string } {
    const sourceDirectory = join(consumerDirectory, "src");
    const entryPath = join(sourceDirectory, "main.js");
    const outputDirectory = join(consumerDirectory, "vite-dist");
    mkdirSync(sourceDirectory, { recursive: true });
    writeFileSync(
        join(consumerDirectory, "index.html"),
        `<!doctype html>
<html>
    <head><title>pdf-rfc3161 packed consumer</title></head>
    <body><script type="module" src="/src/main.js"></script></body>
</html>
`,
        "utf8"
    );
    writeFileSync(
        entryPath,
        `import { preparePdfForTimestamp } from "pdf-rfc3161/internals";

if (typeof preparePdfForTimestamp !== "function") {
    throw new Error("browser subpath preparePdfForTimestamp export is missing");
}

export { preparePdfForTimestamp };
`,
        "utf8"
    );
    return { entryPath, outputDirectory };
}

function main(): void {
    let temporaryDirectory: string | undefined;
    try {
        temporaryDirectory = mkdtempSync(join(tmpdir(), "pdf-rfc3161-packed-consumer-"));
        const packDirectory = join(temporaryDirectory, "pack");
        const consumerDirectory = join(temporaryDirectory, "consumer");
        const packageRoot = join(consumerDirectory, "node_modules", "pdf-rfc3161");
        mkdirSync(packDirectory, { recursive: true });
        mkdirSync(consumerDirectory, { recursive: true });

        const packResult = runPnpm(
            ["pack", "--pack-destination", packDirectory],
            CORE_DIRECTORY
        );
        assertCommandSucceeded(packResult);

        const tarballs = readdirSync(packDirectory).filter((file) => file.endsWith(".tgz"));
        assert.equal(tarballs.length, 1, `expected one package tarball, found ${tarballs.join(", ")}`);
        const tarballPath = join(packDirectory, tarballs[0] ?? "");
        assert(existsSync(tarballPath), `package tarball does not exist: ${tarballPath}`);

        writeConsumerPackage(consumerDirectory, tarballPath);
        assertCommandSucceeded(runPnpm(["install", "--ignore-workspace"], consumerDirectory));

        const checks = writeNodeConsumerChecks(consumerDirectory, packageRoot);
        for (const checkPath of [checks.esmPath, checks.cjsPath]) {
            assertCommandSucceeded(
                runCommand(process.execPath, [checkPath], {
                    cwd: consumerDirectory,
                    env: {
                        ...process.env,
                        PACKAGE_ROOT: packageRoot,
                    },
                })
            );
        }

        const vite = writeViteEntry(consumerDirectory);
        assert(existsSync(vite.entryPath), `Vite entry does not exist: ${vite.entryPath}`);
        assertCommandSucceeded(
            runPnpm(
                ["exec", "vite", "build", "--outDir", vite.outputDirectory],
                consumerDirectory
            )
        );
        assert(existsSync(vite.outputDirectory), `Vite output does not exist: ${vite.outputDirectory}`);

        process.stdout.write(
            `Packed consumer checks passed for ${tarballPath}\n` +
                `Installed package resolved under ${realpathSync(packageRoot)}\n` +
                `Vite production output: ${vite.outputDirectory}\n`
        );
    } finally {
        if (temporaryDirectory !== undefined) {
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
