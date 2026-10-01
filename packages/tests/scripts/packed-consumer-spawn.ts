// Shared child-process and packing helpers for the packed-consumer gates.
//
// Both test-packed-consumer.ts (Node API/CLI contract) and
// test-browser-consumer.ts (T00 real-browser signing gate) install a
// candidate tarball into an isolated temporary consumer. The spawn
// wrappers and pack helpers live here so the two gates cannot drift
// apart. Each gate keeps its own pnpm entrypoint constant (resolved from
// process.env.npm_execpath) and passes it in.
import assert from "node:assert/strict";
import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import { existsSync, mkdirSync, readdirSync } from "node:fs";
import { basename, dirname, extname, join } from "node:path";

export interface CommandResult {
    command: string;
    args: string[];
    result: SpawnSyncReturns<string>;
}

export function commandOutput(result: SpawnSyncReturns<string>): string {
    return [result.stdout, result.stderr]
        .filter((value): value is string => typeof value === "string" && value.length > 0)
        .join("\n");
}

export function run(
    command: string,
    args: string[],
    cwd: string,
    env?: NodeJS.ProcessEnv
): CommandResult {
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

export function runPnpm(
    pnpmEntrypoint: string,
    args: string[],
    cwd: string,
    env?: NodeJS.ProcessEnv
): CommandResult {
    const extension = extname(pnpmEntrypoint).toLowerCase();
    return [".js", ".cjs", ".mjs"].includes(extension)
        ? run(process.execPath, [pnpmEntrypoint, ...args], cwd, env)
        : run(pnpmEntrypoint, args, cwd, env);
}

export function commandSucceeded(commandResult: CommandResult): void {
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

export function packPackage(
    pnpmEntrypoint: string,
    packageDirectory: string,
    packRoot: string
): string {
    const destination = join(packRoot, basename(packageDirectory));
    mkdirSync(destination, { recursive: true });
    commandSucceeded(
        runPnpm(pnpmEntrypoint, ["pack", "--pack-destination", destination], packageDirectory)
    );
    const tarballs = readdirSync(destination).filter((file) => file.endsWith(".tgz"));
    assert.equal(tarballs.length, 1, "expected one tarball for " + packageDirectory);
    const tarballPath = join(destination, tarballs[0] ?? "");
    assert(existsSync(tarballPath), "tarball does not exist: " + tarballPath);
    return tarballPath;
}

export function tarballFiles(tarballPath: string): string[] {
    const result = run("tar", ["-tzf", tarballPath], dirname(tarballPath));
    commandSucceeded(result);
    return commandOutput(result.result)
        .split("\n")
        .map((file) => file.trim())
        .filter((file) => file.startsWith("package/") && !file.endsWith("/"))
        .map((file) => file.slice("package/".length))
        .sort();
}

/** Isolated-consumer install flags shared by both packed-consumer gates. */
export const CONSUMER_INSTALL_ARGS = [
    "install",
    "--config.node-linker=isolated",
    "--config.virtual-store-dir=.pnpm",
];

export function installConsumer(pnpmEntrypoint: string, consumerDirectory: string): void {
    commandSucceeded(runPnpm(pnpmEntrypoint, CONSUMER_INSTALL_ARGS, consumerDirectory));
}
