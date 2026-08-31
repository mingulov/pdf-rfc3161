import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
    cliBuildManifestPath,
    cliSourceHash,
    readCliBuildManifest,
} from "../../../cli/scripts/build-manifest.js";

// The CLI suites spawn the built bundle, not the sources. A local run against a
// stale `packages/cli/dist/cli.cjs` silently tests yesterday's code -- during
// the PR#63 fix wave that hid a real regression, because CI builds first and
// developer machines do not. This guard turns that silence into a clear
// failure instead of a false pass.
//
// It compares CONTENT, not modification times. The mtime sweep this replaced
// failed a rebuild-free `pnpm test` after any operation that rewrites a file
// without changing it -- a branch switch, a fresh clone, `eslint --fix` on an
// already-clean file -- which contradicts CLAUDE.md's promise that `pnpm test`
// needs no build, and trained everyone to ignore the message. The build writes
// a hash of the sources it consumed (packages/cli/scripts/build-manifest.ts);
// here we recompute it and compare.

const UTILS_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(UTILS_DIRECTORY, "../../../..");

/** The built CLI bundle inside an arbitrary checkout of this repository. */
export function cliDistPath(repositoryRoot: string): string {
    return join(repositoryRoot, "packages/cli/dist/cli.cjs");
}

export const CLI_DIST_PATH = cliDistPath(REPOSITORY_ROOT);

/**
 * Fails when `packages/cli/dist/cli.cjs` is missing under `repositoryRoot`, or
 * when the CLI/core sources there no longer hash to what the last build
 * recorded.
 *
 * Parameterized by root so `cli-build-manifest.test.ts` can drive every failure
 * path against a temporary fixture tree instead of mutating the real checkout
 * (which would also require the suite to have run `pnpm build`).
 */
export function assertCliDistIsFreshAt(repositoryRoot: string): void {
    const distPath = cliDistPath(repositoryRoot);
    if (!existsSync(distPath)) {
        throw new Error(
            `missing build: run \`pnpm build\` before the CLI suite (${distPath} does not exist)`
        );
    }
    const manifest = readCliBuildManifest(repositoryRoot);
    if (manifest === undefined) {
        throw new Error(
            "missing build manifest: run `pnpm build` before the CLI suite " +
                `(${cliBuildManifestPath(repositoryRoot)} is absent or unreadable)`
        );
    }
    if (manifest.sourceHash !== cliSourceHash(repositoryRoot)) {
        throw new Error(
            "stale build: run `pnpm build` before the CLI suite " +
                `(${distPath} was built from different packages/cli/src or packages/core/src sources)`
        );
    }
}

/**
 * The same check against this checkout. Call it from the setup of any suite
 * that runs the built CLI.
 */
export function assertCliDistIsFresh(): void {
    assertCliDistIsFreshAt(REPOSITORY_ROOT);
}
