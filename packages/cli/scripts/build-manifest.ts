import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join, relative, sep } from "node:path";

// Records WHICH sources the CLI bundle was built from, so a test suite that
// spawns `packages/cli/dist/cli.cjs` can tell "the bundle is out of date" from
// "the bundle is fine, the files were merely touched".
//
// Modification times cannot make that distinction: a branch switch, a fresh
// clone, a `git stash pop`, or an `eslint --fix` pass that rewrites a file with
// identical bytes all move an mtime forward while leaving the built output
// byte-for-byte correct. This manifest stores a content hash instead.
//
// It deliberately lives NEXT TO the package rather than inside `dist/`: the
// CLI's `files` field publishes the whole `dist` directory, and both
// `test-packed-consumer.ts` and the release workflow assert the tarball's exact
// file list, so an extra file in `dist` would ship and break packaging.

const MANIFEST_VERSION = 1;

/**
 * Sources that decide whether `dist/cli.cjs` is current. The CLI bundle keeps
 * `pdf-rfc3161` external, so a stale core build reaches the spawned binary
 * through the workspace link -- hence core's sources count too.
 */
const SOURCE_DIRECTORIES = ["packages/cli/src", "packages/core/src"];

export interface CliBuildManifest {
    version: number;
    /** SHA-256 over the CLI/core sources, as computed by `cliSourceHash`. */
    sourceHash: string;
    builtAt: string;
}

export function cliBuildManifestPath(repositoryRoot: string): string {
    return join(repositoryRoot, "packages/cli/.build-manifest.json");
}

function collectFiles(directory: string, files: string[]): void {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
        const path = join(directory, entry.name);
        if (entry.isDirectory()) {
            collectFiles(path, files);
        } else if (entry.isFile()) {
            files.push(path);
        }
    }
}

/**
 * Separates the path, length, and content fields of one file inside the digest.
 * A NUL can appear in neither of the first two, so no crafted file name or
 * length can shift a byte across a field boundary and make two different source
 * trees hash alike.
 *
 * Written as an escape and never as a literal control byte: repository sources
 * are ASCII-only, and one raw NUL makes git classify this file as binary, which
 * replaces its diff with "Binary files differ" and hides every future change to
 * it from review.
 */
const FIELD_SEPARATOR = "\0";

/**
 * SHA-256 over every CLI/core source file: its repository-relative path (with
 * POSIX separators, so the digest is identical on Windows), its byte length,
 * and its bytes. Sorting by path makes the walk order irrelevant. Modification
 * times are deliberately absent: the same sources must always hash the same,
 * which is the whole point of replacing the old mtime comparison.
 */
export function cliSourceHash(repositoryRoot: string): string {
    const hash = createHash("sha256");
    const files: string[] = [];
    for (const directory of SOURCE_DIRECTORIES) {
        collectFiles(join(repositoryRoot, directory), files);
    }
    for (const path of files.sort()) {
        const contents = readFileSync(path);
        hash.update(relative(repositoryRoot, path).split(sep).join("/"));
        hash.update(FIELD_SEPARATOR);
        hash.update(String(contents.length));
        hash.update(FIELD_SEPARATOR);
        hash.update(contents);
    }
    return hash.digest("hex");
}

/** Called from the CLI's tsup `onSuccess`, once the bundle is on disk. */
export function writeCliBuildManifest(repositoryRoot: string): CliBuildManifest {
    const manifest: CliBuildManifest = {
        version: MANIFEST_VERSION,
        sourceHash: cliSourceHash(repositoryRoot),
        builtAt: new Date().toISOString(),
    };
    writeFileSync(cliBuildManifestPath(repositoryRoot), JSON.stringify(manifest, null, 4) + "\n");
    return manifest;
}

/**
 * The manifest of the last build, or `undefined` when it is absent or was
 * written by an incompatible version of this file. Both cases mean the same
 * thing to a caller: rebuild.
 */
export function readCliBuildManifest(repositoryRoot: string): CliBuildManifest | undefined {
    const path = cliBuildManifestPath(repositoryRoot);
    if (!existsSync(path)) return undefined;
    let parsed: unknown;
    try {
        parsed = JSON.parse(readFileSync(path, "utf8"));
    } catch {
        return undefined;
    }
    if (typeof parsed !== "object" || parsed === null) return undefined;
    const manifest = parsed as Partial<CliBuildManifest>;
    if (manifest.version !== MANIFEST_VERSION || typeof manifest.sourceHash !== "string") {
        return undefined;
    }
    return {
        version: manifest.version,
        sourceHash: manifest.sourceHash,
        builtAt: typeof manifest.builtAt === "string" ? manifest.builtAt : "",
    };
}
