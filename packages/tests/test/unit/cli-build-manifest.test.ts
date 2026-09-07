import { mkdirSync, mkdtempSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
    cliBuildManifestPath,
    cliSourceHash,
    readCliBuildManifest,
    writeCliBuildManifest,
} from "../../../cli/scripts/build-manifest.js";
import { assertCliDistIsFreshAt, cliDistPath } from "../utils/cli-dist.js";

// The CLI suites refuse to run against a stale `packages/cli/dist/cli.cjs`, and
// that refusal is only as trustworthy as the hash behind it. These tests pin
// the two properties the guard rests on: the digest follows CONTENT (so the
// mtime churn that made the previous guard cry wolf is invisible to it, while a
// real edit is not), and each failure path reports the specific reason.
//
// Everything runs against a temporary fixture checkout. Nothing here touches
// the real packages/cli tree, and nothing here depends on `pnpm build` having
// been run.

const temporaryRoots: string[] = [];

afterEach(() => {
    for (const root of temporaryRoots.splice(0)) {
        rmSync(root, { force: true, recursive: true });
    }
});

interface FixtureCheckout {
    root: string;
    cliSource: string;
    coreSource: string;
    distPath: string;
}

/**
 * A checkout-shaped fixture: the two source directories the hash walks, plus a
 * nested file so the recursive walk is exercised, and a stand-in bundle.
 */
function createFixtureCheckout(): FixtureCheckout {
    const root = mkdtempSync(join(tmpdir(), "pdf-rfc3161-manifest-"));
    temporaryRoots.push(root);
    mkdirSync(join(root, "packages/cli/src/commands"), { recursive: true });
    mkdirSync(join(root, "packages/core/src"), { recursive: true });
    mkdirSync(join(root, "packages/cli/dist"), { recursive: true });

    const cliSource = join(root, "packages/cli/src/cli.ts");
    const coreSource = join(root, "packages/core/src/index.ts");
    writeFileSync(cliSource, "export const cli = 1;\n");
    writeFileSync(join(root, "packages/cli/src/commands/timestamp.ts"), "export const cmd = 2;\n");
    writeFileSync(coreSource, "export const core = 3;\n");

    const distPath = cliDistPath(root);
    writeFileSync(distPath, "// built bundle\n");
    return { root, cliSource, coreSource, distPath };
}

describe("cliSourceHash", () => {
    it("returns the same digest for the same sources", () => {
        const fixture = createFixtureCheckout();

        expect(cliSourceHash(fixture.root)).toBe(cliSourceHash(fixture.root));
    });

    it("ignores modification times", () => {
        // The property the whole rewrite exists for: a branch switch, a fresh
        // clone, or an `eslint --fix` pass that rewrites a file with identical
        // bytes moves mtimes forward without changing what was built.
        const fixture = createFixtureCheckout();
        const before = cliSourceHash(fixture.root);

        const future = new Date(Date.now() + 60_000);
        utimesSync(fixture.cliSource, future, future);
        utimesSync(fixture.coreSource, future, future);
        // Rewriting a file with its own bytes must be invisible too.
        writeFileSync(fixture.cliSource, "export const cli = 1;\n");

        expect(cliSourceHash(fixture.root)).toBe(before);
    });

    // The replacements below keep the file's byte LENGTH identical on purpose.
    // The digest mixes in each file's length as well as its bytes, so an edit
    // that also changes the length would pass even if the contents were never
    // hashed at all -- these two would then be testing nothing.
    it("changes when a CLI source file's contents change", () => {
        const fixture = createFixtureCheckout();
        const before = cliSourceHash(fixture.root);

        writeFileSync(fixture.cliSource, "export const cli = 2;\n");

        expect(cliSourceHash(fixture.root)).not.toBe(before);
    });

    it("changes when a core source file's contents change", () => {
        // Core counts because the CLI bundle keeps `pdf-rfc3161` external: a
        // stale core build reaches the spawned binary through the workspace
        // link.
        const fixture = createFixtureCheckout();
        const before = cliSourceHash(fixture.root);

        writeFileSync(fixture.coreSource, "export const core = 4;\n");

        expect(cliSourceHash(fixture.root)).not.toBe(before);
    });

    it("changes when a source file is added or removed", () => {
        const fixture = createFixtureCheckout();
        const before = cliSourceHash(fixture.root);

        const added = join(fixture.root, "packages/core/src/added.ts");
        writeFileSync(added, "export const added = 4;\n");
        const withAddition = cliSourceHash(fixture.root);
        expect(withAddition).not.toBe(before);

        rmSync(added);
        expect(cliSourceHash(fixture.root)).toBe(before);
    });

    it("changes when a file keeps its contents but moves", () => {
        // The path is mixed into the digest, so a rename cannot slip through.
        const fixture = createFixtureCheckout();
        const before = cliSourceHash(fixture.root);

        rmSync(fixture.coreSource);
        writeFileSync(
            join(fixture.root, "packages/core/src/renamed.ts"),
            "export const core = 3;\n"
        );

        expect(cliSourceHash(fixture.root)).not.toBe(before);
    });
});

describe("the CLI build manifest", () => {
    it("round-trips through write and read", () => {
        const fixture = createFixtureCheckout();

        const written = writeCliBuildManifest(fixture.root);
        const read = readCliBuildManifest(fixture.root);

        expect(written.sourceHash).toBe(cliSourceHash(fixture.root));
        expect(read).toEqual(written);
    });

    it("reports an unreadable or foreign manifest as absent", () => {
        const fixture = createFixtureCheckout();
        const path = cliBuildManifestPath(fixture.root);

        writeFileSync(path, "{ not json");
        expect(readCliBuildManifest(fixture.root)).toBeUndefined();

        writeFileSync(path, JSON.stringify({ version: 99, sourceHash: "abc" }));
        expect(readCliBuildManifest(fixture.root)).toBeUndefined();

        writeFileSync(path, JSON.stringify({ version: 1 }));
        expect(readCliBuildManifest(fixture.root)).toBeUndefined();
    });
});

describe("assertCliDistIsFreshAt", () => {
    it("accepts a bundle whose manifest matches the sources", () => {
        const fixture = createFixtureCheckout();
        writeCliBuildManifest(fixture.root);

        expect(() => {
            assertCliDistIsFreshAt(fixture.root);
        }).not.toThrow();
    });

    it("still accepts it after the sources are touched but not changed", () => {
        const fixture = createFixtureCheckout();
        writeCliBuildManifest(fixture.root);

        const future = new Date(Date.now() + 60_000);
        utimesSync(fixture.cliSource, future, future);
        utimesSync(fixture.coreSource, future, future);

        expect(() => {
            assertCliDistIsFreshAt(fixture.root);
        }).not.toThrow();
    });

    it("rejects a bundle built from different sources", () => {
        const fixture = createFixtureCheckout();
        writeCliBuildManifest(fixture.root);

        // Same length, different bytes -- see the note on the hash tests.
        writeFileSync(fixture.coreSource, "export const core = 4;\n");

        expect(() => {
            assertCliDistIsFreshAt(fixture.root);
        }).toThrow(/stale build: run `pnpm build`/);
    });

    it("names the missing manifest when only the bundle exists", () => {
        const fixture = createFixtureCheckout();

        expect(() => {
            assertCliDistIsFreshAt(fixture.root);
        }).toThrow(/missing build manifest: run `pnpm build`/);
    });

    it("names the missing bundle before looking at the manifest", () => {
        const fixture = createFixtureCheckout();
        writeCliBuildManifest(fixture.root);
        rmSync(fixture.distPath);

        expect(() => {
            assertCliDistIsFreshAt(fixture.root);
        }).toThrow(/missing build: run `pnpm build`/);
    });
});
