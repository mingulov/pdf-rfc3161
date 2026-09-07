import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { writeConsumerWorkspace } from "../../scripts/packed-consumer-config";

it("overrides transitive core dependencies with the supplied candidate tarball", () => {
    const consumer = mkdtempSync(join(tmpdir(), "packed-consumer-config-"));
    try {
        const tarball = join(consumer, 'candidate with spaces and "quotes".tgz');
        writeConsumerWorkspace(consumer, tarball);
        // JSON is valid YAML, including escaped paths on Windows.
        const config = JSON.parse(readFileSync(join(consumer, "pnpm-workspace.yaml"), "utf8")) as {
            overrides: Record<string, string>;
        };
        expect(config.overrides["pdf-rfc3161"]).toBe("file:" + tarball);
    } finally {
        rmSync(consumer, { recursive: true, force: true });
    }
});
