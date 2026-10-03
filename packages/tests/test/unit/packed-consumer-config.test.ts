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
        // Block-style YAML (JSON would be valid too, but pnpm cannot edit
        // inline values in place when recording build approvals). The
        // override value is JSON-quoted, so nasty paths survive verbatim.
        const text = readFileSync(join(consumer, "pnpm-workspace.yaml"), "utf8");
        const overrideLine = text
            .split("\n")
            .find((line) => line.trimStart().startsWith("pdf-rfc3161:"));
        expect(overrideLine).toBeDefined();
        const quoted = overrideLine?.slice(overrideLine.indexOf(":") + 1).trim() ?? "";
        expect(JSON.parse(quoted)).toBe("file:" + tarball);
        expect(text).toContain("allowBuilds:");
    } finally {
        rmSync(consumer, { recursive: true, force: true });
    }
});
