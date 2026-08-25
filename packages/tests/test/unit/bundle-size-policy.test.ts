import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const TEST_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(TEST_DIRECTORY, "../../../..");

describe("core bundle size policy", () => {
    it("keeps the documented 225 KiB ESM ceiling and its rationale", () => {
        const workflow = readFileSync(
            resolve(REPOSITORY_ROOT, ".github/workflows/size.yml"),
            "utf8"
        );

        expect(workflow).toContain("Enforce ESM bundle size budget (<= 225 KiB)");
        expect(workflow).toMatch(/\bMAX=230400\b/);
        expect(workflow).toContain("ESM bundle exceeds 225 KiB (230400 bytes) budget");
    });
});
