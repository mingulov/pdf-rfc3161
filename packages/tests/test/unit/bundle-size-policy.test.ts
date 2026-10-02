import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const TEST_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = resolve(TEST_DIRECTORY, "../../../..");

describe("core bundle size policy", () => {
    it("keeps the documented 249 KiB ESM ceiling and its rationale", () => {
        const workflow = readFileSync(
            resolve(REPOSITORY_ROOT, ".github/workflows/size.yml"),
            "utf8"
        );

        expect(workflow).toContain("Enforce ESM bundle size budget (<= 249 KiB)");
        expect(workflow).toMatch(/\bMAX=254976\b/);
        expect(workflow).toContain("ESM bundle exceeds 249 KiB (254976 bytes) budget");
    });
});
