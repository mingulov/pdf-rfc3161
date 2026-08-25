import { win32 } from "node:path";
import { describe, expect, it } from "vitest";
import { isPathWithinRoot, type PathOperations } from "../../scripts/packed-consumer-path";

const windowsPathOperations: PathOperations = {
    isAbsolute: win32.isAbsolute,
    relative: win32.relative,
    sep: win32.sep,
};

describe("packed consumer package path checks", () => {
    it("accepts the package root and descendants", () => {
        expect(
            isPathWithinRoot("/tmp/consumer/node_modules/pdf-rfc3161", "/tmp/consumer/node_modules/pdf-rfc3161")
        ).toBe(true);
        expect(
            isPathWithinRoot(
                "/tmp/consumer/node_modules/pdf-rfc3161",
                "/tmp/consumer/node_modules/pdf-rfc3161/dist/index.js"
            )
        ).toBe(true);
    });

    it("rejects sibling and parent paths", () => {
        expect(
            isPathWithinRoot("/tmp/consumer/node_modules/pdf-rfc3161", "/tmp/consumer/node_modules/other")
        ).toBe(false);
        expect(
            isPathWithinRoot(
                "/tmp/consumer/node_modules/pdf-rfc3161",
                "/tmp/consumer/node_modules/pdf-rfc3161/../other"
            )
        ).toBe(false);
    });

    it("handles Windows-shaped paths through the platform operations explicitly", () => {
        expect(
            isPathWithinRoot(
                "C:\\consumer\\node_modules\\pdf-rfc3161",
                "C:\\consumer\\node_modules\\pdf-rfc3161\\dist\\index.js",
                windowsPathOperations
            )
        ).toBe(true);
        expect(
            isPathWithinRoot(
                "C:\\consumer\\node_modules\\pdf-rfc3161",
                "C:\\consumer\\node_modules\\other",
                windowsPathOperations
            )
        ).toBe(false);
    });
});
