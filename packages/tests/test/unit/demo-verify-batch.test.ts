import { beforeEach, describe, expect, it, vi } from "vitest";
import { fileURLToPath } from "node:url";

const mocks = vi.hoisted(() => ({
    setState: vi.fn(),
    extractTimestamps: vi.fn(),
    verifyTimestamp: vi.fn(),
    verifyPdfTimestamps: vi.fn(),
    getDSSInfo: vi.fn(),
    extractLTVData: vi.fn(),
    useStateSeeds: [] as unknown[],
}));

vi.mock("../../../demo/node_modules/react/index.js", async (importOriginal) => ({
    ...await importOriginal<Record<string, unknown>>(),
    // Exercise the real event handlers without needing a browser renderer.
    // Tests may queue useStateSeeds to render with pre-set state instead.
    useState: (initial: unknown) => [
        mocks.useStateSeeds.length > 0 ? mocks.useStateSeeds.shift() : initial,
        mocks.setState,
    ],
}));

vi.mock("pdf-rfc3161", () => ({
    extractTimestamps: mocks.extractTimestamps,
    verifyTimestamp: mocks.verifyTimestamp,
    verifyPdfTimestamps: mocks.verifyPdfTimestamps,
    validateTimestampTokenRFC8933Compliance: vi.fn(),
}));

vi.mock("pdf-rfc3161/internals", () => ({
    getDSSInfo: mocks.getDSSInfo,
    extractLTVData: mocks.extractLTVData,
}));

interface ElementShape {
    props?: { children?: unknown; onFileSelect?: (file: File) => void };
}

function findFileSelect(value: unknown): ((file: File) => void) | undefined {
    if (Array.isArray(value)) {
        for (const child of value) {
            const handler = findFileSelect(child);
            if (handler) return handler;
        }
        return undefined;
    }
    if (value === null || typeof value !== "object") return undefined;
    const element = value as ElementShape;
    return element.props?.onFileSelect ?? findFileSelect(element.props?.children);
}

describe("demo PDF-level bounded verification", () => {
    const timestamp = {
        verified: false,
        verificationError: "Aggregate verification budget exceeded",
        info: { genTime: new Date("2026-01-01"), policy: "1.2.3" },
        token: Uint8Array.of(0x30, 0),
    };

    beforeEach(() => {
        vi.clearAllMocks();
        mocks.useStateSeeds.length = 0;
        mocks.extractTimestamps.mockResolvedValue([timestamp]);
        mocks.verifyTimestamp.mockResolvedValue(timestamp);
        mocks.verifyPdfTimestamps.mockResolvedValue([timestamp]);
        mocks.getDSSInfo.mockResolvedValue(null);
        mocks.extractLTVData.mockReturnValue({ certificates: [] });
    });

    it.each(["VerifyPanel", "ValidatorPanel"])(
        "%s uses one bounded batch and preserves invalid results",
        async (name) => {
            // Runtime import lets Vite use the component's own JSX tsconfig;
            // the Node tests themselves do not need a JSX compiler setting.
            const componentPath = fileURLToPath(
                new URL(`../../../demo/src/components/${name}.tsx`, import.meta.url)
            );
            const component = await import(componentPath) as { default: () => ElementShape };
            const handler = findFileSelect(component.default());
            expect(handler).toBeTypeOf("function");
            handler!(new File([Uint8Array.of(1, 2, 3)], "input.pdf"));

            await vi.waitFor(() => {
                expect(mocks.verifyPdfTimestamps).toHaveBeenCalledTimes(1);
                if (name === "ValidatorPanel") {
                    expect(mocks.setState).toHaveBeenCalledWith([
                        expect.objectContaining({
                            isValid: false,
                            errors: [timestamp.verificationError],
                            info: timestamp.info,
                        }),
                    ]);
                } else {
                    expect(mocks.setState).toHaveBeenCalledWith([timestamp]);
                }
            });
            expect(mocks.extractTimestamps).not.toHaveBeenCalled();
            expect(mocks.verifyTimestamp).not.toHaveBeenCalled();
            if (name === "ValidatorPanel") {
                expect(mocks.verifyPdfTimestamps).toHaveBeenCalledWith(
                    Uint8Array.of(1, 2, 3), { strictESSValidation: false }
                );
            } else {
                expect(mocks.verifyPdfTimestamps).toHaveBeenCalledWith(Uint8Array.of(1, 2, 3));
            }
        }
    );
});

describe("demo trust presentation", () => {
    function collectText(value: unknown, out: string[]): void {
        if (typeof value === "string") {
            out.push(value);
            return;
        }
        if (typeof value === "number" || typeof value === "boolean") {
            return;
        }
        if (Array.isArray(value)) {
            for (const child of value) collectText(child, out);
            return;
        }
        if (value === null || typeof value !== "object") return;
        const element = value as ElementShape;
        collectText(element.props?.children, out);
    }

    it("ValidatorPanel pairs every result card with a trust disclaimer and a Signer label", async () => {
        const makeResult = (isValid: boolean) => ({
            isValid,
            info: {
                genTime: new Date("2026-01-01"),
                hashAlgorithm: "SHA-256",
                policy: "1.2.3",
                serialNumber: "42",
            },
            chain: [{ subject: "CN=Example TSA", issuer: "CN=Root", serial: "01" }],
            errors: isValid ? undefined : ["boom"],
        });
        // ValidatorPanel useState order: file, isValidating, results, dssInfo.
        mocks.useStateSeeds.push(
            new File([Uint8Array.of(1, 2, 3)], "input.pdf"),
            false,
            [makeResult(true), makeResult(false)],
            null
        );
        const componentPath = fileURLToPath(
            new URL("../../../demo/src/components/ValidatorPanel.tsx", import.meta.url)
        );
        const component = await import(componentPath) as { default: () => ElementShape };
        const texts: string[] = [];
        collectText(component.default(), texts);

        const disclaimers = texts.filter((t) => t.includes("TSA trust NOT EVALUATED"));
        expect(disclaimers).toHaveLength(2);
        expect(texts).toContain("Signer:");
        expect(texts).not.toContain("TSA:");
    });
});
