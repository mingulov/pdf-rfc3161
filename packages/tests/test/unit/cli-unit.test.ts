import { describe, it, expect, beforeAll } from "vitest";

// Prevent program.parse() side-effect during import.
beforeAll(() => {
    process.env.CLI_TEST_MODE = "true";
});

describe("CLI smoke test", () => {
    it("registers the expected top-level commands", async () => {
        const { program } = await import("../../../cli/src/cli");

        const names = program.commands.map((c) => c.name()).sort();
        expect(names).toEqual(["archive", "timestamp", "verify"]);
    });

    it("help output includes program name and key commands", async () => {
        const { program } = await import("../../../cli/src/cli");

        const help = program.helpInformation();
        expect(help).toContain("Usage:");
        expect(help).toContain("pdf-rfc3161");
        expect(help).toContain("timestamp");
        expect(help).toContain("archive");
        expect(help).toContain("verify");
    });

    it("timestamp command exposes --algorithm with SHA-256 default", async () => {
        const { program } = await import("../../../cli/src/cli");

        const cmd = program.commands.find((c) => c.name() === "timestamp");
        expect(cmd).toBeDefined();
        const help = cmd!.helpInformation();
        expect(help).toContain("--algorithm");
        expect(help).toContain("SHA-256");
        // 0.2.0: `--ltv` opt-in renamed to `--no-ltv` opt-out (audit C3).
        expect(help).toContain("--no-ltv");
        expect(help).toContain("--timeout");
    });

    it("verify command exposes --rfc8933 flag", async () => {
        const { program } = await import("../../../cli/src/cli");

        const cmd = program.commands.find((c) => c.name() === "verify");
        expect(cmd).toBeDefined();
        const help = cmd!.helpInformation();
        expect(help).toContain("--rfc8933");
    });

    it("archive command exposes --name option with default", async () => {
        const { program } = await import("../../../cli/src/cli");

        const cmd = program.commands.find((c) => c.name() === "archive");
        expect(cmd).toBeDefined();
        const help = cmd!.helpInformation();
        expect(help).toContain("--name");
        expect(help).toContain("ArchiveTimestamp");
    });

});
