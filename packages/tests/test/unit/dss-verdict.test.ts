import { describe, expect, it } from "vitest";
import {
    type DssCaseExpectation,
    assertDssCase,
    parseDssOutput,
} from "../utils/dss-verdict.js";

describe("dss oracle verdict contract", () => {
    const WIRE_REPORT = {
        tool: "dss-oracle",
        dss: "6.2",
        pdf: "/tmp/work/dss-basic.pdf",
        signatures: [],
        timestamps: [{ id: "T-abc123", indication: "PASSED" }],
    };

    it("parses a well-formed oracle report", () => {
        const report = parseDssOutput(JSON.stringify(WIRE_REPORT));
        expect(report.timestamps).toHaveLength(1);
        expect(report.timestamps[0]?.indication).toBe("PASSED");
        expect(report.dss).toBe("6.2");
    });

    it("rejects malformed oracle output", () => {
        expect(() => parseDssOutput("not json")).toThrow(/dss oracle/i);
    });

    it("rejects a contract mismatch", () => {
        const wrong = { ...WIRE_REPORT, tool: "something-else" };
        expect(() => parseDssOutput(JSON.stringify(wrong))).toThrow(/contract/i);
    });

    it("accepts an unsigned case with zero timestamps", () => {
        const report = parseDssOutput(
            JSON.stringify({ ...WIRE_REPORT, signatures: [], timestamps: [] })
        );
        const expectation: DssCaseExpectation = { signatures: 0, timestamps: [] };
        expect(() => assertDssCase(report, expectation)).not.toThrow();
    });

    it("rejects an unsigned case that reports timestamps", () => {
        const report = parseDssOutput(JSON.stringify(WIRE_REPORT));
        const expectation: DssCaseExpectation = { signatures: 0, timestamps: [] };
        expect(() => assertDssCase(report, expectation)).toThrow(/unsigned/i);
    });

    it("accepts a timestamped case with the expected indication", () => {
        const report = parseDssOutput(JSON.stringify(WIRE_REPORT));
        const expectation: DssCaseExpectation = {
            signatures: 0,
            timestamps: [{ indication: "PASSED" }],
        };
        expect(() => assertDssCase(report, expectation)).not.toThrow();
    });

    it("rejects a timestamped case with an unexpected indication", () => {
        const report = parseDssOutput(JSON.stringify(WIRE_REPORT));
        const expectation: DssCaseExpectation = {
            signatures: 0,
            timestamps: [{ indication: "FAILED" }],
        };
        expect(() => assertDssCase(report, expectation)).toThrow(/indication/i);
    });

    it("rejects a signed case with zero timestamps", () => {
        const report = parseDssOutput(
            JSON.stringify({ ...WIRE_REPORT, signatures: [], timestamps: [] })
        );
        const expectation: DssCaseExpectation = {
            signatures: 0,
            timestamps: [{ indication: "PASSED" }],
        };
        expect(() => assertDssCase(report, expectation)).toThrow(/no timestamp/i);
    });

    it("rejects a case with an unexpected timestamp count", () => {
        const report = parseDssOutput(JSON.stringify(WIRE_REPORT));
        const expectation: DssCaseExpectation = {
            signatures: 0,
            timestamps: [{ indication: "PASSED" }, { indication: "PASSED" }],
        };
        expect(() => assertDssCase(report, expectation)).toThrow(/count/i);
    });
});
