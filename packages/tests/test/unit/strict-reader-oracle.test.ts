import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
    archiveTimestamp,
    timestampPdf,
    timestampPdfMultiple,
    TimestampSession,
} from "pdf-rfc3161";
import { afterEach, describe, expect, it, vi } from "vitest";
import { qpdfLinearizedBasePdf } from "../fixtures/qpdf-linearized-base.js";
import { createRFC3161TokenFixtureFromRequest } from "../fixtures/rfc3161-token.js";
import { appendClassicTableRevision } from "../utils/incremental-revision.js";
import { makeInput, stubTsaFetch } from "../utils/timestamp-fixtures.js";
import { xrefSectionFormats } from "../utils/xref-format.js";

// PR#63 follow-up: the macOS Preview regression (a classic xref table whose
// /Prev pointed into a cross-reference stream) shipped because no CI job
// parsed our output with a strict, non-repairing PDF reader. Ghostscript is
// such a reader and runs on Linux, so it stands in for CoreGraphics on every
// push. The byte-level format assertions live in incremental-xref-format.test.ts;
// this suite is the independent oracle that catches structural damage of any
// kind, not only the one shape we already know about.

const GHOSTSCRIPT_TIMEOUT_MS = 30_000;

function ghostscriptAvailable(): boolean {
    const probe = spawnSync("gs", ["--version"], {
        encoding: "utf8",
        timeout: GHOSTSCRIPT_TIMEOUT_MS,
    });
    return probe.error === undefined && probe.status === 0;
}

const GHOSTSCRIPT_AVAILABLE = ghostscriptAvailable();

// Silence is the failure mode this suite exists to prevent, so it must never
// self-skip on a machine that is supposed to run it. Every CI job that runs
// `pnpm test` installs ghostscript (ci.yml and release.yml alike); if one ever
// stops, this throws at collection instead of reporting a quiet "skipped",
// mirroring the corpus-robustness convention that an all-skipped run fails.
// Developer machines without gs keep the skip.
if (!GHOSTSCRIPT_AVAILABLE && (process.env.CI ?? "") !== "") {
    throw new Error(
        "ghostscript is required in CI: the strict-reader oracle is the only job that parses " +
            "our output with a non-repairing PDF reader, and skipping it silently would hide " +
            "the PR#63 class of regression. Install it (apt-get install -y ghostscript) or " +
            "remove the CI environment variable to run without the oracle."
    );
}

const decoder = new TextDecoder("latin1");

/**
 * Appends more comment bytes than the sniffer's MAX_PDF_TAIL_SCAN window (2048)
 * after the file's final %%EOF, hiding the terminal `startxref` from it. Every
 * byte is a PDF comment, so readers that scan the whole file for the trailer
 * still find it and the document itself is unchanged.
 */
function padPastTailScan(input: Uint8Array): Uint8Array {
    const padding = new TextEncoder().encode(`\n${"%".repeat(2500)}\n`);
    const output = new Uint8Array(input.length + padding.length);
    output.set(input);
    output.set(padding, input.length);
    return output;
}

const temporaryDirectories: string[] = [];

afterEach(() => {
    vi.unstubAllGlobals();
    for (const directory of temporaryDirectories.splice(0)) {
        rmSync(directory, { force: true, recursive: true });
    }
});

function writeTemporaryPdf(name: string, bytes: Uint8Array): string {
    const directory = mkdtempSync(join(tmpdir(), "pdf-rfc3161-gs-"));
    temporaryDirectories.push(directory);
    const path = join(directory, name);
    writeFileSync(path, bytes);
    return path;
}

interface GhostscriptRun {
    status: number | null;
    output: string;
}

/**
 * Renders one PDF to the null device. `strict` adds -dPDFSTOPONERROR, which
 * turns a structural problem into a nonzero exit instead of a silent repair.
 */
function runGhostscript(path: string, strict: boolean): GhostscriptRun {
    const args = ["-dNOPAUSE", "-dBATCH", "-sDEVICE=nullpage"];
    if (strict) args.push("-dPDFSTOPONERROR");
    args.push(path);
    const result = spawnSync("gs", args, {
        encoding: "utf8",
        timeout: GHOSTSCRIPT_TIMEOUT_MS,
    });
    expect(result.error).toBeUndefined();
    return {
        status: result.status,
        output: [result.stdout, result.stderr].filter((value) => value.length > 0).join("\n"),
    };
}

function commandFailure(label: string, run: GhostscriptRun): string {
    return [`ghostscript (${label}) exited with ${String(run.status)}`, run.output]
        .filter((value) => value.length > 0)
        .join("\n");
}

/**
 * Asserts that a strict, non-repairing reader accepts the bytes as they are:
 * strict mode must exit 0, and the lenient run must not report a repair.
 * Ghostscript sometimes rebuilds a broken xref quietly, so the second check is
 * what catches damage the first one papers over.
 */
function expectGhostscriptAccepts(name: string, bytes: Uint8Array): void {
    const path = writeTemporaryPdf(name, bytes);

    const strict = runGhostscript(path, true);
    expect(strict.status, commandFailure("strict", strict)).toBe(0);
    expect(strict.output, commandFailure("strict", strict)).toContain("Page 2");

    const lenient = runGhostscript(path, false);
    expect(lenient.status, commandFailure("lenient", lenient)).toBe(0);
    expect(lenient.output.toLowerCase(), commandFailure("lenient", lenient)).not.toContain(
        "repair"
    );
}

/**
 * Collects one run's complaint lines: the tab-indented items ghostscript
 * lists under "The following errors/warnings were encountered at least once
 * while processing this file", plus its `**** ...` summary banner.
 *
 * Only these lines carry a verdict about the file. Everything else in the
 * output is environment-dependent (version banner, page progress, the
 * absolute path of a substituted font), so keeping the set this narrow is
 * what makes a differential between two runs stable across gs builds.
 * String scanning rather than a regex: no pattern, bounded or otherwise, is
 * needed to split lines and test two prefixes.
 *
 * The one `****` pair that is excluded is the "The file was produced by:
 * >>>> ... <<<<" attribution gs appends to that summary. It quotes the
 * document's /Producer string rather than diagnosing anything, so it differs
 * between an input and its timestamped output purely because the output
 * carries producer metadata -- which would make every differential report a
 * phantom regression. Dropping it cannot blunt the negative controls: the
 * attribution is only ever printed inside the "this file had errors" summary,
 * whose own line stays in the set.
 */
function ghostscriptComplaints(output: string): Set<string> {
    const complaints = new Set<string>();
    for (const rawLine of output.split("\n")) {
        const line = rawLine.trim().toLowerCase();
        if (line.startsWith("****")) {
            const complaint = line.slice(4).trim();
            if (complaint.startsWith("the file was produced by") || complaint.startsWith(">>>>")) {
                continue;
            }
            complaints.add(complaint);
        } else if (rawLine.startsWith("\t") && line.length > 0) {
            complaints.add(line);
        }
    }
    return complaints;
}

/**
 * The "never worse" differential the hybrid-history cases share.
 *
 * expectGhostscriptAccepts does not fit an input that is already defective:
 * a classic-table revision whose /Prev points into a cross-reference stream
 * makes ghostscript repair the INPUT and fail strict mode on it, and nothing
 * an incremental update appends can undo that. What timestamping must
 * guarantee for such a file is only that it never makes matters worse, so
 * require the baseline to render every page, then require the output to
 * render every page too and to raise no complaint the input did not already
 * raise. A new complaint or a lost page is the regression.
 */
function expectGhostscriptNoWorse(name: string, input: Uint8Array, output: Uint8Array): void {
    const baseline = runGhostscript(writeTemporaryPdf(`${name}-base.pdf`, input), false);
    expect(baseline.status, commandFailure("baseline", baseline)).toBe(0);
    expect(baseline.output, commandFailure("baseline", baseline)).toContain("Page 2");

    const lenient = runGhostscript(writeTemporaryPdf(`${name}.pdf`, output), false);
    expect(lenient.status, commandFailure("lenient", lenient)).toBe(0);
    expect(lenient.output, commandFailure("lenient", lenient)).toContain("Page 2");
    const accepted = ghostscriptComplaints(baseline.output);
    const added = [...ghostscriptComplaints(lenient.output)].filter(
        (complaint) => !accepted.has(complaint)
    );
    expect(added, commandFailure("lenient", lenient)).toEqual([]);
}

/**
 * The negative-control counterpart of expectGhostscriptAccepts: asserts that
 * damaged bytes trip at least one of that helper's two signals, without
 * pinning which one.
 *
 * Which one fires is ghostscript-version dependent. 10.06 exits nonzero in
 * strict mode for a classic xref table whose /Prev points into a
 * cross-reference stream; 10.02.1 (ubuntu CI) does not stop on an xref repair
 * at all under -dPDFSTOPONERROR -- it renders every page and exits 0 while
 * still listing "xref table was repaired" among its errors. An exit-code-only
 * control therefore passes on one version and fails on the other.
 *
 * What the oracle actually guarantees is the disjunction: acceptance requires
 * a clean strict exit AND a complaint-free run, so damage is detected when
 * either half fails. Assert exactly that, and do not "simplify" it back to an
 * exit-code check. Returns the two runs' combined output, lowercased, so a
 * caller can additionally pin a message both versions are known to print.
 */
function expectGhostscriptDetectsDamage(name: string, bytes: Uint8Array): string {
    const path = writeTemporaryPdf(name, bytes);
    const strict = runGhostscript(path, true);
    const lenient = runGhostscript(path, false);
    const combined = `${strict.output}\n${lenient.output}`.toLowerCase();
    const detail = [commandFailure("strict", strict), commandFailure("lenient", lenient)].join(
        "\n"
    );

    // Mirror both halves of the acceptance criterion: a complaint is either a
    // line of ghostscript's error/warning summary or the bare word the
    // positive helper blocks, whichever spelling a version happens to use.
    const complained = ghostscriptComplaints(combined).size > 0 || combined.includes("repair");
    expect(strict.status !== 0 || complained, detail).toBe(true);
    return combined;
}

describe.runIf(GHOSTSCRIPT_AVAILABLE)("strict-reader (ghostscript) oracle", () => {
    it("accepts a no-LTV timestamp appended to an xref-stream input", async () => {
        stubTsaFetch();
        const result = await timestampPdf({
            pdf: await makeInput(true),
            tsa: { url: "https://timestamp.example.test", retry: 0 },
            enableLTV: false,
        });

        expectGhostscriptAccepts("stream-no-ltv.pdf", result.pdf);
    });

    it("accepts an LTV timestamp appended to an xref-stream input", async () => {
        stubTsaFetch();
        const result = await timestampPdf({
            pdf: await makeInput(true),
            tsa: { url: "https://timestamp.example.test", retry: 0 },
            enableLTV: true,
        });

        expect(result.ltvData?.certificates).toHaveLength(1);
        expectGhostscriptAccepts("stream-ltv.pdf", result.pdf);
    });

    it("accepts an LTV timestamp appended to a classic-table input", async () => {
        stubTsaFetch();
        const result = await timestampPdf({
            pdf: await makeInput(false),
            tsa: { url: "https://timestamp.example.test", retry: 0 },
            enableLTV: true,
        });

        expect(result.ltvData?.certificates).toHaveLength(1);
        expectGhostscriptAccepts("table-ltv.pdf", result.pdf);
    });

    it("accepts a re-timestamped xref-stream input", async () => {
        stubTsaFetch();
        const tsa = { url: "https://timestamp.example.test", retry: 0 };
        const first = await timestampPdf({ pdf: await makeInput(true), tsa, enableLTV: false });
        const second = await timestampPdf({ pdf: first.pdf, tsa, enableLTV: false });

        expectGhostscriptAccepts("stream-retimestamped.pdf", second.pdf);
    });

    // Review finding M3: the archive (document-timestamp renewal) path had no
    // xref-stream-input coverage at all, and it writes two extra revisions
    // (the global DSS update plus the renewal timestamp).
    it("accepts an archive renewal built from an xref-stream input", async () => {
        stubTsaFetch();
        const tsa = { url: "https://timestamp.example.test", retry: 0 };
        const timestamped = await timestampPdf({
            pdf: await makeInput(true),
            tsa,
            enableLTV: true,
        });
        const renewed = await archiveTimestamp({ pdf: timestamped.pdf, tsa });

        expectGhostscriptAccepts("stream-archive.pdf", renewed.pdf);
    });

    it("accepts a timestamp embedded through the step-by-step TimestampSession", async () => {
        const session = new TimestampSession(await makeInput(true), { enableLTV: true });
        const request = await session.createTimestampRequest();
        const fixture = await createRFC3161TokenFixtureFromRequest(request, { form: "response" });
        const output = await session.embedTimestampToken(fixture.response);

        expectGhostscriptAccepts("stream-session-ltv.pdf", output);
    });

    it("accepts a two-TSA timestampPdfMultiple result", async () => {
        stubTsaFetch();
        const result = await timestampPdfMultiple({
            pdf: await makeInput(true),
            tsaList: [
                { url: "https://timestamp-a.example.test", retry: 0 },
                { url: "https://timestamp-b.example.test", retry: 0 },
            ],
            enableLTV: false,
        });

        expect(result.timestamps).toHaveLength(2);
        expectGhostscriptAccepts("stream-multiple.pdf", result.pdf);
    });

    it("accepts an LTV timestamp appended to a qpdf-linearized input", async () => {
        stubTsaFetch();
        const input = qpdfLinearizedBasePdf();
        const result = await timestampPdf({
            pdf: input,
            tsa: { url: "https://timestamp.example.test", retry: 0 },
            enableLTV: true,
        });

        // expectGhostscriptAccepts does not fit this input: the pinned qpdf
        // fixture draws with a font resource some ghostscript builds cannot
        // resolve, so the untimestamped base may already draw a repair notice
        // of its own, and it has one page rather than two. Run the base first
        // and require the timestamped output to be no worse than it: strict
        // acceptance, plus no complaint the base did not already make. That
        // differential catches any new repair timestamping introduces, not
        // just the xref message the pre-fix shape happens to produce, and it
        // holds whether or not this machine's gs resolves that font.
        const baseline = runGhostscript(writeTemporaryPdf("linearized-base.pdf", input), false);
        expect(baseline.status, commandFailure("baseline", baseline)).toBe(0);
        expect(baseline.output.toLowerCase(), commandFailure("baseline", baseline)).not.toContain(
            "xref table was repaired"
        );

        const path = writeTemporaryPdf("linearized-ltv.pdf", result.pdf);
        const strict = runGhostscript(path, true);
        expect(strict.status, commandFailure("strict", strict)).toBe(0);
        expect(strict.output, commandFailure("strict", strict)).toContain("Page 1");

        const lenient = runGhostscript(path, false);
        expect(lenient.status, commandFailure("lenient", lenient)).toBe(0);
        const accepted = ghostscriptComplaints(baseline.output);
        const added = [...ghostscriptComplaints(lenient.output)].filter(
            (complaint) => !accepted.has(complaint)
        );
        expect(added, commandFailure("lenient", lenient)).toEqual([]);
    });

    it("does not degrade a hybrid-history input", async () => {
        stubTsaFetch();
        // An xref-stream base carrying a classic-table revision on top: the
        // shape v0.2.0 itself produced, and therefore the shape a re-timestamp
        // of our own older output has to survive.
        const input = appendClassicTableRevision(await makeInput(true));
        const result = await timestampPdf({
            pdf: input,
            tsa: { url: "https://timestamp.example.test", retry: 0 },
            enableLTV: false,
        });

        // The input's own middle revision is a classic table whose /Prev
        // points into a cross-reference stream, so it is already defective;
        // see expectGhostscriptNoWorse for why that rules out acceptance.
        // Before the fix the appended section was a stream whose /Prev pointed
        // at a table, and ghostscript went from repairing the input to
        // "Couldn't initialise file" with zero pages -- exactly the
        // degradation this pins.
        expectGhostscriptNoWorse("hybrid-no-ltv", input, result.pdf);
    });

    it("does not degrade a hybrid-history input whose tail hides the startxref", async () => {
        stubTsaFetch();
        // The same hybrid history, but with 2500 bytes of comment padding
        // after the final %%EOF. That pushes the terminal `startxref` outside
        // the sniffer's 2 KiB tail window, so it cannot classify the last
        // revision and has to stand down -- assert that precondition rather
        // than trusting it, because a wider window would silently turn this
        // into a duplicate of the case above.
        const input = padPastTailScan(appendClassicTableRevision(await makeInput(true)));
        expect(xrefSectionFormats(input)).toEqual(["stream", "table"]);
        expect(decoder.decode(input.subarray(input.length - 2048))).not.toContain("startxref");

        const result = await timestampPdf({
            pdf: input,
            tsa: { url: "https://timestamp.example.test", retry: 0 },
            enableLTV: false,
        });

        // Standing down must mean the classic table, not "keep whatever
        // pdf-lib decided". pdf-lib sets useObjectStreams for ANY xref stream
        // in the file's history, so leaving the flag alone appended a stream
        // over a classic table here: the inverse of the shape this release
        // removes, and worse than v0.2.0, which appended a table. Ghostscript
        // went from rendering both pages (with the input's own repair notice)
        // to "Couldn't initialise file" and no pages at all.
        expect(xrefSectionFormats(result.pdf)).toEqual(["stream", "table", "table"]);
        expectGhostscriptNoWorse("hybrid-padded-no-ltv", input, result.pdf);
    });

    describe("negative controls", () => {
        it("rejects the pre-fix classic-table-over-xref-stream shape", async () => {
            stubTsaFetch();
            const result = await timestampPdf({
                pdf: await makeInput(true),
                tsa: { url: "https://timestamp.example.test", retry: 0 },
                enableLTV: false,
            });
            // A classic table whose /Prev points into a cross-reference
            // stream: exactly what CoreGraphics rejected, and the control
            // proving both assertions in expectGhostscriptAccepts have teeth.
            // Without it, a helper that silently accepted everything would
            // look just as green.
            const broken = appendClassicTableRevision(result.pdf);

            const output = expectGhostscriptDetectsDamage("pre-fix-shape.pdf", broken);
            // Both 10.02.1 and 10.06 diagnose this specific shape as a
            // repaired xref, so the control can pin the message as well as
            // the disjunction -- 10.02.1 prints it from the strict run it
            // does not stop, 10.06 from the lenient one.
            expect(output).toContain("xref table was repaired");
        });

        it("rejects a truncated PDF", async () => {
            stubTsaFetch();
            const result = await timestampPdf({
                pdf: await makeInput(true),
                tsa: { url: "https://timestamp.example.test", retry: 0 },
                enableLTV: false,
            });
            const truncated = result.pdf.subarray(0, result.pdf.length - 64);

            // Truncation trips the strict exit on both known versions, but
            // assert through the same disjunction as the shape control: which
            // signal a given ghostscript raises is its business, not a
            // property of this project.
            expectGhostscriptDetectsDamage("truncated.pdf", truncated);
        });
    });
});
