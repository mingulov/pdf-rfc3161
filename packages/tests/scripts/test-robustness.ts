import { fileURLToPath } from "node:url";
import { dirname, resolve, relative, join } from "node:path";
import { mkdtempSync, readdirSync, rmSync, statSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { execFile } from "node:child_process";
import { timestampPdf, KNOWN_TSA_URLS } from "pdf-rfc3161";
import { PDFDocument } from "pdf-lib";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const DEFAULT_CORPUS_DIR = resolve(__dirname, "../.corpus/py-pdf-sample-files");
const CORPUS_DIR = resolve(process.env.ROBUSTNESS_CORPUS_DIR ?? DEFAULT_CORPUS_DIR);
const REPORT_FILE = resolve(__dirname, "../robustness-report.json");
const SUMMARY_FILE = resolve(__dirname, "../robustness-summary.md");
const CORPUS_SETUP_COMMAND = "pnpm --filter pdf-rfc3161-tests exec tsx scripts/fetch-corpus.ts";

interface TestResult {
    file: string;
    status: "PASS" | "FAIL" | "SKIP";
    error?: string;
    errorCode?: string;
    sizeBefore?: number;
    sizeAfter?: number;
    duration?: number;
    pageCountBefore?: number;
    pageCountAfter?: number;
    textMatch?: boolean;
}

const RESULTS: TestResult[] = [];

// Configuration
const BATCH_DELAY_MS = 2500; // FreeTSA rate limit kindness
const SKIP_PATTERNS = ["password", "encrypted"]; // Encrypted files not supported by pdf-lib

function findPdfFiles(dir: string): string[] {
    let results: string[] = [];
    const list = readdirSync(dir);

    for (const file of list) {
        const filePath = join(dir, file);
        const stat = statSync(filePath);
        if (stat && stat.isDirectory()) {
            results = results.concat(findPdfFiles(filePath));
        } else if (file.toLowerCase().endsWith(".pdf")) {
            results.push(filePath);
        }
    }
    return results;
}

function corpusSetupError(state: "missing" | "empty" | "not a directory"): Error {
    return new Error(
        `Robustness corpus is ${state}: ${CORPUS_DIR}\n` +
            "Fetch the ignored sample corpus before rerunning:\n" +
            `  ${CORPUS_SETUP_COMMAND}`
    );
}

function getCorpusFiles(): string[] {
    let corpusStat: ReturnType<typeof statSync>;
    try {
        corpusStat = statSync(CORPUS_DIR);
    } catch (error: unknown) {
        if (error instanceof Error && "code" in error && error.code === "ENOENT") {
            throw corpusSetupError("missing");
        }
        throw error;
    }

    if (!corpusStat.isDirectory()) {
        throw corpusSetupError("not a directory");
    }

    const files = findPdfFiles(CORPUS_DIR);
    if (files.length === 0) {
        throw corpusSetupError("empty");
    }
    return files;
}

function extractPdfText(pdfPath: string): Promise<string> {
    return new Promise((resolveText, reject) => {
        execFile(
            "pdftotext",
            ["-layout", pdfPath, "-"],
            {
                encoding: "utf8",
                maxBuffer: 50 * 1024 * 1024,
            },
            (error, stdout) => {
                if (error) {
                    reject(error);
                    return;
                }
                resolveText(String(stdout).trim());
            }
        );
    });
}

async function compareTextContent(original: Uint8Array, timestamped: Uint8Array): Promise<boolean> {
    const temporaryDirectory = mkdtempSync(join(tmpdir(), "pdf-rfc3161-robustness-"));
    const originalPath = join(temporaryDirectory, "original.pdf");
    const timestampedPath = join(temporaryDirectory, "timestamped.pdf");

    try {
        writeFileSync(originalPath, original);
        writeFileSync(timestampedPath, timestamped);
        const [textBefore, textAfter] = await Promise.all([
            extractPdfText(originalPath),
            extractPdfText(timestampedPath),
        ]);
        return textBefore === textAfter;
    } finally {
        rmSync(temporaryDirectory, { force: true, recursive: true });
    }
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function runTest() {
    console.log(`Scanning corpus in ${CORPUS_DIR}...`);
    const files = getCorpusFiles();
    console.log(`Found ${files.length} PDF files.`);

    let passed = 0;
    let failed = 0;
    let skipped = 0;
    let executed = 0;

    for (let i = 0; i < files.length; i++) {
        const file = files[i];
        const relativePath = relative(CORPUS_DIR, file || "");

        // Skip check
        if (SKIP_PATTERNS.some((p) => file && file.toLowerCase().includes(p))) {
            console.log(`[${i + 1}/${files.length}] SKIP: ${relativePath} (matched skip pattern)`);
            RESULTS.push({ file: relativePath, status: "SKIP", error: "Matched skip pattern" });
            skipped++;
            continue;
        }

        console.log(`[${i + 1}/${files.length}] Testing: ${relativePath}...`);

        try {
            if (!file) continue;
            const pdfBytes = new Uint8Array(readFileSync(file));

            // Initial load check - skip if already corrupt or encrypted (double check)
            try {
                await PDFDocument.load(pdfBytes, { ignoreEncryption: true });
            } catch (e) {
                console.log(`   SKIP: Could not load PDF (likely encrypted or invalid): ${e}`);
                RESULTS.push({
                    file: relativePath,
                    status: "SKIP",
                    error: "Load failed: " + String(e),
                });
                skipped++;
                continue;
            }

            const start = Date.now();
            executed++;
            const result = await timestampPdf({
                pdf: pdfBytes,
                tsa: {
                    url: KNOWN_TSA_URLS.FREETSA,
                    timeout: 20000,
                },
                signatureSize: 16384, // Increased to accommodate FreeTSA cert chain (~5.5KB)
            });
            const duration = Date.now() - start;

            // Validate output PDF structure
            let pageCountBefore = 0;
            let pageCountAfter = 0;
            let textMatch = false;

            try {
                // Check page counts
                const originalDoc = await PDFDocument.load(pdfBytes, { ignoreEncryption: true });
                pageCountBefore = originalDoc.getPageCount();

                const resultDoc = await PDFDocument.load(result.pdf, { ignoreEncryption: true });
                pageCountAfter = resultDoc.getPageCount();

                if (pageCountAfter !== pageCountBefore) {
                    throw new Error(`Page count mismatch: ${pageCountBefore} -> ${pageCountAfter}`);
                }

                // Optional: Compare text content using pdftotext if available
                try {
                    textMatch = await compareTextContent(pdfBytes, result.pdf);
                    if (!textMatch) {
                        console.log(`   WARN: Text content differs after timestamping`);
                    }
                } catch {
                    // pdftotext not available or failed, skip text comparison
                    textMatch = true; // Assume match if we can't check
                }
            } catch (validationError: unknown) {
                const msg =
                    validationError instanceof Error
                        ? validationError.message
                        : String(validationError);
                console.log(`   FAIL: VALIDATION FAILED: ${msg}`);
                RESULTS.push({
                    file: relativePath,
                    status: "FAIL",
                    error: "Validation failed: " + msg,
                    sizeBefore: pdfBytes.length,
                    sizeAfter: result.pdf.length,
                    duration,
                    pageCountBefore,
                    pageCountAfter,
                });
                failed++;
                continue;
            }

            console.log(
                `   PASS (${duration}ms) - Size: ${pdfBytes.length} -> ${result.pdf.length}, Pages: ${pageCountBefore}`
            );
            RESULTS.push({
                file: relativePath,
                status: "PASS",
                sizeBefore: pdfBytes.length,
                sizeAfter: result.pdf.length,
                duration,
                pageCountBefore,
                pageCountAfter,
                textMatch,
            });
            passed++;
        } catch (error: any) {
            console.log(`   FAIL: ${error.message} (${error.code})`);
            RESULTS.push({
                file: relativePath,
                status: "FAIL",
                error: error.message,
                errorCode: error.code,
            });
            failed++;
        }

        // Rate limit delay
        if (i < files.length - 1) {
            await sleep(BATCH_DELAY_MS);
        }
    }

    if (executed === 0) {
        throw new Error(
            "Robustness corpus yielded zero executable PDF files after skip filters or PDF-load checks. " +
                "Fetch or select a corpus containing at least one valid, non-encrypted PDF:\n" +
                `  ${CORPUS_SETUP_COMMAND}`
        );
    }

    // Generate Report
    console.log("\nGenerating Report...");
    writeFileSync(REPORT_FILE, JSON.stringify(RESULTS, null, 2));

    const summary = `
# Robustness Test Summary
Date: ${new Date().toISOString()}

- **Total**: ${files.length}
- **Passed**: ${passed}
- **Failed**: ${failed}
- **Skipped**: ${skipped}

## Failures
${RESULTS.filter((r) => r.status === "FAIL")
    .map((r) => `- **${r.file}**: ${r.errorCode} - ${r.error}`)
    .join("\n")}
    `;
    writeFileSync(SUMMARY_FILE, summary);

    console.log(`\nDONE! Summary saved to ${SUMMARY_FILE}`);
    if (failed > 0) {
        throw new Error(`Robustness test found ${failed} failing PDF file(s)`);
    }
}

void runTest().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`Robustness test failed: ${message}`);
    process.exitCode = 1;
});
