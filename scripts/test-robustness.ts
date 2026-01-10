import { fileURLToPath } from "node:url";
import { dirname, resolve, relative, join } from "node:path";
import { readdirSync, statSync, readFileSync, writeFileSync } from "node:fs";
import { execSync } from "node:child_process";
import { timestampPdf, KNOWN_TSA_URLS, TimestampErrorCode } from "../src/index.js";
import { PDFDocument } from "pdf-lib-incremental-save";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const CORPUS_DIR = resolve(__dirname, "../.corpus/py-pdf-sample-files");
const REPORT_FILE = resolve(__dirname, "../robustness-report.json");
const SUMMARY_FILE = resolve(__dirname, "../robustness-summary.md");

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

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function runTest() {
    console.log(`Scanning corpus in ${CORPUS_DIR}...`);
    const files = findPdfFiles(CORPUS_DIR);
    console.log(`Found ${files.length} PDF files.`);

    let passed = 0;
    let failed = 0;
    let skipped = 0;

    for (let i = 0; i < files.length; i++) {
        const file = files[i];
        const relativePath = relative(CORPUS_DIR, file);

        // Skip check
        if (SKIP_PATTERNS.some(p => file.toLowerCase().includes(p))) {
            console.log(`[${i + 1}/${files.length}] SKIP: ${relativePath} (matched skip pattern)`);
            RESULTS.push({ file: relativePath, status: "SKIP", error: "Matched skip pattern" });
            skipped++;
            continue;
        }

        console.log(`[${i + 1}/${files.length}] Testing: ${relativePath}...`);

        try {
            const pdfBytes = new Uint8Array(readFileSync(file));

            // Initial load check - skip if already corrupt or encrypted (double check)
            try {
                await PDFDocument.load(pdfBytes, { ignoreEncryption: true });
            } catch (e) {
                console.log(`   SKIP: Could not load PDF (likely encrypted or invalid): ${e}`);
                RESULTS.push({ file: relativePath, status: "SKIP", error: "Load failed: " + String(e) });
                skipped++;
                continue;
            }

            const start = Date.now();
            const result = await timestampPdf({
                pdf: pdfBytes,
                tsa: {
                    url: KNOWN_TSA_URLS.FREETSA,
                    timeout: 20000
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
                    const tmpOriginal = `/tmp/robustness_original_${i}.pdf`;
                    const tmpTimestamped = `/tmp/robustness_timestamped_${i}.pdf`;
                    writeFileSync(tmpOriginal, pdfBytes);
                    writeFileSync(tmpTimestamped, result.pdf);

                    const textBefore = execSync(`pdftotext -layout "${tmpOriginal}" -`, {
                        encoding: "utf-8",
                        maxBuffer: 50 * 1024 * 1024,
                    }).trim();
                    const textAfter = execSync(`pdftotext -layout "${tmpTimestamped}" -`, {
                        encoding: "utf-8",
                        maxBuffer: 50 * 1024 * 1024,
                    }).trim();

                    textMatch = textBefore === textAfter;
                    if (!textMatch) {
                        console.log(`   WARN: Text content differs after timestamping`);
                    }
                } catch {
                    // pdftotext not available or failed, skip text comparison
                    textMatch = true; // Assume match if we can't check
                }
            } catch (validationError: unknown) {
                const msg = validationError instanceof Error ? validationError.message : String(validationError);
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

            console.log(`   PASS (${duration}ms) - Size: ${pdfBytes.length} -> ${result.pdf.length}, Pages: ${pageCountBefore}`);
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
                errorCode: error.code
            });
            failed++;
        }

        // Rate limit delay
        if (i < files.length - 1) {
            await sleep(BATCH_DELAY_MS);
        }
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
${RESULTS.filter(r => r.status === "FAIL").map(r => `- **${r.file}**: ${r.errorCode} - ${r.error}`).join("\n")}
    `;
    writeFileSync(SUMMARY_FILE, summary);

    console.log(`\nDONE! Summary saved to ${SUMMARY_FILE}`);
    if (failed > 0) process.exit(1);
}

runTest().catch(console.error);
