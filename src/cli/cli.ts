/* eslint-disable no-console */
import { Command, Option } from "commander";
import { readFile, writeFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import {
    timestampPdf,
    extractTimestamps,
    verifyTimestamp,
    KNOWN_TSA_URLS,
    TimestampError,
} from "../index.js";
import type { HashAlgorithm } from "../types.js";

const VERSION = "0.1.0";

interface CliOptions {
    output?: string;
    algorithm: HashAlgorithm;
    ltv: boolean;
    reason?: string;
    location?: string;
    contactInfo?: string;
    name: string;
    timeout: string;
    retry: string;
    verbose: boolean;
    optimize: boolean;
    omitM: boolean;
}

const program = new Command();

program
    .name("pdf-rfc3161")
    .description("Add RFC 3161 trusted timestamps to PDF documents.")
    .version(VERSION);

program
    .command("timestamp")
    .description("Add an RFC 3161 timestamp to a PDF document")
    .argument("<tsa_url>", "TSA server URL (e.g., http://timestamp.digicert.com)")
    .argument("<file>", "Input PDF file")
    .argument("[bucket_output]", "Output file path (optional)")
    .addOption(new Option("-o, --output <file>", "Output file (legacy option)").hideHelp())
    .addOption(
        new Option("-a, --algorithm <alg>", "Hash algorithm")
            .choices(["SHA-256", "SHA-384", "SHA-512"])
            .default("SHA-256")
    )
    .option("--ltv", "Enable LTV (Long-Term Validation) - adds DSS/VRI dictionaries", false)
    .option("--reason <text>", "Reason for the timestamp")
    .option("--location <text>", "Location where the timestamp occurs")
    .option("--contact-info <text>", "Contact info for the signer")
    .option("--name <text>", "Name of the signature field", "Timestamp")
    .option("--timeout <ms>", "Request timeout in milliseconds", "30000")
    .option("--retry <n>", "Number of retry attempts", "3")
    .option("-v, --verbose", "Verbose output", false)
    .option("--optimize", "Optimize signature size (2-pass)", false)
    .option("--omit-m", "Omit modification time (/M) from signature dictionary", false)
    .action(
        async (
            tsaUrl: string,
            inputFile: string,
            bucketOutput: string | undefined,
            options: CliOptions
        ) => {
            try {
                // Handle output file logic: explicit argument > -o flag > auto-generated
                const outputFile =
                    bucketOutput ?? options.output ?? generateOutputFilename(inputFile);

                if (options.verbose) {
                    console.log(`Input:     ${inputFile}`);
                    console.log(`Output:    ${outputFile}`);
                    console.log(`TSA:       ${tsaUrl}`);
                    console.log(`Algorithm: ${options.algorithm}`);
                    console.log(`LTV:       ${options.ltv ? "enabled" : "disabled"}`);
                    if (options.reason) console.log(`Reason:    ${options.reason}`);
                    if (options.location) console.log(`Location:  ${options.location}`);
                    if (options.contactInfo) console.log(`Contact:   ${options.contactInfo}`);
                    console.log();
                }

                // Read input PDF
                const pdfBytes = await readFile(inputFile);
                const pdfData = new Uint8Array(pdfBytes);

                if (options.verbose) {
                    console.log(`Read ${String(pdfBytes.length)} bytes from ${inputFile}`);
                    console.log("Requesting timestamp from TSA...");
                }

                // Timestamp the PDF
                const timestampOptions = {
                    pdf: pdfData,
                    tsa: {
                        url: tsaUrl,
                        hashAlgorithm: options.algorithm,
                        timeout: parseInt(options.timeout, 10),
                        retry: parseInt(options.retry, 10),
                    },
                    reason: options.reason,
                    location: options.location,
                    contactInfo: options.contactInfo,
                    signatureFieldName: options.name,
                    optimizePlaceholder: options.optimize,
                    omitModificationTime: options.omitM,
                    enableLTV: options.ltv,
                };

                const result = await timestampPdf(timestampOptions);

                // Write output
                await writeFile(outputFile, result.pdf);

                console.log(`SUCCESS: Timestamp added successfully!`);
                console.log(`  Output:      ${outputFile}`);
                console.log(`  Time:        ${result.timestamp.genTime.toISOString()}`);
                console.log(`  Policy:      ${result.timestamp.policy}`);

                if (options.verbose) {
                    console.log(`  Serial:      ${result.timestamp.serialNumber}`);
                    console.log(`  Algorithm:   ${result.timestamp.hashAlgorithm}`);
                    console.log(`  Digest:      ${result.timestamp.messageDigest.slice(0, 32)}...`);
                    console.log(
                        `  Certificate: ${result.timestamp.hasCertificate ? "included" : "not included"
                        }`
                    );
                    console.log(`  Input size:  ${pdfBytes.length.toLocaleString()} bytes`);
                    console.log(`  Output size: ${result.pdf.length.toLocaleString()} bytes`);
                    const delta = result.pdf.length - pdfBytes.length;
                    const deltaPercent = ((delta / pdfBytes.length) * 100).toFixed(1);
                    console.log(
                        `  Size delta:  +${delta.toLocaleString()} bytes (+${deltaPercent}%)`
                    );
                }
            } catch (error: unknown) {
                handleError(error, options.verbose);
            }
        }
    );

program
    .command("verify")
    .description("Verify RFC 3161 timestamps in a PDF document")
    .argument("<file>", "PDF file to verify")
    .option("-v, --verbose", "Show detailed timestamp information", false)
    .action(async (inputFile: string, options: Pick<CliOptions, "verbose">) => {
        try {
            if (options.verbose) {
                console.log(`Verifying: ${inputFile}\n`);
            }

            // Read input PDF
            const pdfBytes = await readFile(inputFile);
            const pdfData = new Uint8Array(pdfBytes);

            // Extract timestamps
            const timestamps = await extractTimestamps(pdfData);

            if (timestamps.length === 0) {
                console.log("No RFC 3161 timestamps found in this PDF.");
                return;
            }

            console.log(`Found ${timestamps.length.toString()} timestamp(s):\n`);

            for (let i = 0; i < timestamps.length; i++) {
                const ts = timestamps[i];
                if (!ts) continue;

                // Verify the timestamp
                const verified = await verifyTimestamp(ts);
                timestamps[i] = verified;

                console.log(`Timestamp ${(i + 1).toString()}:`);
                console.log(`  Field:         ${ts.fieldName}`);
                console.log(`  Time:          ${ts.info.genTime.toISOString()}`);
                console.log(`  Policy:        ${ts.info.policy}`);

                if (verified.verified) {
                    console.log(`  Status:        [OK] Verified`);
                } else {
                    console.log(`  Status:        [FAIL] Verification failed`);
                    if (verified.verificationError !== undefined) {
                        console.log(`  Error:         ${verified.verificationError}`);
                    }
                }

                if (options.verbose) {
                    console.log(`  Serial:        ${ts.info.serialNumber}`);
                    console.log(`  Algorithm:     ${ts.info.hashAlgorithm}`);
                    console.log(`  Digest:        ${ts.info.messageDigest.slice(0, 32)}...`);
                    console.log(
                        `  Certificate:   ${ts.info.hasCertificate ? "included" : "not included"}`
                    );
                    console.log(`  Covers whole:  ${ts.coversWholeDocument ? "yes" : "no"}`);
                }

                console.log();
            }

            // Summary
            const verifiedCount = timestamps.filter((ts) => ts.verified).length;
            if (verifiedCount === timestamps.length) {
                console.log(
                    `SUCCESS: All ${String(timestamps.length)} timestamp(s) verified successfully.`
                );
            } else {
                console.log(
                    `WARN: ${String(verifiedCount)}/${String(timestamps.length)} timestamp(s) verified.`
                );
                process.exit(1);
            }
        } catch (err: unknown) {
            handleError(err, options.verbose);
        }
    });

// Add examples section to help text
program.addHelpText(
    "after",
    `
KNOWN TSA SERVERS:
    ${Object.entries(KNOWN_TSA_URLS)
        .map(([name, url]) => `${name.padEnd(12)} ${url}`)
        .join("\n    ")}
`
);

function handleError(err: unknown, verbose: boolean): void {
    if (err instanceof TimestampError) {
        console.error(`Error [${err.code}]: ${err.message}`);
        if (verbose && err.cause) {
            console.error("Cause:", err.cause);
        }
    } else if (err instanceof Error) {
        console.error(`Error: ${err.message}`);
    } else {
        console.error("An unknown error occurred");
    }
    process.exit(1);
}

function generateOutputFilename(inputFile: string): string {
    const dir = dirname(inputFile);
    const base = basename(inputFile);
    const dotIndex = base.lastIndexOf(".");

    if (dotIndex > 0) {
        const name = base.slice(0, dotIndex);
        const ext = base.slice(dotIndex);
        return join(dir, `${name}-timestamped${ext}`);
    }

    return join(dir, `${base}-timestamped`);
}

program.parse();
