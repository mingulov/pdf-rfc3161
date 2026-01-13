import { Command, Option } from "commander";
import { readFile, writeFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import {
    timestampPdf,
    timestampPdfLTA,
    extractTimestamps,
    verifyTimestamp,
    getDSSInfo,
    validateTimestampTokenRFC8933Compliance,
    KNOWN_TSA_URLS,
    TimestampError,
    type HashAlgorithm,
    setLogger,
} from "pdf-rfc3161";
import * as pkijs from "pkijs";

// VERSION is injected by tsup at build time (via define: { VERSION: ... })
// For dev/tsx execution, we handle it via globalThis check.


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

// Injected by tsup at build time
declare const VERSION: string;

// Safe check for VERSION injection (handles both build and dev/tsx scenarios)

let cliVersion = 'dev';
try {
    if (typeof VERSION !== 'undefined') {
        cliVersion = VERSION;
    }
} catch {
    // Ignore ReferenceError in dev mode
}


program
    .name('pdf-rfc3161')
    .description('CLI tool for adding RFC 3161 timestamps to PDFs')
    .version(cliVersion);

program
    .command("timestamp")
    .description("Add an RFC 3161 timestamp to a PDF document")
    .argument("<tsa_url>", "TSA server URL (e.g., https://freetsa.org/tsr)")
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

                    // Enable verbose logging in core library
                    const verboseLogger = {
                        debug: (msg: string, ...args: unknown[]) => console.debug(`[DEBUG] ${msg}`, ...args),
                        info: (msg: string, ...args: unknown[]) => console.info(`[INFO] ${msg}`, ...args),
                        warn: (msg: string, ...args: unknown[]) => console.warn(`[WARN] ${msg}`, ...args),
                        error: (msg: string, ...args: unknown[]) => console.error(`[ERROR] ${msg}`, ...args),
                    };
                    setLogger(verboseLogger);
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

                if (result.ltvData) {
                    const certCount = result.ltvData.certificates.length;
                    const crlCount = result.ltvData.crls.length;
                    const ocspCount = result.ltvData.ocspResponses.length;
                    console.log(
                        `  LTV Data:    ${String(certCount)} Certs, ${String(crlCount)} CRLs, ${String(ocspCount)} OCSPs embedded`
                    );
                }
            } catch (error: unknown) {
                handleError(error, options.verbose);
            }
        }
    );

program
    .command("archive")
    .description("Add a PAdES-LTA Archive Timestamp (long-term preservation)")
    .argument("<tsa_url>", "TSA server URL (e.g., https://freetsa.org/tsr)")
    .argument("<file>", "Input PDF file")
    .argument("[bucket_output]", "Output file path (optional)")
    .addOption(new Option("-o, --output <file>", "Output file").hideHelp())
    .addOption(
        new Option("-a, --algorithm <alg>", "Hash algorithm")
            .choices(["SHA-256", "SHA-384", "SHA-512"])
            .default("SHA-256")
    )
    .option("--no-update", "Do not fetch fresh revocation data for existing signatures", false)
    .option("--name <text>", "Name of the signature field", "ArchiveTimestamp")
    .option("--timeout <ms>", "Request timeout in milliseconds", "30000")
    .option("--retry <n>", "Number of retry attempts", "3")
    .option("-v, --verbose", "Verbose output", false)
    .action(
        async (
            tsaUrl: string,
            inputFile: string,
            bucketOutput: string | undefined,
            cmdOptions: CliOptions & { noUpdate: boolean }
        ) => {
            try {
                const outputFile =
                    bucketOutput ?? cmdOptions.output ?? generateOutputFilename(inputFile);

                if (cmdOptions.verbose) {
                    console.log(`PAdES-LTA Archive Timestamping`);
                    console.log(`Input:     ${inputFile}`);
                    console.log(`Output:    ${outputFile}`);
                    console.log(`TSA:       ${tsaUrl}`);
                    console.log(
                        `Update:    ${!cmdOptions.noUpdate ? "Fetch fresh revocation data" : "Use existing only"}`
                    );
                    console.log();
                }

                const pdfBytes = await readFile(inputFile);
                const pdfData = new Uint8Array(pdfBytes);

                if (cmdOptions.verbose) {
                    console.log("Processing document...");

                    // Enable verbose logging in core library
                    const verboseLogger = {
                        debug: (msg: string, ...args: unknown[]) => console.debug(`[DEBUG] ${msg}`, ...args),
                        info: (msg: string, ...args: unknown[]) => console.info(`[INFO] ${msg}`, ...args),
                        warn: (msg: string, ...args: unknown[]) => console.warn(`[WARN] ${msg}`, ...args),
                        error: (msg: string, ...args: unknown[]) => console.error(`[ERROR] ${msg}`, ...args),
                    };
                    setLogger(verboseLogger);
                }

                const result = await timestampPdfLTA({
                    pdf: pdfData,
                    tsa: {
                        url: tsaUrl,
                        hashAlgorithm: cmdOptions.algorithm,
                        timeout: parseInt(cmdOptions.timeout, 10),
                        retry: parseInt(cmdOptions.retry, 10),
                    },
                    signatureFieldName: cmdOptions.name,
                    includeExistingRevocationData: !cmdOptions.noUpdate,
                });

                await writeFile(outputFile, result.pdf);

                console.log(`SUCCESS: Archive timestamp added!`);
                console.log(`  Output:      ${outputFile}`);
                console.log(`  Time:        ${result.timestamp.genTime.toISOString()}`);

                if (result.ltvData) {
                    const certCount = result.ltvData.certificates.length;
                    const crlCount = result.ltvData.crls.length;
                    const ocspCount = result.ltvData.ocspResponses.length;
                    console.log(
                        `  LTV Data:    ${String(certCount)} Certs, ${String(crlCount)} CRLs, ${String(ocspCount)} OCSPs embedded`
                    );
                }
            } catch (err: unknown) {
                handleError(err, cmdOptions.verbose);
            }
        }
    );

program
    .command("verify")
    .description("Verify RFC 3161 timestamps in a PDF document")
    .argument("<file>", "PDF file to verify")
    .option("-v, --verbose", "Show detailed timestamp information", false)
    .option("--rfc8933", "Validate RFC 8933 CMS Algorithm Identifier Protection compliance", false)
    .action(
        async (inputFile: string, options: Pick<CliOptions, "verbose"> & { rfc8933: boolean }) => {
            try {
                if (options.verbose) {
                    console.log(`Verifying: ${inputFile}\n`);
                }

                // Read input PDF
                const pdfBytes = await readFile(inputFile);
                const pdfData = new Uint8Array(pdfBytes);

                // Check for Document Security Store (LTV)
                const dssInfo = await getDSSInfo(pdfData);
                if (dssInfo && (dssInfo.certs > 0 || dssInfo.crls > 0 || dssInfo.ocsps > 0)) {
                    console.log(`Document Security Store (LTV):`);
                    console.log(`  Certificates:   ${String(dssInfo.certs)}`);
                    console.log(`  CRLs:           ${String(dssInfo.crls)}`);
                    console.log(`  OCSP Responses: ${String(dssInfo.ocsps)}`);
                    console.log();
                }

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

                    if (ts.reason) console.log(`  Reason:        ${ts.reason}`);
                    if (ts.location) console.log(`  Location:      ${ts.location}`);
                    if (ts.contactInfo) console.log(`  Contact:       ${ts.contactInfo}`);
                    if (ts.m) console.log(`  Signed At:     ${ts.m.toISOString()}`);

                    if (verified.verified) {
                        console.log(`  Status:        [OK] Verified`);
                    } else {
                        console.log(`  Status:        [FAIL] Verification failed`);
                        if (verified.verificationError !== undefined) {
                            console.log(`  Error:         ${verified.verificationError}`);
                        }
                    }

                    // Extract TSA Name from certificate
                    if (verified.certificates && verified.certificates.length > 0) {
                        const count = verified.certificates.length;
                        const signer = verified.certificates[0];
                        if (signer) {
                            const signerName = getCommonName(signer.subject);
                            console.log(`  TSA Name:      ${signerName}`);
                        }

                        if (options.verbose) {
                            console.log(`  Chain:         ${String(count)} certificates`);
                            verified.certificates.forEach(
                                (cert: pkijs.Certificate, idx: number) => {
                                    const subject = getCommonName(cert.subject);
                                    const issuer = getCommonName(cert.issuer);
                                    const serial = cert.serialNumber.valueBlock.toString();
                                    console.log(`    [${String(idx)}] Subject: ${subject}`);
                                    console.log(`        Issuer:  ${issuer}`);
                                    console.log(`        Serial:  ${serial}`);
                                }
                            );
                        }
                    }

                    // RFC 8933 compliance validation
                    if (options.rfc8933 && verified.verified) {
                        const rfc8933Result = validateTimestampTokenRFC8933Compliance(ts.token);
                        if (rfc8933Result.compliant) {
                            console.log(`  RFC 8933:      [OK] Compliant`);
                        } else {
                            console.log(
                                `  RFC 8933:      [WARN] ${rfc8933Result.issues.join(", ")}`
                            );
                        }

                        if (options.verbose) {
                            console.log(
                                `  Digest consistency: ${rfc8933Result.digestAlgorithmConsistency ? "OK" : "FAIL"}`
                            );
                            console.log(
                                `  Algorithm protection: ${rfc8933Result.hasAlgorithmProtection ? "present" : "missing"}`
                            );
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
                const verifiedCount = timestamps.filter(
                    (ts: { verified: boolean }) => ts.verified
                ).length;
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
            } catch (err) {
                handleError(err, options.verbose);
            }
        }
    );

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
        console.error(`Error [${err.code.toString()}]: ${err.message}`);
        if (verbose && "cause" in err && err.cause instanceof Error) {
            console.error("Cause:", err.cause.message);
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

function getCommonName(dn: pkijs.RelativeDistinguishedNames): string {
    for (const set of dn.typesAndValues) {
        if (set.type === "2.5.4.3") {

            return set.value.valueBlock.value as string;
        }
    }
    const first = dn.typesAndValues[0];
    if (first) {

        return first.value.valueBlock.value as string;
    }
    return "Unknown";
}

// Export functions for testing
export { handleError, generateOutputFilename };

// Only parse command line arguments if not in test mode
// This allows unit tests to import the CLI module without triggering argument parsing
if (process.env.CLI_TEST_MODE !== "true") {
    program.parse();
}
