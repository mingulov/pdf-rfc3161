const fs = require("node:fs");
const path = require("node:path");

class UsageError extends Error {}

function printHelp(stream = process.stdout) {
    stream.write("Usage:\n  node packages/tests/scripts/verify-signature.cjs <pdf-path> [<pdf-path> ...]\n\n");
    stream.write("Verify RFC 3161 document timestamps with the built pdf-rfc3161 public API.\n\n");
    stream.write("The script checks document ByteRange binding, CMS signature consistency, ");
    stream.write("timestamp EKU and generation-time validity. It does not establish TSA trust: ");
    stream.write("the default trust store is intentionally empty (H3).\n\n");
    stream.write("Options:\n");
    stream.write("  -h, --help  Show this help and exit\n");
}

function parseArguments(argv) {
    if (argv.length === 1 && (argv[0] === "--help" || argv[0] === "-h")) {
        return { help: true };
    }
    if (argv.length === 0) {
        throw new UsageError("At least one PDF path is required");
    }
    for (const argument of argv) {
        if (argument.startsWith("-")) {
            throw new UsageError(`Unknown option: ${argument}`);
        }
    }
    return { help: false, pdfPaths: argv };
}

function loadBuiltPackage() {
    try {
        return require("pdf-rfc3161");
    } catch (error) {
        const detail = error instanceof Error ? error.message : String(error);
        throw new Error(
            `Could not load the built pdf-rfc3161 package. Run pnpm build first. ${detail}`
        );
    }
}

function timestampTime(timestamp) {
    const value = timestamp.info?.genTime;
    return value instanceof Date ? value.toISOString() : "not available";
}

async function verifyPdf(library, pdfPath) {
    if (
        typeof library.extractTimestamps !== "function" ||
        typeof library.verifyTimestamp !== "function"
    ) {
        throw new Error("Built pdf-rfc3161 package is missing extractTimestamps or verifyTimestamp");
    }

    const resolvedPath = path.resolve(pdfPath);
    const pdf = new Uint8Array(fs.readFileSync(resolvedPath));
    process.stdout.write(`Verifying ${resolvedPath}\n`);

    const timestamps = await library.extractTimestamps(pdf);
    if (timestamps.length === 0) {
        throw new Error("No RFC 3161 document timestamps found");
    }

    let allPassed = true;
    for (const timestamp of timestamps) {
        const verified = await library.verifyTimestamp(timestamp, {
            pdf,
            requireTimestampingEKU: true,
            requireCertValidAtGenTime: true,
            strictESSValidation: true,
        });
        const label = verified.fieldName || "unnamed timestamp field";
        const result = verified.verified ? "PASS" : "FAIL";
        process.stdout.write(`  ${label}: cryptographic consistency ${result}\n`);
        process.stdout.write(`  ${label}: timestamp time ${timestampTime(verified)}\n`);
        process.stdout.write(
            `  ${label}: ByteRange covers supplied file ${verified.coversWholeDocument ? "yes" : "no"}\n`
        );
        if (!verified.verified) {
            allPassed = false;
            process.stderr.write(
                `  ${label}: ${verified.verificationError ?? "verification returned failure"}\n`
            );
        }
    }

    process.stdout.write(
        "  Trust policy / H3: NOT EVALUATED (supply a caller-owned trust store for path trust)\n"
    );
    return allPassed;
}

async function main() {
    const options = parseArguments(process.argv.slice(2));
    if (options.help) {
        printHelp();
        return;
    }

    const library = loadBuiltPackage();
    let allPassed = true;
    for (const pdfPath of options.pdfPaths) {
        try {
            if (!(await verifyPdf(library, pdfPath))) {
                allPassed = false;
            }
        } catch (error) {
            allPassed = false;
            const detail = error instanceof Error ? error.message : String(error);
            process.stderr.write(`Verification failed for ${pdfPath}: ${detail}\n`);
        }
    }
    if (!allPassed) {
        process.exitCode = 1;
    }
}

main().catch((error) => {
    if (error instanceof UsageError) {
        process.stderr.write(`Error: ${error.message}\n\n`);
        printHelp(process.stderr);
        process.exitCode = 2;
        return;
    }
    const detail = error instanceof Error ? error.stack ?? error.message : String(error);
    process.stderr.write(`Signature verification failed: ${detail}\n`);
    process.exitCode = 1;
});
