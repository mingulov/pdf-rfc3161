const fs = require("node:fs");
const path = require("node:path");

const VARIANTS = [
    {
        fileName: "final-test-no-ltv.pdf",
        description: "document timestamp with default metadata and LTV collection disabled",
        options: { enableLTV: false },
    },
    {
        fileName: "final-test-ltv.pdf",
        description: "document timestamp with candidate validation-material collection enabled",
        options: { enableLTV: true },
    },
    {
        fileName: "final-test-optimized.pdf",
        description: "LTV-disabled timestamp with an optimized placeholder",
        options: { enableLTV: false, optimizePlaceholder: true },
    },
    {
        fileName: "final-test-ltv-optimized.pdf",
        description: "LTV-enabled timestamp with an optimized placeholder",
        options: { enableLTV: true, optimizePlaceholder: true },
    },
    {
        fileName: "final-test-omit-m.pdf",
        description: "explicit /M omission (the default)",
        options: { enableLTV: false, omitModificationTime: true },
    },
    {
        fileName: "final-test-with-m.pdf",
        description: "compatibility metadata variant with /M explicitly enabled",
        options: { enableLTV: false, omitModificationTime: false },
    },
];

class UsageError extends Error {}

function printHelp(stream = process.stdout) {
    stream.write(
        `Usage:\n  node packages/tests/scripts/generate-check-files.cjs --output-dir <directory> --tsa-url <url>\n\n`
    );
    stream.write("Generate manual RFC 3161 PDF validation samples with the built package.\n\n");
    stream.write("Options:\n");
    stream.write("  --output-dir <directory>  New or existing directory for generated PDFs\n");
    stream.write(
        "  --tsa-url <url>           Explicit HTTP(S) TSA endpoint; there is no default\n"
    );
    stream.write("  -h, --help                Show this help and exit\n\n");
    stream.write(
        "Existing output files are never overwritten. A failed output batch rolls back only "
    );
    stream.write(
        "files created by that batch. enableLTV is explicit on every variant: it collects "
    );
    stream.write("candidate validation material, not trust or LTV validity.\n");
}

function requiredValue(argv, index, option) {
    const value = argv[index + 1];
    if (value === undefined || value.length === 0 || value.startsWith("-")) {
        throw new UsageError(`${option} requires a value`);
    }
    return value;
}

function parseArguments(argv) {
    if (argv.length === 1 && (argv[0] === "--help" || argv[0] === "-h")) {
        return { help: true };
    }

    let outputDirectory;
    let tsaUrl;

    for (let index = 0; index < argv.length; index += 1) {
        const argument = argv[index];
        if (argument === "--output-dir") {
            if (outputDirectory !== undefined) {
                throw new UsageError("--output-dir may only be provided once");
            }
            outputDirectory = requiredValue(argv, index, argument);
            index += 1;
            continue;
        }
        if (argument === "--tsa-url") {
            if (tsaUrl !== undefined) {
                throw new UsageError("--tsa-url may only be provided once");
            }
            tsaUrl = requiredValue(argv, index, argument);
            index += 1;
            continue;
        }
        if (argument === "--help" || argument === "-h") {
            throw new UsageError("--help must be used on its own");
        }
        if (argument.startsWith("-")) {
            throw new UsageError(`Unknown option: ${argument}`);
        }
        throw new UsageError(`Unexpected positional argument: ${argument}`);
    }

    if (outputDirectory === undefined) {
        throw new UsageError("--output-dir is required");
    }
    if (tsaUrl === undefined) {
        throw new UsageError("--tsa-url is required");
    }

    let parsedUrl;
    try {
        parsedUrl = new URL(tsaUrl);
    } catch {
        throw new UsageError("--tsa-url must be an absolute HTTP(S) URL");
    }
    if (parsedUrl.protocol !== "https:" && parsedUrl.protocol !== "http:") {
        throw new UsageError("--tsa-url must use http: or https:");
    }

    return { help: false, outputDirectory, tsaUrl };
}

function resolveOutputDirectory(outputDirectory) {
    const requestedDirectory = path.resolve(outputDirectory);
    if (fs.existsSync(requestedDirectory)) {
        if (!fs.statSync(requestedDirectory).isDirectory()) {
            throw new Error(`Output path is not a directory: ${requestedDirectory}`);
        }
    } else {
        fs.mkdirSync(requestedDirectory, { recursive: true });
    }
    return fs.realpathSync(requestedDirectory);
}

function outputPath(outputDirectory, fileName) {
    const candidate = path.resolve(outputDirectory, fileName);
    const relative = path.relative(outputDirectory, candidate);
    if (
        relative.length === 0 ||
        relative === ".." ||
        relative.startsWith(`..${path.sep}`) ||
        path.isAbsolute(relative)
    ) {
        throw new Error(`Unsafe generated output path: ${fileName}`);
    }
    return candidate;
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

function writeGeneratedFiles(generated, fileSystem = fs) {
    const createdOutputPaths = [];
    try {
        for (const result of generated) {
            const fileDescriptor = fileSystem.openSync(result.outputPath, "wx");
            createdOutputPaths.push(result.outputPath);
            let writeError;
            try {
                fileSystem.writeFileSync(fileDescriptor, result.pdf);
            } catch (error) {
                writeError = error;
                throw error;
            } finally {
                try {
                    fileSystem.closeSync(fileDescriptor);
                } catch (closeError) {
                    if (writeError === undefined) {
                        throw closeError;
                    }
                }
            }
        }
    } catch (error) {
        for (const outputPath of createdOutputPaths) {
            try {
                fileSystem.unlinkSync(outputPath);
            } catch {
                // Preserve the original write failure; only paths created by this batch are candidates.
            }
        }
        throw error;
    }
}

async function generateCheckFiles(options) {
    const { PDFDocument } = require("pdf-lib-incremental-save");
    const { timestampPdf } = loadBuiltPackage();
    if (typeof timestampPdf !== "function") {
        throw new Error("Built pdf-rfc3161 package does not export timestampPdf");
    }

    const outputDirectory = resolveOutputDirectory(options.outputDirectory);
    const paths = VARIANTS.map((variant) => ({
        ...variant,
        outputPath: outputPath(outputDirectory, variant.fileName),
    }));
    for (const variant of paths) {
        if (fs.existsSync(variant.outputPath)) {
            throw new Error(`Refusing to overwrite existing output file: ${variant.outputPath}`);
        }
    }

    const document = await PDFDocument.create();
    document.addPage([595, 842]);
    document.setTitle("RFC 3161 manual validation sample");
    document.setSubject("Manual validation of document timestamps and candidate DSS material");
    document.setAuthor("pdf-rfc3161");
    const inputPdf = await document.save();

    process.stdout.write(`Generating check files in ${outputDirectory}\n`);
    const generated = [];
    for (const variant of paths) {
        process.stdout.write(`Generating ${variant.fileName}: ${variant.description}\n`);
        const result = await timestampPdf({
            pdf: inputPdf,
            tsa: { url: options.tsaUrl },
            ...variant.options,
        });
        generated.push({ outputPath: variant.outputPath, pdf: result.pdf });
    }

    writeGeneratedFiles(generated);
    process.stdout.write("Generated files are ready for the manual validation protocol.\n");
}

async function main() {
    const options = parseArguments(process.argv.slice(2));
    if (options.help) {
        printHelp();
        return;
    }
    await generateCheckFiles(options);
}

function reportFailure(error) {
    if (error instanceof UsageError) {
        process.stderr.write(`Error: ${error.message}\n\n`);
        printHelp(process.stderr);
        process.exitCode = 2;
        return;
    }
    const detail = error instanceof Error ? (error.stack ?? error.message) : String(error);
    process.stderr.write(`Failed to generate check files: ${detail}\n`);
    process.exitCode = 1;
}

module.exports = { writeGeneratedFiles };

if (require.main === module) {
    main().catch(reportFailure);
}
