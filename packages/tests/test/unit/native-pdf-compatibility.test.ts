import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { PDFDocument } from "pdf-lib-incremental-save";
import { timestampPdf } from "pdf-rfc3161";
import { afterEach, describe, expect, it, vi } from "vitest";
import { stubTsaFetch } from "../utils/timestamp-fixtures.js";

const MACOS_ORACLE = `
import Foundation
import PDFKit

guard let path = ProcessInfo.processInfo.environment["PDF_RFC3161_NATIVE_PDF"] else {
    fputs("PDF_RFC3161_NATIVE_PDF is not set\\n", stderr)
    exit(1)
}
guard let document = PDFDocument(url: URL(fileURLWithPath: path)) else {
    fputs("PDFKit could not open the PDF\\n", stderr)
    exit(1)
}
guard document.pageCount == 2 else {
    fputs("PDFKit found \\(document.pageCount) pages instead of 2\\n", stderr)
    exit(1)
}
for index in 0..<document.pageCount {
    guard document.page(at: index) != nil else {
        fputs("PDFKit could not load page \\(index)\\n", stderr)
        exit(1)
    }
}
`;

const WINDOWS_ORACLE = String.raw`
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$null = [Windows.Storage.StorageFile, Windows.Storage, ContentType = WindowsRuntime]
$null = [Windows.Data.Pdf.PdfDocument, Windows.Data.Pdf, ContentType = WindowsRuntime]

$asTask = [System.WindowsRuntimeSystemExtensions].GetMethods() |
    Where-Object {
        $_.Name -eq "AsTask" -and
            $_.IsGenericMethod -and
            $_.GetGenericArguments().Count -eq 1 -and
            $_.GetParameters().Count -eq 1 -and
            $_.GetParameters()[0].ParameterType.Name -like "IAsyncOperation*" -and
            $_.GetParameters()[0].ParameterType.Name -notlike "*WithProgress*"
    } |
    Select-Object -First 1

function Await-WinRt($Operation, [Type] $ResultType) {
    $task = $asTask.MakeGenericMethod($ResultType).Invoke($null, @($Operation))
    $task.Wait()
    return $task.Result
}

$fileOperation = [Windows.Storage.StorageFile]::GetFileFromPathAsync(
    $env:PDF_RFC3161_NATIVE_PDF
)
$file = Await-WinRt $fileOperation ([Windows.Storage.StorageFile])
$documentOperation = [Windows.Data.Pdf.PdfDocument]::LoadFromFileAsync($file)
$document = Await-WinRt $documentOperation ([Windows.Data.Pdf.PdfDocument])

if ($document.PageCount -ne 2) {
    throw "Windows.Data.Pdf found $($document.PageCount) pages instead of 2"
}
for ($index = 0; $index -lt $document.PageCount; $index++) {
    $page = $document.GetPage([uint32] $index)
    if ($null -eq $page) {
        throw "Windows.Data.Pdf could not load page $index"
    }
    $page.Dispose()
}
`;

const temporaryDirectories: string[] = [];

afterEach(() => {
    vi.unstubAllGlobals();
    for (const directory of temporaryDirectories.splice(0)) {
        rmSync(directory, { force: true, recursive: true });
    }
});

async function createTimestampedLtvPdf(): Promise<string> {
    const document = await PDFDocument.create();
    document.addPage([200, 200]);
    document.addPage([200, 200]);
    const input = await document.save();

    stubTsaFetch();

    const result = await timestampPdf({
        pdf: input,
        tsa: { url: "https://timestamp.example.test", retry: 0 },
        enableLTV: true,
    });
    expect(result.ltvData?.certificates).toHaveLength(1);

    const directory = mkdtempSync(join(tmpdir(), "pdf-rfc3161-native-"));
    temporaryDirectories.push(directory);
    const path = join(directory, "timestamped-ltv.pdf");
    writeFileSync(path, result.pdf);
    return path;
}

function commandFailure(status: number | null, stdout: string, stderr: string): string {
    return [`native PDF process exited with ${String(status)}`, stdout, stderr]
        .filter((value) => value.length > 0)
        .join("\n");
}

describe.runIf(process.platform === "darwin")("macOS native PDF compatibility", () => {
    it("opens a multi-page timestampPdf LTV result with PDFKit", async () => {
        const path = await createTimestampedLtvPdf();
        const result = spawnSync("xcrun", ["swift", "-e", MACOS_ORACLE], {
            encoding: "utf8",
            env: { ...process.env, PDF_RFC3161_NATIVE_PDF: path },
            timeout: 20_000,
        });

        expect(result.error).toBeUndefined();
        expect(result.status, commandFailure(result.status, result.stdout, result.stderr)).toBe(0);
    });

    it("renders a multi-page timestampPdf LTV result with Quick Look", async () => {
        const path = await createTimestampedLtvPdf();
        const outputDirectory = join(dirname(path), "quick-look");
        mkdirSync(outputDirectory);
        const result = spawnSync("qlmanage", ["-t", "-s", "128", "-o", outputDirectory, path], {
            encoding: "utf8",
            timeout: 20_000,
        });

        expect(result.error).toBeUndefined();
        const failure = commandFailure(result.status, result.stdout, result.stderr);
        expect(result.status, failure).toBe(0);
        const thumbnails = readdirSync(outputDirectory);
        expect(thumbnails, failure).toHaveLength(1);
        expect(statSync(join(outputDirectory, thumbnails[0] ?? "")).size, failure).toBeGreaterThan(
            0
        );
    });
});

describe.runIf(process.platform === "win32")("Windows native PDF compatibility", () => {
    it("opens a multi-page timestampPdf LTV result with Windows.Data.Pdf", async () => {
        const path = await createTimestampedLtvPdf();
        const result = spawnSync(
            "powershell.exe",
            ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-"],
            {
                encoding: "utf8",
                env: { ...process.env, PDF_RFC3161_NATIVE_PDF: path },
                input: WINDOWS_ORACLE,
                timeout: 20_000,
            }
        );

        expect(result.error).toBeUndefined();
        expect(result.status, commandFailure(result.status, result.stdout, result.stderr)).toBe(0);
    });
});
