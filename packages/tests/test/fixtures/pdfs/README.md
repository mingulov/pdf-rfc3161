# PDF Fixtures

This directory contains test PDF files for testing timestamp embedding, extraction, and validation.

## Files

### Basic PDFs

- `minimal.pdf` - Smallest valid PDF (hello world)
- `with-signature.pdf` - PDF with existing signature field

### Test Cases

- `large.pdf` - Large PDF (>10MB) for performance testing
- `corrupted.pdf` - PDF with corruption for error handling
- `multi-page.pdf` - PDF with multiple pages

## Generation

PDFs are created using various tools:

```bash
# Minimal PDF
echo "Hello World" | ps2pdf - minimal.pdf

# Large PDF (repeat content to reach size)
dd if=/dev/zero of=large.bin bs=1M count=11
echo "Large PDF content" > large.txt
# Use PDF generation library to create large.pdf

# Corrupted PDF
cp minimal.pdf corrupted.pdf
# Corrupt some bytes in the file
```

## Usage in Tests

```typescript
import { readFileSync } from "fs";
import { extractTimestamps } from "../../src/pdf/extract";

const pdfBytes = new Uint8Array(readFileSync("test/fixtures/pdfs/minimal.pdf"));
const timestamps = await extractTimestamps(pdfBytes);
expect(timestamps).toHaveLength(0); // No timestamps in minimal PDF
```
