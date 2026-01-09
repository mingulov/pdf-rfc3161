const { PDFDocument } = require('pdf-lib-incremental-save');
const { timestampPdf, KNOWN_TSA_URLS } = require('../dist/index.cjs');
const fs = require('fs');
const path = require('path');

async function generateCheckFiles() {
    const outputDir = path.resolve(__dirname, '../../test_files');
    if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
    }

    console.log(`Generating check files in ${outputDir}...`);

    const doc = await PDFDocument.create();
    doc.addPage([595, 842]);
    doc.setTitle('Timestamp Test');
    doc.setSubject('Manual verification of LTV and non-LTV timestamps');
    doc.setAuthor('pdf-rfc3161');
    const pdfBytes = await doc.save();

    // 1. Non-LTV Timestamp
    console.log('Generating non-LTV timestamp...');
    const resNoLTV = await timestampPdf({
        pdf: pdfBytes,
        tsa: { url: KNOWN_TSA_URLS.DIGICERT },
    });
    fs.writeFileSync(path.join(outputDir, 'final-test-no-ltv.pdf'), resNoLTV.pdf);

    // 2. LTV Timestamp (using unified API)
    console.log('Generating LTV timestamp...');
    const resLTV = await timestampPdf({
        pdf: pdfBytes,
        tsa: { url: KNOWN_TSA_URLS.DIGICERT },
        enableLTV: true,
    });
    fs.writeFileSync(path.join(outputDir, 'final-test-ltv.pdf'), resLTV.pdf);

    // 3. LTV Disabled (Regression check - same as non-LTV)
    console.log('Generating LTV disabled timestamp...');
    const resLTVDisabled = await timestampPdf({
        pdf: pdfBytes,
        tsa: { url: KNOWN_TSA_URLS.DIGICERT },
        enableLTV: false,
    });
    fs.writeFileSync(path.join(outputDir, 'final-test-ltv-disabled.pdf'), resLTVDisabled.pdf);

    // 4. Optimized Payload (Minimal Padding)
    console.log('Generating Optimized (minimal padding) timestamp...');
    const resOptimized = await timestampPdf({
        pdf: pdfBytes,
        tsa: { url: KNOWN_TSA_URLS.DIGICERT },
        optimizePlaceholder: true,
    });
    fs.writeFileSync(path.join(outputDir, 'final-test-optimized.pdf'), resOptimized.pdf);

    // 5. Optimized LTV
    console.log('Generating Optimized LTV timestamp...');
    const resLTVOptimized = await timestampPdf({
        pdf: pdfBytes,
        tsa: { url: KNOWN_TSA_URLS.DIGICERT },
        enableLTV: true,
        optimizePlaceholder: true,
    });
    fs.writeFileSync(path.join(outputDir, 'final-test-ltv-optimized.pdf'), resLTVOptimized.pdf);

    // 6. Omit Modification Time
    console.log('Generating PDF with omitted modification time...');
    const resNoM = await timestampPdf({
        pdf: pdfBytes,
        tsa: { url: KNOWN_TSA_URLS.DIGICERT },
        omitModificationTime: true,
    });
    fs.writeFileSync(path.join(outputDir, 'final-test-omit-m.pdf'), resNoM.pdf);

    console.log('Done! Please verify these files in Adobe Acrobat.');
}

generateCheckFiles().catch(console.error);
