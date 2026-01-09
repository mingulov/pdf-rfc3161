const fs = require('fs');
const crypto = require('crypto');
const { execSync } = require('child_process');

function verify(pdfPath) {
    console.log(`Verifying ${pdfPath}...`);
    const pdf = fs.readFileSync(pdfPath);
    const pdfStr = pdf.toString('latin1');

    // 1. Extract ByteRange
    const brMatch = pdfStr.match(/\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/);
    if (!brMatch) {
        console.error('No ByteRange found!');
        return;
    }
    const br = [
        parseInt(brMatch[1]),
        parseInt(brMatch[2]),
        parseInt(brMatch[3]),
        parseInt(brMatch[4])
    ];
    console.log('ByteRange:', br);

    // 2. Extract Signed Data
    const part1 = pdf.subarray(br[0], br[0] + br[1]);
    const part2 = pdf.subarray(br[2], br[2] + br[3]);
    const signedData = Buffer.concat([part1, part2]);
    console.log(`Extracted ${signedData.length} bytes of signed data.`);

    // 3. Hash it (SHA-256)
    const hash = crypto.createHash('sha256').update(signedData).digest('hex');
    console.log('calculated_hash:', hash);

    // 4. Extract Token from Contents
    const contentsMatch = pdfStr.match(/\/Contents\s*<([^>]+)>/);
    if (!contentsMatch) {
        console.error('No /Contents found!');
        return;
    }
    let hex = contentsMatch[1];
    const hexClean = hex.replace(/\s/g, '');
    const tokenBuffer = Buffer.from(hexClean, 'hex');

    fs.writeFileSync('/tmp/token.der', tokenBuffer);

    // 5. Extract message imprint
    try {
        const textOut = execSync('openssl ts -reply -in /tmp/token.der -token_in -text', { encoding: 'utf8' });
        console.log('--- OpenSSL Output ---');
        console.log(textOut);
        console.log('----------------------');

        // Improved matching for OpenSSL multi-line hex dump
        const lines = textOut.split('\n');
        let messageDataHex = '';
        let capturing = false;
        for (const line of lines) {
            if (line.includes('Message data:')) {
                capturing = true;
                continue;
            }
            if (capturing) {
                // If the line has ' - ', it's a hex dump line.
                // e.g. "    0000 - 05 97 14 1a ..."
                const dumpMatch = line.match(/^\s*[0-9A-Fa-f]+ - (([0-9A-Fa-f]{2}[\s-]+)+)/);
                if (dumpMatch) {
                    messageDataHex += dumpMatch[1].replace(/[^0-9A-Fa-f]/g, '');
                } else if (line.trim() !== '' && messageDataHex.length > 0) {
                    // Stop if we hit a non-hex line after we started capturing
                    capturing = false;
                }
            }
        }

        if (messageDataHex) {
            const tokenHash = messageDataHex.toLowerCase().trim();
            console.log('token_imprint:  ', tokenHash);

            if (tokenHash === hash) {
                console.log('SUCCESS: Hash matches!');
            } else {
                console.error('FAILURE: Hash Mismatch!');
                console.log('Diff:');
                console.log(' Calc: ', hash);
                console.log(' Tok:  ', tokenHash);
            }
        } else {
            console.log('Could not find Message data in openssl output.');
        }

    } catch (e) {
        console.error('OpenSSL failed:', e.message);
        console.log(e.stdout ? e.stdout.toString() : '');
    }
}

const args = process.argv.slice(2);
if (args.length > 0) {
    verify(args[0]);
} else {
    const base = '/home/user/src/m/test_files';
    verify(`${base}/final-test-no-ltv.pdf`);
}
