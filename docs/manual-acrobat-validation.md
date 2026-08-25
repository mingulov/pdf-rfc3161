# Manual Acrobat Reader validation protocol

This protocol records one reproducible observation of an Adobe Acrobat Reader build. It
does not automate Acrobat in CI, redistribute Adobe software, assert Adobe approval, or
make a universal claim about other Reader versions, trust settings, operating systems,
or PDF viewers. The expected wording below is an observation to record for the tested
build, not a contract.

Use [validation-tools.md](validation-tools.md) for the role boundaries of Acrobat,
qpdf, pyHanko, and OpenSSL. Do not process an untrusted PDF outside
resource-limited isolation; the supported signing workflow expects a clean,
structurally valid input. See
[pdf-lib-incremental-save-limitations.md](pdf-lib-incremental-save-limitations.md).

Use the tested build's equivalent controls, guided by Adobe's primary documentation for
[validation](https://helpx.adobe.com/uk/acrobat/desktop/e-sign-documents/manage-digital-signatures/validate-digital-sign.html?screen=modern),
[signature preferences](https://helpx.adobe.com/uk/acrobat/desktop/e-sign-documents/manage-digital-signatures/set-preferences.html),
and [certificate trust](https://helpx.adobe.com/acrobat/desktop/e-sign-documents/manage-digital-signatures/set-certificate-trust.html).
For trust-list observations, Adobe documents [AATL](https://helpx.adobe.com/ca/acrobat/using/trusted-identities.html)
and [EUTL refresh caveats](https://helpx.adobe.com/sg/document-cloud/kb/european-union-trust-lists.html).
The labels and behavior must still be recorded exactly as observed in the tested build.

Acrobat Reader, Acrobat Standard, and Acrobat Pro can expose the same controls
under different panel names, menu routes, and new-versus-classic UI layouts.
For example, one build can call the list a "Signatures" panel while another
surfaces it through its signature or certificate workflow. Use the equivalent
control for the installed product, record the exact route and labels, and do
not treat this protocol's labels as a cross-version UI contract.

## Prepare a test run

Build the package and generate a fresh sample into a caller-selected directory. The
generator has no default TSA URL or output path.

```bash
corepack pnpm@10.30.3 build
node packages/tests/scripts/generate-check-files.cjs \
  --output-dir <absolute-output-directory> \
  --tsa-url <https-or-http-tsa-url>
```

Select the file under test and call it `PDF` below. Do not replace it after recording its
hash. If a live TSA was used, record its endpoint and any terms or rate-limit condition
that affected the run. `enableLTV` variants collect candidate validation material; they
do not create a trust decision, full LTV result, or indefinite validity claim.

### Retain a disposable local-root fixture

The normal offline interoperability gate uses a temporary directory and deletes its
root certificate, TSA response, covered bytes, and PDF at the end. Generate
the retained fixture on an Ubuntu 24.04 AMD64 runner with the same pinned tools
as CI. Create a fresh, caller-selected absolute output directory that does not
yet exist; its parent directory must already exist:

```bash
ARTIFACT_DIR=<absolute-new-artifact-directory>
PYTHON=/tmp/pdf-rfc3161-pades-python/bin/python \
  corepack pnpm@10.30.3 --filter pdf-rfc3161-tests test:interoperability \
    --output-dir "$ARTIFACT_DIR"
for FILE_NAME in timestamped.pdf root.pem response.tsr covered.bin request.tsq; do
  sha256sum "$ARTIFACT_DIR/$FILE_NAME"
done
```

Before this block, complete the canonical
[clean-checkout setup](pades-oracle-tools.md#run-from-a-clean-checkout), including
its passing temporary interoperability run. Preserve the five SHA-256 lines above
in the Ubuntu generation record for comparison after transfer.

The command refuses a relative or existing output directory. On success it
retains the same local fixture artifacts for the same-file checks:

| File              | Role                                                              |
| ----------------- | ----------------------------------------------------------------- |
| `timestamped.pdf` | Set `PDF` to this file for Reader, qpdf, and pyHanko.             |
| `root.pem`        | Set `ROOT_CERT` to this disposable local test root.               |
| `response.tsr`    | Set `TIMESTAMP_RESPONSE` to this complete TimeStampResp.          |
| `covered.bin`     | Set `COVERED_BYTES` to the exact concatenated ByteRange bytes.    |
| `request.tsq`     | Retain with the response as the matching RFC 3161 request record. |

The directory also contains the disposable `root.key` and `tsa.key`. Treat
both as private test material: do not copy, share, or import them. If Reader
runs on another machine, transfer only the five public files listed above and
verify their hashes after transfer. Delete both copies after the Reader cleanup
record is complete. If the gate fails, inspect and remove only this
caller-selected directory yourself; the command deliberately does not delete a
retained output directory.

For a Unix-like shell, set the same-file paths explicitly:

```bash
ARTIFACT_DIR=<absolute-new-artifact-directory>
PDF="$ARTIFACT_DIR/timestamped.pdf"
ROOT_CERT="$ARTIFACT_DIR/root.pem"
TIMESTAMP_RESPONSE="$ARTIFACT_DIR/response.tsr"
COVERED_BYTES="$ARTIFACT_DIR/covered.bin"
```

On the Windows machine running Reader, set `$artifactDirectory` to the directory
containing the five transferred public files. This step does not regenerate or
repair the PDF and must not receive either private key:

```powershell
$artifactDirectory = "C:\absolute\path\to\artifact-directory"
if (-not [System.IO.Path]::IsPathRooted($artifactDirectory)) {
    throw "artifactDirectory must be an absolute path"
}
if (-not (Test-Path -LiteralPath $artifactDirectory -PathType Container)) {
    throw "Artifact directory does not exist: $artifactDirectory"
}

$env:PDF = Join-Path $artifactDirectory "timestamped.pdf"
$env:ROOT_CERT = Join-Path $artifactDirectory "root.pem"
$env:TIMESTAMP_RESPONSE = Join-Path $artifactDirectory "response.tsr"
$env:COVERED_BYTES = Join-Path $artifactDirectory "covered.bin"

@($env:PDF, $env:ROOT_CERT, $env:TIMESTAMP_RESPONSE, $env:COVERED_BYTES,
  (Join-Path $artifactDirectory "request.tsq")) | ForEach-Object {
    if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) {
        throw "Missing retained fixture file: $_"
    }
    Get-FileHash -LiteralPath $_ -Algorithm SHA256
}
```

Compare every transferred hash with the Ubuntu generation record. Keep
`$artifactDirectory` for the root-fingerprint and cleanup steps below.

Before opening Reader, record this identity sheet:

| Item                               | Record                                             |
| ---------------------------------- | -------------------------------------------------- |
| Tested PDF absolute path           | Exact caller-selected path                         |
| Tested PDF SHA-256                 | Exact digest of the bytes Reader opens             |
| Library commit                     | `git rev-parse HEAD` output                        |
| Lockfile SHA-256                   | Exact digest of `pnpm-lock.yaml`                   |
| Reader product, version, and build | Exact About dialog text                            |
| Operating system and version       | Exact system version                               |
| Locale                             | Reader and OS locale                               |
| Architecture                       | For example, x64 or arm64                          |
| Trust source                       | AATL, EUTL, manual local root, or no root          |
| Network state                      | Online or offline, proxy/VPN state if relevant     |
| Revocation preferences             | Exact Reader preference labels and selected values |
| TSA URL and test variant           | Endpoint and generated file name                   |

On Unix-like systems, calculate the two file digests with:

```bash
sha256sum "$PDF"
sha256sum pnpm-lock.yaml
```

On Windows PowerShell, record the transferred PDF hash and compare it with the
Ubuntu generation record. The lockfile hash also comes from that Ubuntu record;
the Reader machine does not need a repository checkout:

```powershell
$env:PDF = "C:\absolute\path\to\document.pdf"
Get-FileHash -LiteralPath $env:PDF -Algorithm SHA256
```

On another platform, use its SHA-256 command and record both the command and
its complete output.

## Capture same-file open-source evidence

Run these commands on the Ubuntu generation runner against the SHA-256-recorded
`PDF`, not a regenerated or repaired copy. Preserve stdout, stderr, tool version,
exit status, and the tested file hash. Activate the same locally extracted
qpdf/OpenSSL binaries that the interoperability gate checked:

```bash
PADES_ROOT="$PWD/packages/tests/.pades-oracles/amd64-qpdf-11.9.0-1.1ubuntu0.1-openssl-3.0.13-0ubuntu3.12/rootfs"
PATH="$PADES_ROOT/usr/bin:$PATH"
LD_LIBRARY_PATH="$PADES_ROOT/usr/lib/x86_64-linux-gnu"
PYTHON=/tmp/pdf-rfc3161-pades-python/bin/python
export PATH LD_LIBRARY_PATH

qpdf --version
qpdf --check "$PDF"
node packages/tests/scripts/verify-signature.cjs "$PDF"
"$PYTHON" packages/tests/scripts/verify-pades.py "$PDF" "$ROOT_CERT"
openssl ts -verify \
  -queryfile "$ARTIFACT_DIR/request.tsq" \
  -in "$TIMESTAMP_RESPONSE" \
  -CAfile "$ROOT_CERT"
openssl ts -verify \
  -data "$COVERED_BYTES" \
  -in "$TIMESTAMP_RESPONSE" \
  -CAfile "$ROOT_CERT"
```

Record every exit value with the command output. A nonzero project-verifier
exit is evidence of a failed consistency check, not a reason to substitute a
different PDF. The project-owned verifier uses the built public API with
document ByteRange binding, CMS consistency, complete ESS binding,
timestamping EKU, and generation-time checks. Its `PASS` is cryptographic
consistency only. It intentionally reports `TSA trust: NOT EVALUATED`; the
separate pyHanko command establishes trust only against the supplied disposable
local root.

The helper expects exactly one document timestamp and reports JSON fields for timestamp
count, integrity, and trust. Do not substitute an unrelated root merely to obtain a
green result. If the PDF was made with a public TSA and no matching local root exists,
record pyHanko local-root trust as `NOT OBSERVED`.

If those three companion artifacts were not retained from the same run, record the
OpenSSL result as `NOT OBSERVED`. Do not use a response, covered bytes, or root from a
different PDF. qpdf validates syntax and cross-reference structure; project-owned
qpdf-JSON assertions, not qpdf alone, cover DSS/VRI placement in the offline gate.

## Safely import a local test root

Only import a disposable local root generated for this test. Never import an unknown
public TSA root, a TSA leaf certificate, or a root supplied by an unverified document.
Before import, record both the file digest and certificate identity:

```bash
sha256sum "$ROOT_CERT"
openssl x509 -in "$ROOT_CERT" -noout -fingerprint -sha256 -subject -issuer -serial
```

On Windows, record the transferred root file hash without requiring OpenSSL:

```powershell
Get-FileHash -LiteralPath $env:ROOT_CERT -Algorithm SHA256
```

Compare the file hash with the Ubuntu record. Compare the certificate subject,
issuer, serial, and fingerprint recorded on Ubuntu with the certificate details
shown by Reader before enabling trust. In the tested Reader build's
[trusted-certificate manager](https://helpx.adobe.com/acrobat/desktop/protect-documents/encrypt-with-certificates/import-via-digital-sign.html),
import that exact PEM or DER root, limit trust to the timestamp/signature-validation
purpose offered by that build, and record every selected trust checkbox. Restart or
reopen Reader if the build requires it. Do not use a broad "trust all" setting.

In Reader, the trusted-certificate manager is commonly reached through the
product's Preferences dialog under Signatures, then Identities and Trusted
Certificates. Acrobat Standard or Pro can present the same manager through a
different product menu or a different label. Follow the linked Adobe guidance,
choose the equivalent manager for the installed edition, and record the actual
route before changing trust settings.

After the result is captured, find the imported certificate by the recorded SHA-256
fingerprint, subject, and serial; remove only that matching local root; restart Reader;
and record the removal and cleanup time. Delete the private local test-root material
from the test environment. The record must say whether cleanup was completed.

After Reader removal and recording that cleanup, this Windows PowerShell command safely
removes only the retained fixture directory. Do not run it until all Reader and tamper
steps below are complete. It refuses a filesystem root, rejects unexpected entries, and
checks for the expected local-fixture files before deletion:

```powershell
$resolvedArtifactDirectory = (Resolve-Path -LiteralPath $artifactDirectory).Path
$filesystemRoot = [System.IO.Path]::GetPathRoot($resolvedArtifactDirectory)
$directorySeparators = [char[]]@(
    [System.IO.Path]::DirectorySeparatorChar,
    [System.IO.Path]::AltDirectorySeparatorChar
)
$trimmedArtifactDirectory = $resolvedArtifactDirectory.TrimEnd($directorySeparators)
$trimmedFilesystemRoot = $filesystemRoot.TrimEnd($directorySeparators)
if ($trimmedArtifactDirectory -eq $trimmedFilesystemRoot) {
    throw "Refusing to remove a filesystem root"
}

$expectedFixtureFiles = @(
    "timestamped.pdf", "root.pem", "response.tsr", "covered.bin", "request.tsq"
)
$unexpectedEntries = @(
    Get-ChildItem -LiteralPath $resolvedArtifactDirectory -Force | Where-Object {
        $_.PSIsContainer -or $_.Name -notin $expectedFixtureFiles
    }
)
if ($unexpectedEntries.Count -ne 0) {
    throw "Refusing cleanup because the directory contains unexpected entries"
}
foreach ($fileName in $expectedFixtureFiles) {
    $fixturePath = Join-Path $resolvedArtifactDirectory $fileName
    if (-not (Test-Path -LiteralPath $fixturePath -PathType Leaf)) {
        throw "Refusing cleanup because expected fixture file is missing: $fileName"
    }
}
foreach ($fileName in $expectedFixtureFiles) {
    Remove-Item -LiteralPath (Join-Path $resolvedArtifactDirectory $fileName) -Force
}
Remove-Item -LiteralPath $resolvedArtifactDirectory
```

## Reader or Acrobat observation steps

1. Open the original `PDF` whose SHA-256 is on the identity sheet.
2. In Reader, open its Signatures panel and select the timestamp entry. In
   Acrobat Standard or Pro, open the equivalent signature list from its
   installed UI and record the exact route if it has a different label.
3. Record the exact panel classification. The target observation is a document timestamp
   signature, not an approval or certification signature.
4. Open the validation summary and record the exact integrity text. Record separately
   whether Reader reports an intact document/timestamp and whether it reports any warning.
5. Open certificate details and record the TSA certificate path, including the selected
   trust source and any untrusted or revocation state.
6. Open timestamp details and record the displayed timestamp time, time zone, policy or
   TSA information shown by Reader, and exact wording.
7. Record every LTV/revocation UI state. Candidate DSS material is not itself proof of
   trust, freshness, revocation status, general PAdES-LTA, or indefinite validity.
8. Capture the required screenshots with these exact names, redact only data that cannot
   be retained, and describe every redaction:

    - `01-signature-summary.png`
    - `02-tsa-certificate-path.png`
    - `03-timestamp-details.png`

## One-byte covered-range tamper control

On the Ubuntu generation runner, make a copy at an absolute, caller-selected
`TAMPERED` path outside the retained artifact directory. From `packages/tests`
after building the package, run this snippet with absolute `PDF` and `TAMPERED`
values. It changes exactly one covered ASCII space byte to a tab and refuses to
overwrite a file.

```bash
cd packages/tests
PDF=<absolute-original-pdf> TAMPERED=<absolute-tampered-pdf> node --input-type=module <<'NODE'
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { isAbsolute } from "node:path";
import { extractTimestamps } from "pdf-rfc3161";

const source = process.env.PDF;
const target = process.env.TAMPERED;
if (!source || !target || !isAbsolute(source) || !isAbsolute(target)) {
    throw new Error("PDF and TAMPERED must be absolute paths");
}
if (existsSync(target)) throw new Error(`Refusing to overwrite ${target}`);

const bytes = new Uint8Array(readFileSync(source));
const [timestamp] = await extractTimestamps(bytes);
if (!timestamp) throw new Error("No document timestamp found");
const [firstOffset, firstLength, secondOffset, secondLength] = timestamp.byteRange;
let changed = false;
for (const [offset, length] of [[firstOffset, firstLength], [secondOffset, secondLength]]) {
    for (let index = offset; index < offset + length; index += 1) {
        if (bytes[index] === 0x20) {
            bytes[index] = 0x09;
            changed = true;
            break;
        }
    }
    if (changed) break;
}
if (!changed) throw new Error("No covered ASCII space was available for the tamper control");
writeFileSync(target, bytes, { flag: "wx" });
NODE
```

Record the `TAMPERED` SHA-256 on Ubuntu and confirm the project verifier exits
nonzero from the current `packages/tests` directory:

```bash
sha256sum "$TAMPERED"
node scripts/verify-signature.cjs "$TAMPERED"
```

Transfer only that tampered PDF to a separate Windows path and verify its hash
against the Ubuntu record:

```powershell
$env:TAMPERED = "C:\absolute\path\to\tampered.pdf"
Get-FileHash -LiteralPath $env:TAMPERED -Algorithm SHA256
```

Then open the tampered copy in the same Reader settings. Reader must not report it as
intact. Capture the observed wording in the results table; a tampered file reported as
intact is a `FAIL` for this protocol even if another UI field is unavailable.
Delete the separate tampered copy after recording the result.

## Results table

Every cell in the `Result` column must contain only `PASS`, `FAIL`, or `NOT OBSERVED`.
Do not use another status, a blank, or a prose substitute. Put exact UI text, command
output locations, and screenshot hashes in the Evidence column.

| Check                          | Evidence to retain                                                                  | Result       |
| ------------------------------ | ----------------------------------------------------------------------------------- | ------------ |
| Original PDF identity          | PDF SHA-256, commit, lock SHA-256, and absolute path                                | NOT OBSERVED |
| Reader environment             | Product/version/build, OS, locale, architecture, network and revocation preferences | NOT OBSERVED |
| Trust source                   | AATL, EUTL, manual local root, or no root; root fingerprint when manual             | NOT OBSERVED |
| Signature Panel classification | Exact text showing document timestamp classification                                | NOT OBSERVED |
| Original integrity             | Exact Reader validation text                                                        | NOT OBSERVED |
| TSA certificate path           | Screenshot and path/trust-state transcription                                       | NOT OBSERVED |
| Timestamp time                 | Screenshot and displayed time transcription                                         | NOT OBSERVED |
| LTV/revocation UI              | Exact displayed state and any warning                                               | NOT OBSERVED |
| qpdf same-file result          | Version, command, exit status, stdout/stderr, PDF SHA-256                           | NOT OBSERVED |
| pyHanko same-file result       | Version, command, JSON, root fingerprint, PDF SHA-256                               | NOT OBSERVED |
| OpenSSL same-file result       | Version, command, exit status, response/covered-bytes/root hashes, PDF SHA-256      | NOT OBSERVED |
| Screenshot 01                  | `01-signature-summary.png` and its SHA-256                                          | NOT OBSERVED |
| Screenshot 02                  | `02-tsa-certificate-path.png` and its SHA-256                                       | NOT OBSERVED |
| Screenshot 03                  | `03-timestamp-details.png` and its SHA-256                                          | NOT OBSERVED |
| One-byte tamper                | Tampered SHA-256, verifier nonzero result, and Reader does not report intact        | NOT OBSERVED |
| Local-root cleanup             | Matching root removed by fingerprint and cleanup time recorded                      | NOT OBSERVED |

Attach this filled record to the release or issue discussion only after checking its
provenance, privacy, and license. It is evidence for the recorded environment, not a
redistributable Adobe fixture by default.
