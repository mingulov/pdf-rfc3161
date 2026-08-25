# pdf-lib-incremental-save 1.17.4 limitations

`pdf-rfc3161` intentionally uses the official
[`pdf-lib-incremental-save`](https://github.com/remdra/pdf-lib-incremental-save)
package, pinned exactly to `1.17.4` in `packages/core/package.json` and
`packages/tests/package.json`. The upstream package is MIT licensed; its installed
license is available at `packages/core/node_modules/pdf-lib-incremental-save/LICENSE.md`
after installation.

## Intended input and responsibility boundary

`pdf-rfc3161` is a PDF timestamp signer, not a PDF sanitizer, repair tool, or hostile-file
security gateway. Its supported signing workflow expects the caller to supply a clean,
structurally valid PDF from a trusted source or from a separately validated intake process.
It appends an incremental timestamp revision and deliberately preserves the existing bytes;
it does not normalize or regenerate the input document.

The potential dependency issues below remain documented so maintainers and deployments that
choose to accept untrusted PDFs understand the boundary. They are not a claim that this
library supports deliberately malformed or adversarial input. A fork or replacement loader
is deferred to separate work. The direct `pako` dependency previously used by this project
for an experimental preflight is gone; `pako` may still be present transitively through the
official dependency.

## What the pinned dependency does

These observations refer to the upstream 1.17.4 source shipped with the installed package:

- `src/core/parser/PDFParser.ts`, `parseDocument()` repeatedly calls
  `parseDocumentSection()` while walking the physical byte stream. Its
  `parseIndirectObjects()` and `skipJibberish()` paths discover physical objects in
  sequence, rather than first restricting parsing to one authoritative active xref graph.
  Historical, stale, or unreferenced physical objects can therefore be encountered.
- In that same file, `parseIndirectObjectHeader()` accepts unbounded PDF
  whitespace/comments between the raw integers and `obj`. `skipJibberish()` tries that
  header parser from arbitrary printable-byte positions, and `matchKeyword()` does not
  require a token boundary around `obj`. A physical object can therefore be discovered
  after a loose prefix that a standards-oriented scanner would not treat as a header.
- In `PDFParser.ts`, `parseIndirectObject()` sends every physical raw stream whose
  `/Type` is `/ObjStm` to `PDFObjectStreamParser.forStream(...).parseIntoContext()` and
  every physical `/Type /XRef` stream to `PDFXRefStreamParser.forStream(...).parseIntoContext()`.
  The `/ObjStm` and `/XRef` container references are not assigned through the normal
  `context.assign(ref, object)` branch. Consequently `context.enumerateIndirectObjects()`
  is not an authoritative largest-object-number view.
- `src/core/parser/PDFObjectParser.ts`, `parseDictOrStream()` uses a stream `/Length`
  only when it is a direct `PDFNumber`. An indirect `/Length` reference, or a direct
  length that does not lead to `endstream`, calls `findEndOfStreamFallback(startPos)`.
  That fallback scans for nested `stream` and `endstream` keywords. It does not resolve
  the indirect length before choosing the stream boundary.
- `src/core/parser/PDFObjectStreamParser.ts` constructs its byte source with
  `ByteStream.fromPDFRawStream()`. `src/core/parser/ByteStream.ts` calls
  `decodePDFRawStream(rawStream).decode()`, and `src/core/streams/DecodeStream.ts`,
  `decode()`, keeps decoding until EOF before returning the accumulated buffer. The
  `PDFXRefStreamParser` constructor also uses `ByteStream.fromPDFRawStream()`.
  The pinned dependency exposes no caller-controlled decoded-size, CPU, or aggregate
  stream budget at this boundary.

Together, these behaviors mean a post-load wrapper cannot safely prove exactly what the
loader considered an object, stream, or allocation boundary. An input-size limit alone is
not a decompression or CPU limit.

## Minimal indirect-Length pseudo-ObjStm reproduction

The following standalone Node ESM example creates exactly 381 bytes. It uses an indirect
`/Length 4 0 R` whose later value is `0`, while the physical stream contains a small
`/ObjStm` payload. In 1.17.4 the indirect length takes the `endstream` fallback path;
the loader accepts the physical object stream and exposes object `5` in its context.

```js
import assert from "node:assert/strict";
import { PDFDocument } from "pdf-lib-incremental-save";

const source = [
    "%PDF-1.5",
    "1 0 obj",
    "<< /Type/Catalog/Pages 2 0 R>>",
    "endobj",
    "2 0 obj",
    "<< /Type/Pages/Count 0/Kids[]>>",
    "endobj",
    "3 0 obj",
    "<</Type/ObjStm/N 1/First 4/Length 4 0 R>>",
    "stream",
    "5 0<<>>",
    "endstream",
    "endobj",
    "4 0 obj",
    "0",
    "endobj",
    "xref",
    "0 5",
    "0000000000 65535 f ",
    "0000000009 00000 n ",
    "0000000055 00000 n ",
    "0000000102 00000 n ",
    "0000000184 00000 n ",
    "trailer",
    "<</Size 5/Root 1 0 R>>",
    "startxref",
    "201",
    "%%EOF",
].join("\n") + "\n";

const bytes = Buffer.from(source.padEnd(381, " "), "latin1");
assert.equal(bytes.length, 381);

const document = await PDFDocument.load(bytes, { updateMetadata: false });
console.log(document.context.enumerateIndirectObjects().map(([ref]) => ref.objectNumber));
// 1.17.4 prints [ 1, 2, 4, 5 ].
```

This is a small behavioral reproduction, not a claim that every parser must accept it.
It illustrates why a project-owned strict preflight cannot safely assert a different
stream interpretation and then claim to bound what the official loader will parse.

## 128 MiB decompression methodology

Do not commit a large fixture and do not run this on a developer workstation or shared
CI runner. In a disposable container with explicit CPU and memory limits, make an
otherwise minimal physical `/Type /ObjStm` or `/Type /XRef` stream with a direct
`/Filter /FlateDecode` and a direct `/Length` equal to `deflateSync` output length.
Use a decoded payload of `128 * 1024 * 1024` bytes. For an object stream, prefix the
payload with a valid small object-stream header such as `5 0 ` and set `/N 1` and
`/First 4`; append the compressed bytes before `endstream`.

For example, the controlled generator's essential allocation is:

```js
const decoded = Buffer.concat([
    Buffer.from("5 0 <<>>", "ascii"),
    Buffer.alloc(128 * 1024 * 1024 - 8, 0x20),
]);
const compressed = deflateSync(decoded);
```

Place `compressed` in the physical stream and load it only inside the resource-limited
container. The relevant loader path is eager physical ObjStm/XRef decoding described
above; the purpose is to measure resource use, not to establish a regression that local
code can prevent before `PDFDocument.load`.

## Local guards in this release

The local mutation boundary reduces a specific writer-collision risk after the official
loader has returned:

- `preparePdfForTimestamp()` and `updateValidationStore()` call
  `restoreLargestObjectNumber()` after `PDFDocument.load()`.
- `packages/core/src/pdf/internals.ts` combines the dependency context references with a
  bounded physical-header scan. It starts at each digit run and recognizes the
  loader-like grammar `N S1 G S2 obj`: `S1` contains at least one PDF whitespace or
  comment separator, while `S2` may be empty or contain those separators. There is no
  required trailing boundary after `obj`, matching the dependency's `matchKeyword`
  behavior. This keeps the scan from missing a loose physical ObjStm/XRef container ID.
  A matching candidate with either separator run over 100 bytes fails closed with
  `PDF_ERROR` rather than being ignored; unrelated long whitespace after an arbitrary
  literal/stream number does not by itself reject. The heuristic shares a separator-work
  budget of eight byte inspections per input byte; repeated ambiguous candidates that
  exhaust it also fail closed with `PDF_ERROR`, so they cannot make the post-load scan
  superlinear. Each number is accumulated only while it remains in the supported safe
  range (`Number.MAX_SAFE_INTEGER - 1`), and a matching unsafe header rejects with
  `PDF_ERROR`.
- The scan is a compatibility heuristic for omitted physical ObjStm/XRef container IDs,
  not an xref parser. Literal strings and stream bytes can look like headers. A safe
  false positive can overestimate the next object number; this either allocates a later
  safe number or fails closed. It must never justify reuse of a possibly occupied number.
- Every new core mutation-time object registration goes through `checkedRegister()`.
  It rejects unsafe arithmetic and verifies the number returned by the dependency.
- `prepare.ts` and `validation-store.ts` force the incremental writer's
  `context.pdfFileDetails.useObjectStreams = false`. This prevents the mutation writer
  from inventing unchecked ObjStm/XRef container references in the new revision.

These guards do not validate the input xref graph, resolve indirect stream lengths,
bound parser decompression, decide whether a physical object is active, or prove that a
hostile PDF was parsed correctly. They do not make the official loader a strict parser.

The official loader does not expose raw active offsets or revision ownership for the
objects it returns. Project code therefore cannot turn a post-load context lookup into
proof that a particular physical object occurrence belongs to the active revision. Where
the project needs to associate a project-generated signature dictionary with raw bytes,
an ambiguous project signature occurrence fails closed rather than selecting an
occurrence heuristically. Targeted ByteRange checks do not harden the loader: they check
only a selected signature's byte geometry after loading and cannot constrain the
physical object, stream, or allocation decisions made during loading. Parser hardening,
an authoritative active-revision model, and any replacement-loader work are future work
separate from these mutation-time guards.

## Project-owned timestamp occurrence boundary

Timestamp extraction adds a separate, deliberately narrow post-load check in
`signature-occurrence-index.ts`. It is a narrow lexical partial parser, not a full or
authoritative PDF loader or xref resolver, and does not alter the official
`pdf-lib-incremental-save@1.17.4` package. The check makes a selected document-timestamp
`/Contents` occurrence fail closed when the project cannot bind its raw hexadecimal token
to the selected `/ByteRange` gap and physical signature owner. It lexically skips
comments, literal strings, hexadecimal strings, and stream payloads before considering a
physical indirect-object header. It also requires the selected gap to include the complete
hexadecimal token delimiters.

For a current or earlier signed revision, the check records only lexically framed
append boundaries. A classic target must contain at least one syntactically framed xref
subsection and horizontally framed entry followed by a trailer dictionary. An XRef-stream
target must be a complete physical indirect object with exact root `/Type /XRef`. A later
boundary needs one direct unsigned `/Prev` whose value is the preceding accepted xref
offset. The bytes between accepted boundaries may contain only whitespace/comments,
complete physical objects, and the accepted xref framing; no object can follow the chosen
xref target before its `startxref`. A tightly framed two-xref linearized base is collapsed
to its `/L` endpoint before ordinary append checks begin. This rejects a terminal
`startxref` that merely points back to an old xref or an arbitrary appended token sequence.

This is lexical append-boundary evidence, not authoritative xref-chain validation. It
does not resolve xref entries, prove that a physical object is active/reachable, validate
the loader's interpretation of an indirect stream `/Length`, or establish revision
ownership from the dependency context. Ambiguous selected signature ownership fails
closed; it performs no unrelated semantic resolution or normalization. The source
regressions in `signature-occurrence-index.test.ts`, `byte-range-geometry.test.ts`, and
`nested-document-timestamp.test.ts` cover lexical spoofing, signed number spellings,
framed classic/XRef-stream updates, `/Prev` linkage, linearized bases, and valid
xref-stream source PDFs whose new timestamp revision is classic.

The project-owned scanner caps aggregate lexical work at four times the maximum PDF size
(1,000 MiB), physical-candidate attempts at 1,000,000, timestamp `/Contents` occurrences
at 1,024 per object, and collected `startxref`/EOF markers at 4,096 per PDF. Each physical
object and classic-xref trailer parse has a separate 100,000 retained-structure cap: every
returned parsed value, retained dictionary, and retained dictionary entry counts before it
is collected. The scanner uses binary boundary membership lookup. Shared selected `/V`
values are decoded, bound, metadata-parsed, and CMS-verified once per PDF-level operation.
Extracted fields sharing that value share the raw token and complete `/Contents` buffers and
a decoded token nonce by read-only convention; callers must copy any of those buffers before
mutation. Duplicate verification results likewise share their selected certificate array by
read-only convention. Archive renewal verifies values sequentially and collects shared LTV
candidate material once. A fixed 512 MiB aggregate covered-byte budget is charged before each
distinct verification can copy or hash PDF bytes.
`verifyPdfTimestamps` retains result order and returns `verified: false` for an exhausted
value; default archive renewal warns and continues, while `strictExistingVerification`
rejects before mutation. Those bounds reduce repeated work in project code after loading.
They do not bound the official loader's decompression, parser CPU, memory use, or
active-object model; keep the sandbox and resource limits above for hostile inputs.

## Operational mitigations

- Treat hostile or tenant-supplied PDFs as untrusted code-like input for CPU and memory
  planning. Run parsing and timestamp preparation in a sandbox with explicit memory,
  CPU, wall-clock, and concurrency limits.
- Keep the existing byte-size limit, but do not rely on it alone: a small compressed
  stream can expand substantially, and many physical streams can be encountered.
- Prefer trusted PDF sources when a sandbox is unavailable. Reject or quarantine inputs
  whose origin and resource budget are not acceptable to the deployment.
- Do not normalize or rewrite an already signed PDF as a mitigation. Rewriting changes
  signed byte ranges and breaks existing signatures. Preserve the original bytes and
  inspect a copy only in an isolated environment.
- Report upstream parser defects to the official dependency as well as reporting their
  impact through this project's security channel.

## Future strict-loader acceptance checklist

Do not remove this boundary note or the hostile-input sandbox recommendation until a
reviewed loader replacement or upstream release provides all of the following:

1. A documented, bounded parser with safe integer handling and authoritative indirect
   `/Length` resolution before stream boundary recovery.
2. One xref-reachable active object graph, including object-stream and xref-stream
   container IDs, with no eager scan of stale or unreferenced physical objects.
3. Enforced decoded-byte, CPU, recursion, object-count, and aggregate resource budgets
   for every supported filter before materializing decoded streams.
4. Tests for malformed indirect lengths, pseudo ObjStm/XRef input, stale revisions,
   compressed object streams, large expansion ratios, and object-number collision
   boundaries, plus independent parser review or differential validation.
5. A versioned dependency update, license review, package ESM/CJS smoke coverage, and a
   security review that verifies the new boundary in the actual edge-runtime build.

## Maintainer documentation boundary

Public documentation, migration notes, validator guidance, and issue replies that
describe PDF input handling should link to this note. They must distinguish the
incremental-write collision guard from hostile-PDF parser hardening and must not claim
that the dependency limitation is fixed. When the dependency version or integration
changes, update the affected entries with reproducible evidence while retaining that
boundary.
