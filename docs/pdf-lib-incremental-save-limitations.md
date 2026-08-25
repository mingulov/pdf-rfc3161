# pdf-lib-incremental-save 1.17.4 limitations

`pdf-rfc3161` intentionally uses the official
[`pdf-lib-incremental-save`](https://github.com/remdra/pdf-lib-incremental-save)
package, pinned exactly to `1.17.4` in `packages/core/package.json` and
`packages/tests/package.json`. The upstream package is MIT licensed; its installed
license is available at `packages/core/node_modules/pdf-lib-incremental-save/LICENSE.md`
after installation.

This is a maintainer and deployer boundary note. It does not describe a fixed hostile-PDF
parser. A fork or replacement loader is deferred to separate work. The direct `pako`
dependency previously used by this project for an experimental preflight is gone; `pako`
may still be present transitively through the official dependency.

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

## Task 7 documentation TODO

Task 7 public documentation, migration notes, validator guidance, and issue replies must
link to this note when they describe PDF input handling. They must distinguish the
incremental-write collision guard from hostile-PDF parser hardening and must not claim
that the dependency limitation is fixed.
