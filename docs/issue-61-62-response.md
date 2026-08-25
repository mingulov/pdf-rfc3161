# Paste-ready responses for issues #61 and #62

These are maintainer drafts. They describe the merged behavior and offline evidence but
do not post to GitHub, claim universal Adobe approval, or change the separate hostile-PDF
loader boundary.

## Issue #61: DocTimeStamp classification

> Thanks for reporting this. We confirmed both root causes.
>
> First, the AcroForm field was correctly `/FT /Sig`, but its signature value dictionary
> was emitted as `/Type /Sig` rather than `/Type /DocTimeStamp`. The field remains
> `/FT /Sig`; only the value dictionary changes. Second, the official
> `pdf-lib-incremental-save@1.17.4` writer excludes `/Type /Sig` objects from object
> streams, so changing the type alone would hide the fixed-width `/Contents` placeholder
> required for ByteRange embedding.
>
> The fix now emits `/Type /DocTimeStamp` with `/SubFilter /ETSI.RFC3161`, preserves
> `/FT /Sig`, forces the timestamp-placeholder incremental revision through the classic
> writer, and preserves the original PDF bytes as an exact prefix. The required offline
> evidence is qpdf structural validation plus project-owned object assertions, pyHanko
> document-timestamp discovery and local-root validation, and OpenSSL RFC 3161
> token/imprint verification:
>
> ```bash
> corepack pnpm@10.30.3 build
> corepack pnpm@10.30.3 --filter pdf-rfc3161-tests test:conformance
> ```
>
> Could you please retest the resulting file in your Acrobat Reader build and share the
> version/build, trust configuration, and observed Signature Panel classification using
> the manual protocol? That observation is valuable compatibility evidence, but we are
> not claiming universal Adobe approval.
>
> The project continues to use the official dependency pinned exactly to `1.17.4`. Its
> loader/parser limitations are documented separately and remain deferred; this fix does
> not claim to repair them. See [the maintainer boundary note](https://github.com/mingulov/pdf-rfc3161/blob/main/docs/pdf-lib-incremental-save-limitations.md).

## Issue #62: additive DSS and signature-specific VRI

> Thanks for the detailed report. We confirmed the regressions: VRI was written at the
> Catalog instead of under `/DSS`, DSS replacement could discard existing validation
> data and VRI entries, the VRI key came from the wrong source, and cross-load object
> references could collide.
>
> DSS updates are now additive. Existing global `Certs`, `CRLs`, `OCSPs`, `VRI`, and
> unknown DSS keys are preserved; byte-identical validation streams are reused; and every
> VRI reference is shared with the corresponding global DSS array. The explicit opt-in
> replacement is:
>
> ```ts
> import { addVRIForSignature } from "pdf-rfc3161/internals";
>
> const updated = await addVRIForSignature(
>     pdf,
>     { fieldName: "Timestamp" },
>     { validationData: { certificates, crls, ocspResponses } }
> );
> ```
>
> Its VRI key is uppercase SHA-1 over the exact decoded, fully padded `/Contents` value
> bytes from the selected signature field. It is not a certificate hash, ASCII-hex hash,
> trimmed DER-token hash, SHA-256 key, or caller-provided PDF reference. The
> decoded-value interpretation is an evidence-backed PDF-string inference, not a claim
> that the ETSI wording alone spells out every encoding detail.
>
> In pinned pyHanko 0.36.2, the `async_add_validation_info` path passes an ASCII
> lowercase-hex representation of decoded, padded contents to its VRI helper. Its
> archival timestamp-chain passes raw `last_timestamp.pkcs7_content`, while normal
> post-sign VRI work starts from raw `fill_with_cms` contents. This is a path-specific
> producer disagreement, not a general pyHanko key claim, an error claim, or the
> normative oracle for this output. VRI itself is optional, and ETSI
> EN 319 142-1 says it `SHOULD NOT` be used in the baseline profile;
> `archiveTimestamp` therefore merges global DSS material but never creates VRI entries
> automatically. Call the explicit API only when a caller has a field-specific
> interoperability reason.
>
> The legacy `addVRI` and `addVRIEnhanced` wrappers remain exported but deprecated. They
> require `signatureFieldName` and delegate safely, or reject unsafe cross-context
> references and unsupported key choices with `INVALID_ARGUMENT`.
>
> The focused structural evidence is included in the offline conformance and VRI tests:
>
> ```bash
> corepack pnpm@10.30.3 --filter pdf-rfc3161-tests exec vitest run \
>   test/unit/vri.test.ts test/unit/vri-enhanced.test.ts test/unit/validation-store.test.ts
> corepack pnpm@10.30.3 --filter pdf-rfc3161-tests test:conformance
> ```
>
> The validation-tool roles and the normative/documentation caveats are recorded in
> [validation-tools.md](https://github.com/mingulov/pdf-rfc3161/blob/main/docs/validation-tools.md).
