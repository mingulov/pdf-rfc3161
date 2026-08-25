# Validation tools and their roles

This project uses several independent tools because no single tool establishes PDF
structure, RFC 3161 cryptography, certificate trust, and viewer behavior at once. The
normative PAdES baseline for this work is [ETSI EN 319 142-1 V1.2.1
(2024-01)](https://www.etsi.org/deliver/etsi_EN/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf).
The [V1.3.0 work item](https://portal.etsi.org/webapp/workprogram/Report_WorkItem.asp?WKI_ID=73780)
is an approval-stage draft, not this project's normative baseline.

For this work, EN 319 142-1 describes the VRI key input as the complete
hexadecimal string in `/Contents`; it makes VRI optional and says it `SHOULD
NOT` be used in the baseline profile. The project uses an uppercase SHA-1 over
the complete decoded, padded PDF-string value as an implementation
interpretation. The PDF specification explicitly mentions zero padding, and
an earlier ETSI text explicitly described decoded bytes, but neither source
turns that interpretation into a claim that every producer follows it. See
[ISO 32000-2:2020](https://www.pdfa-inc.org/product/iso-32000-2-pdf-2-0-bundle-sponsored-access/)
and [ETSI TS 102 778-4](https://www.etsi.org/deliver/etsi_TS/102700_102799/10277804/01.01.01_60/ts_10277804v010101p.pdf).

## Required role matrix

| Tool                  | Required CI role                                   | Not an oracle for                            |
| --------------------- | -------------------------------------------------- | -------------------------------------------- |
| qpdf                  | PDF syntax, xref, object graph, DSS/VRI placement  | CMS/TSA trust                                |
| OpenSSL               | RFC 3161 token and imprint cryptography            | PDF object semantics                         |
| pyHanko 0.36.2        | timestamp discovery, integrity, local-root trust   | normative VRI-key encoding                   |
| Adobe Acrobat Reader  | manual viewer classification and UI/trust behavior | deterministic CI                             |
| TrueDoc pinned commit | future non-gating digest/CMS differential signal   | #61, #62, path validation, PAdES conformance |
| EU DSS/iText          | optional manual comparison                         | bundled MIT dependency                       |

The matrix describes the project-owned test layer, not a claim that every listed tool
implements every check itself. In particular, `qpdf --check` validates PDF structure;
the offline conformance harness reads `qpdf --json` and makes project-owned assertions
about `/Type /DocTimeStamp`, Catalog to DSS linkage, and DSS/VRI placement. A clean qpdf
exit code alone is not a semantic VRI assertion.

The required offline gate is intentionally layered:

```bash
corepack pnpm@10.30.3 build
corepack pnpm@10.30.3 --filter pdf-rfc3161-tests test:conformance
corepack pnpm@10.30.3 --filter pdf-rfc3161-tests test:package
```

`test:conformance` creates its own local root and TSA, checks the generated PDF with
qpdf, pyHanko, and OpenSSL, and proves that a one-byte covered-range change fails the
imprint checks. `test:package` uses a packed artifact, rather than the Vitest source
alias, for ESM, CJS, and Vite consumer checks.

By default, `test:conformance` removes its temporary local-root artifacts. The
[manual Acrobat protocol](manual-acrobat-validation.md#retain-a-disposable-local-root-fixture)
documents its explicit `--output-dir` mode for a later same-file Reader, pyHanko, and
OpenSSL observation; that retained directory contains private disposable keys and must
be cleaned up by its caller.

## What each result means

- qpdf provides a structural PDF view and detects syntax/xref problems. It does not
  verify CMS signatures or decide whether a TSA is trusted.
- OpenSSL verifies the RFC 3161 token and message imprint when given the matching token,
  covered bytes, and trust input. It does not resolve the PDF Catalog or determine
  whether a signature dictionary is a PAdES document timestamp.
- pyHanko discovers document timestamps and can verify integrity and a deliberately
  supplied local root. Its current VRI producer behavior is not the normative rule for
  this project. In pinned 0.36.2, the
  [`async_add_validation_info` path](https://github.com/MatthiasValvekens/pyHanko/blob/v0.36.2/pkgs/pyhanko/src/pyhanko/sign/validation/dss.py#L694-L703)
  passes lowercase ASCII hex of the decoded, padded contents to its VRI helper. That is
  not pyHanko's general producer rule: its
  [archival timestamp-chain path](https://github.com/MatthiasValvekens/pyHanko/blob/v0.36.2/pkgs/pyhanko/src/pyhanko/sign/signers/pdf_signer.py#L1011-L1017)
  passes raw `last_timestamp.pkcs7_content`, and
  [normal post-sign VRI work](https://github.com/MatthiasValvekens/pyHanko/blob/v0.36.2/pkgs/pyhanko/src/pyhanko/sign/signers/pdf_signer.py#L2701-L2706)
  starts from raw `fill_with_cms` contents. These path-specific differences are not an error claim
  and do not select this project's VRI output rule. [pyHanko describes itself as beta
  and not production-ready](https://github.com/MatthiasValvekens/pyHanko/blob/v0.36.2/README.md#L10-L18),
  so it is a useful independent check rather than a conformance authority.
- Acrobat Reader is a manual compatibility observation. Use the reproducible checklist
  in [manual-acrobat-validation.md](manual-acrobat-validation.md), record the exact
  Reader build and environment, and do not turn one build's UI wording into an API
  contract.

## TrueDoc: optional differential signal only

Treat [TrueDoc at commit
`0a93f5ea218d4a50f8526bf7eb8c6cab69a0f26c`](https://github.com/signedbyai/truedoc/tree/0a93f5ea218d4a50f8526bf7eb8c6cab69a0f26c)
as untrusted and immature for project acceptance decisions. At that exact commit its
[verification source](https://github.com/signedbyai/truedoc/blob/0a93f5ea218d4a50f8526bf7eb8c6cab69a0f26c/verify-core.mjs#L175-L270)
uses lexical PDF scans and a nearest-dictionary window. Although it reads a dictionary
type, its classification uses the SubFilter mapping rather than requiring
`/Type /DocTimeStamp`; it therefore cannot distinguish the #61 regression. Its DSS/VRI
handling is a trailing-byte heuristic, not Catalog/DSS/VRI graph parsing, so it cannot
detect #62 or verify compressed DSS content. Its [certificate selection and chain
logic](https://github.com/signedbyai/truedoc/blob/0a93f5ea218d4a50f8526bf7eb8c6cab69a0f26c/verify-core.mjs#L520-L565)
also does not provide the RFC 5280 path-validation, revocation, ESS, or EKU checks that
this project needs for a trust claim. Its [certificate selection](https://github.com/signedbyai/truedoc/blob/0a93f5ea218d4a50f8526bf7eb8c6cab69a0f26c/verify-core.mjs#L678-L683)
also selects the first CMS certificate rather than the SignerInfo SID, so it is not a
signer-selection oracle.

TrueDoc is therefore not an acceptance oracle for #61, #62, Catalog/DSS/VRI placement,
path trust, or PAdES conformance. Its [current workflow explicitly permits a green run
with zero fixture PDFs](https://github.com/signedbyai/truedoc/blob/0a93f5ea218d4a50f8526bf7eb8c6cab69a0f26c/.github/workflows/verify.yml#L46-L51).

After separate code review and fixture review, a future job may pin this exact reviewed
SHA and run it only on a schedule as a non-gating differential. Such a job must use
project-owned positive DocTimeStamp fixtures, a one-byte covered-range tamper fixture,
and structural #61/#62 mutation fixtures; it must assert known outcomes and fail when
zero fixtures were checked. It can offer a digest/CMS variance signal only. It must not
be used for trust, path-validation, or PAdES acceptance.

## License and redistribution boundary

This section is technical release guidance, not legal advice. Recheck the exact release
and all transitive dependencies before distribution.

- [qpdf](https://github.com/qpdf/qpdf/blob/main/LICENSE.txt) is Apache-2.0, and
  [pyHanko 0.36.2](https://github.com/MatthiasValvekens/pyHanko/blob/v0.36.2/LICENSE)
  is MIT. [OpenSSL 3](https://docs.openssl.org/3.0/man7/migration_guide/) is Apache-2.0.
  They are suitable as separately installed CI tools for this MIT project; they are not
  bundled into the published JavaScript package.
- [EU DSS](https://github.com/esig/dss/blob/master/LICENSE) is LGPL-licensed, and
  [iText](https://github.com/itext/itext-java/blob/develop/LICENSE.md) is AGPL or
  commercial depending on the distribution arrangement. They remain optional, manually
  installed comparison tools. Do not add either to the normal package or CI dependency
  graph without a license review of the intended distribution model.
- TrueDoc is [Apache-2.0](https://github.com/signedbyai/truedoc/blob/0a93f5ea218d4a50f8526bf7eb8c6cab69a0f26c/LICENSE#L90-L142)
  and has a [NOTICE file](https://github.com/signedbyai/truedoc/blob/0a93f5ea218d4a50f8526bf7eb8c6cab69a0f26c/NOTICE#L1-L13).
  This project does not redistribute it. If a future change redistributes TrueDoc or a
  derivative, include the Apache license, mark modified files, retain applicable
  notices, and carry a readable NOTICE attribution. Private review or derivation alone
  is not a redistribution event. Apache-2.0 section 6 permits customary factual
  origin description and NOTICE reproduction; it does not license TrueDoc or SignedBy
  names and logos as project branding or imply their endorsement.

## Related boundaries

The required validators do not change the PDF loader trust boundary. The project stays
on the official `pdf-lib-incremental-save@1.17.4`; its loader limitations are separate,
documented, and deferred in [pdf-lib-incremental-save-limitations.md](pdf-lib-incremental-save-limitations.md).
Use a resource-limited sandbox for hostile PDFs.
