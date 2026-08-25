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

| Tool                 | Required role                                      | Not an oracle for          |
| -------------------- | -------------------------------------------------- | -------------------------- |
| qpdf                 | PDF syntax, xref, and JSON object-graph input      | CMS/TSA trust or DSS policy |
| OpenSSL              | RFC 3161 token and imprint cryptography            | PDF object semantics       |
| pyHanko 0.36.2       | timestamp discovery, integrity, local-root trust   | normative VRI-key encoding |
| Adobe Acrobat Reader | manual viewer classification and UI/trust behavior | deterministic CI           |

The matrix describes the project-owned test layer, not a claim that every listed tool
implements every check itself. In particular, `qpdf --check` validates PDF structure;
the offline interoperability harness reads `qpdf --json` and makes project-owned assertions
about `/Type /DocTimeStamp`, Catalog to DSS linkage, and DSS/VRI placement. A clean qpdf
exit code alone is not a semantic VRI assertion.

The required offline interoperability gate is intentionally layered. On a
clean Ubuntu 24.04 AMD64 runner, first follow the
[pinned-tool clean-run recipe](pades-oracle-tools.md#run-from-a-clean-checkout),
then run:

```bash
corepack pnpm@10.30.3 build
PYTHON=/tmp/pdf-rfc3161-pades-python/bin/python \
  corepack pnpm@10.30.3 --filter pdf-rfc3161-tests test:interoperability
corepack pnpm@10.30.3 --filter pdf-rfc3161-tests test:package
```

`test:interoperability` creates its own local root and TSA, checks the generated PDF with
qpdf, pyHanko, and OpenSSL, and proves that a one-byte covered-range change fails the
imprint checks. `test:package` uses a packed artifact, rather than the Vitest source
alias, for ESM, CJS, and Vite consumer checks.

By default, `test:interoperability` removes its temporary local-root artifacts. The
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
  starts from raw `fill_with_cms` contents. These path-specific differences are not an
  error claim and do not select this project's VRI output rule. It remains a useful
  independent check rather than a normative authority.
- Acrobat Reader is a manual compatibility observation. Use the reproducible checklist
  in [manual-acrobat-validation.md](manual-acrobat-validation.md), record the exact
  Reader build and environment, and do not turn one build's UI wording into an API
  contract.

## Additional validator policy

A future third-party validator may be useful as a non-gating differential signal, but
only after its exact source revision, parser model, certificate selection, validation
scope, fixture coverage, zero-input behavior, and license have been reviewed. Exercise
it with project-owned positive fixtures, a one-byte covered-range tamper fixture, and
the structural issue #61/#62 mutation fixtures. Assert the expected outcomes and fail
when zero fixtures are checked. Such a differential must not replace the required PDF
structure, RFC 3161 cryptography, local-root trust, or manual viewer checks above.

## License and redistribution boundary

This section is technical release guidance, not legal advice. Recheck the exact release
and all transitive dependencies before distribution.

- [qpdf](https://github.com/qpdf/qpdf/blob/main/LICENSE.txt) is Apache-2.0, and
  [pyHanko 0.36.2](https://github.com/MatthiasValvekens/pyHanko/blob/v0.36.2/LICENSE)
  is MIT. [OpenSSL 3](https://docs.openssl.org/3.0/man7/migration_guide/) is Apache-2.0.
  They are suitable as separately installed CI tools for this MIT project; they are not
  bundled into the published JavaScript package.
- Any additional comparison tool must remain outside the published JavaScript package
  until its exact release, transitive dependencies, redistribution model, and required
  notices have been reviewed.

## Related boundaries

The required validators do not change the PDF loader trust boundary. The project stays
on the official `pdf-lib-incremental-save@1.17.4`; its loader limitations are separate,
documented, and deferred in [pdf-lib-incremental-save-limitations.md](pdf-lib-incremental-save-limitations.md).
Use a resource-limited sandbox for hostile PDFs.
