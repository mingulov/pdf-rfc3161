# Maintenance and security review: 2026-10-20

## Scope and original failure

Reviewed the library, CLI, demo, dependency graph, packaged consumers and
CI/release tooling at base commit `432e02fbc6ab4f6a9c09b8f0fee742ad45632bf9`.
This is a source and regression-test review, not a claim that all vulnerabilities
are absent or that hostile PDFs are safe to process without isolation.

The scheduled [Security Audit run](https://github.com/mingulov/pdf-rfc3161/actions/runs/39093274897)
failed on two development-tool transitive dependencies:

- `shell-quote` 1.10.0: critical command-injection advisory
  [GHSA-pqg4-j6r4-53mv](https://github.com/advisories/GHSA-pqg4-j6r4-53mv).
  The refreshed lockfile resolves 1.12.0 (patched floor: 1.11.0).
- `source-map-js` 1.2.1: high denial-of-service advisory
  [GHSA-68fv-2mgg-jv7q](https://github.com/advisories/GHSA-68fv-2mgg-jv7q).
  The refreshed lockfile resolves 1.2.2.

The original `pnpm audit --json` reproduced one critical and one high finding.
After the update it reports zero findings at every severity. The blocking
moderate-level CI audit remains enabled; no advisory was ignored. A lockfile
regression test rejects the known vulnerable versions.

## Direct JavaScript dependency updates

| Dependency | Before | After |
| --- | --- | --- |
| `@playwright/test` | `^1.63.0` | `^1.64.1` |
| `@types/node` | `^26.6.3` | `^26.6.5` |
| `@vitejs/plugin-react` | `^6.1.1` | `^6.1.2` |
| `@vitest/coverage-v8` | `^5.0.2` | `^5.0.5` |
| `asn1js` | `^3.0.10` | `^3.1.0` |
| `eslint` | `^10.11.0` | `^10.13.0` |
| `eslint-plugin-security` | `^4.1.0` | `^4.2.0` |
| `globals` | `^17.12.0` | `^17.13.0` |
| `lucide-react` | `^1.49.0` | `^1.59.0` |
| `playwright` | `^1.63.0` | `^1.64.1` |
| `pnpm` | `12.3.4` | `12.14.0` |
| `prettier` | `^3.9.9` | `^3.9.10` |
| `pvutils` | `^1.2.0` | `removed (unused direct test dependency)` |
| `react` | `^19.3.0` | `^19.3.1` |
| `react-dom` | `^19.3.0` | `^19.3.1` |
| `tsup` | `^8.5.1` | `^9.0.0` |
| `typescript-eslint` | `^8.71.0` | `^8.71.2` |
| `vite` | `^8.3.1` | `^8.3.4` |
| `vitest` | `^5.0.2` | `^5.0.5` |

Transitive updates include `qs` 6.16.1, PostCSS 8.5.31, Rollup 4.64.10 and
Rolldown 1.2.14. Existing obsolete release-age exceptions were removed rather
than adding new exemptions.

### Deliberate retentions

- With explicit maintainer approval, the Node.js minimum moves from 22.12.0
  to 22.18.0 and tsup moves from 8.5.1 to 9.0.0. Node 22.12-22.17 support is
  intentionally dropped. The changeset is a minor release, not a patch;
  `MIGRATION.md` explains the compatibility change.
- Fresh registry checks also found typescript-eslint 8.72.0 (published
  2026-10-19 17:08 UTC), lucide-react 1.60.0 (2026-10-20 06:15 UTC), and
  ASN1.js 4.0.0 (2026-10-19 14:54 UTC). They remain inside pnpm's default
  24-hour release-age cooldown at review time; no exemption is introduced.
  ASN1.js 4 also lies outside PKIjs 3.4.1's `asn1js: ^3.0.6` dependency
  contract, so it needs a coordinated compatibility migration rather than
  forcing duplicate ASN.1 class families into the cryptographic graph.
- `pdf-lib-incremental-save` remains 1.17.4, the current published version and
  an intentional dependency required to preserve existing signatures. It was
  not replaced with vanilla `pdf-lib`.
- PKIjs 3.4.1, TypeScript 7.0.2 plus its 6.0.2 API compatibility bridge,
  Stryker 10.0.0, esbuild 0.28.2 and the other unchanged direct dependencies
  remain on their current compatible published versions.
- Transitive `pvutils` 1.2.0 remains required by ASN1.js/PKIjs. The unused direct
  declaration in the private tests package was removed instead of forcing
  transitive consumers across an unsupported major-version boundary.

## Confirmed source findings and corrections

1. **PDF metadata syntax injection.** `PDFString.of` does not escape arbitrary
   text. Caller-controlled reason, location, contact information and signature
   field names could add dictionary entries. Literal ASCII delimiters and
   backslashes are now escaped; Unicode/control text is encoded as UTF-16BE
   hex strings. Tests cover all fields, both object-stream modes, malformed
   delimiters, backslashes, control characters, Unicode, unchanged ByteRange,
   and preservation of the original PDF bytes.
2. **CMS algorithm-profile validation.** PKIjs can select a verification family
   from the signer key while ignoring incompatible algorithm declarations.
   The library now checks declared key/signature/digest compatibility and
   RSA/ECDSA/PSS parameters before cryptographic verification. This finding
   was a profile-validation weakness, not evidence of signature forgery or
   trust-chain bypass. Genuine RSA, ECDSA and PSS signatures remain covered.
3. **Generated demo commands/scripts.** Certificate-provided URLs previously
   entered shell commands without quoting. Exploitation required a person to
   copy and execute the displayed command; the demo did not execute it
   automatically. Shared POSIX quoting, HTTP(S) validation, an option
   terminator and literal curl URL handling now preserve URL data. Generated
   JavaScript uses JSON string encoding for URL, content type and labels.
4. **Malformed-URL diagnostic leakage.** Failed URL parsing exposed the raw
   input in both the message and native error cause. Failures now use fixed
   diagnostics without retaining native `input`; tests check nested error
   fields, credentials, query tokens and fragments.
5. **Demo batch verification bounds.** Multi-signature verification uses the
   existing batch API so callers share a structural index and the aggregate
   verification budget rather than multiplying independent verification work.

## CI and independent validation tooling

- All actions remain immutable SHA-pinned. Updated setup-node, upload/download
  artifacts, setup-uv, CodeQL and the optional Snyk action to their checked
  compatible revisions; unchanged actions were already current.
- Python 3.12.15, uv 0.13.3, pyHanko 0.38.0 and certvalidator 0.33.0 are pinned.
  Python dependencies remain hash locked. The new uv archive checksum is
  explicitly pinned.
- Native oracle packages use the 2026-10-20 Ubuntu snapshot and verified
  SHA-256 hashes. OpenSSL receives Ubuntu revision `3.0.13-0ubuntu3.16`; qpdf
  remains 11.9.0. The isolated rootfs does not replace host system packages.
- The Node 22/24/26 matrix remains intact. An additional packed-consumer job
  runs on exact Node 22.18.0 after building on Node 26, verifying the public
  runtime floor separately from developer-tool engine requirements.
- The updated offline PAdES interoperability gate passes all 182 cases.

### Bundle budget attribution

The main ESM artifact grows from 263,983 to 267,933 bytes (+3,950; 1.50%),
and gzip level 9 from 57,931 to 58,734 bytes (+803; 1.39%). This is the
measured cost of the additional CMS algorithm/parameter validation, literal
PDF text encoding and refreshed build tooling. The hard ceiling increases
from 258 to 262 KiB (268,288 bytes); it remains enforced, not disabled or
made non-blocking. The associated policy test is updated explicitly.

## Boundaries retained

- **Unresolved optional RFC APIs:** independent review found that the RFC 8933
  reporting helper can return a false-positive compliance result for mixed
  digest/signature declarations or an empty CMSAlgorithmProtection attribute.
  The RFC 5544 helper's self-produced envelope can pass its own round-trip
  checks while being rejected by an independent ASN.1 implementation. Do not
  use these helper reports as independent standards-conformance evidence.
  Correcting their full contracts/wire format needs a separately reviewed
  compatibility change, not a rushed dependency-refresh rewrite.
- **Unresolved upstream strictness:** pre-existing PKIjs behavior can accept
  trailing bytes in an ECDSA signature value or a relabeled outer X.509
  signature-algorithm declaration. Review reproduced representation/profile
  acceptance, not a mathematical signature forgery. Additional canonical
  encoding and certificate-algorithm checks warrant focused follow-up.
- The bundled default trust store is intentionally empty and fail-closed.
  Applications must supply verified pinned trust roots or explicitly choose
  unanchored validation. This maintenance does not invent trust anchors.
- The upstream PDF parser is not a hardened hostile-input sandbox. Its
  documented decompression/object-stream limitations still require an
  isolated, resource-limited intake boundary for untrusted PDFs.
- Live public-TSA integration and release/deployment jobs are not triggered by
  pull requests. PR success must not be described as a completed deployment
  or a fresh live-TSA qualification. Optional Snyk/coverage-upload services
  retain their existing conditional/non-blocking behavior.
- Local sandbox restrictions prevent some IPC sockets and loopback-dependent
  tests. Those failures were reproduced on unchanged main; they are not
  converted into skipped tests or relaxed assertions. GitHub CI checks the
  exact PR revision on normal runners.

## Verification record

See the pull request for the final exact commit, check links and counts.
The new findings were reproduced before their fixes and reviewed independently.
No release, deployment, merge or automatic merge is performed by this change.
