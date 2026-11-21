# Acrobat Reader COM oracle attempt (November 2026, unsuccessful)

Status: not merged. The work is preserved on branch
`feat/acrobat-reader-oracle` (9 commits, `c88ade1` through `07ba066`)
and documented here so a retry starts from the failure record instead
of rediscovering it. Until an automated oracle exists, use the
[manual Acrobat Reader validation protocol](manual-acrobat-validation.md).

## Goal

Drive Adobe Acrobat Reader through COM automation on the Windows CI
runner and assert signature state per fixture, using numeric
`Field.signatureValidate` codes only (never UI text):

| Fixture                     | Expected code |
| --------------------------- | ------------- |
| Unsigned PDF                | no fields     |
| Timestamped PDF             | 3 (valid, unverified) |
| Timestamped PDF with LTV    | 3 (valid, unverified) |
| One-byte tampered copy      | 2 (invalid)   |

## Design (on the branch)

- `packages/tests/scripts/acrobat-reader-oracle.ps1` — opens each
  manifest PDF via `AcroExch.App` / `AVDoc` / `PDDoc`, reads signature
  fields through the Acrobat JavaScript bridge, prints one JSON report
  (contract version 1) to stdout. Verdicts are data: unsigned or
  invalid PDFs still exit 0; nonzero exit means the harness failed.
- `packages/tests/test/utils/acrobat-verdict.ts` — strict report
  parser plus per-case assertions. Spawn budget 150 s for the matrix.
- `packages/tests/test/unit/acrobat-reader.test.ts` — vitest wrapper,
  skipped unless win32 with `ACROBAT_READER_TESTS=true`. Builds the
  fixture matrix offline with the stub TSA.
- `packages/tests/scripts/diagnose-reader-com.ps1` — TEMP-DIAG probe
  script (do not merge as-is).
- `.github/workflows/ci.yml` — the `native-pdf-compatibility`
  Windows job installs Reader via winget
  (`Adobe.Acrobat.Reader.64-bit`, machine scope), disables Protected
  Mode through the FeatureLockDown policy key, stamps per-user EULA
  markers, then runs the oracle step.

## Failure record

Every CI run failed at COM activation: `AcroExch.App` creation
returns E_FAIL on the runner. Diagnostics ruled out, one variable at
a time:

1. Missing executable registration — probed 64-bit, WOW6432Node, and
   per-user App Paths keys plus a bounded Adobe install-dir search.
2. Reader 26 executable rename — unified `Acrobat.exe` discovered
   (no `AcroRd32.exe`); both names probed everywhere.
3. Cold-install first activation — executable warm-up launch between
   COM retries; lingering warmup PIDs reaped explicitly after one was
   found hijacking single-instance activation without serving COM.
4. Elevation mismatch — TEMP-DIAG v1/v3 probed 64-bit, 32-bit, and
   unelevated contexts, our integrity level versus the Reader process
   level, and the AppID `RunAs Interactive User` mitigation.
5. First-run dialogs — TEMP-DIAG v2 pre-launched Reader with
   `-Embedding` and enumerated windows during a plain launch.
6. Unaccepted EULA — install with `EULA_ACCEPT=YES` plus per-user
   EULA markers (`07ba066`). Still red; last unverified suspect at
   pause was residual first-run state, but no evidence confirms it.

Reference runs (branch PR #102, since closed): the final run
`41471778832` shows the Windows oracle step exiting 1. That run also
carried two unrelated reds: the PAdES oracle install step (branch was
behind main) and a macOS capacity-queue failure.

## Resume pointers

- Branch: `feat/acrobat-reader-oracle`. Commits `5323926`, `96a640e`,
  and `da955a2` are marked DO NOT MERGE; drop or rework the TEMP-DIAG
  probes before any retry, and rebase onto current main first.
- Roles of each validation tool stay defined in
  [validation-tools.md](validation-tools.md).
- If the retry succeeds, the oracle belongs in the
  `native-pdf-compatibility` Windows job next to the existing
  Windows.Data.Pdf checks, gated the way the branch gates it.
