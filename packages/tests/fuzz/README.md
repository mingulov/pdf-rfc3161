# T16 Jazzer.js pilot: fuzzing `pdf-rfc3161` parsers

Coverage-guided fuzzing for the six parser entry points in the T16 plan
checkbox, using a locked `@jazzer.js/core` 4.0.0. Gating status: **corpus
replay is REQUIRED, exploration is OPTIONAL** (scheduled + manual,
`continue-on-error`). See `.github/workflows/fuzz.yml`.

## Layout

- `targets/` - TypeScript harnesses, one `fuzz` export per file, plus the
  shared `fuzz-common.ts` (network deny, expected-error wrapper).
- `corpus/<target>/` - checked-in nonempty seeds (19 files, all < 64 KiB).
- `targets.mjs`, `replay.mjs`, `explore.mjs` - plain-node runners (no tsx
  needed at run time).
- `build/` - gitignored tsc output (harness AND core as unbundled ESM).
- `work/` - gitignored run output (logs, coverage, exploration findings).

## Why transpiled unbundled ESM

Jazzer.js cannot execute TypeScript targets directly, and its ESM loader
hooks instrument per-file modules. `../tsconfig.fuzz.json` compiles
`packages/core/src` plus `targets/` to `build/` preserving module
structure; bare imports (`asn1js`, `pkijs`, `pdf-lib-incremental-save`)
resolve from the workspace at run time. The fuzzer instruments the
emitted core path only (`-i fuzz/build/core`).

## Targets

| Target          | Core function                                   | Mode  | Seeds                                             |
| --------------- | ----------------------------------------------- | ----- | ------------------------------------------------- |
| `fuzz-response` | `tsa/response.ts` `parseTimestampResponse`      | sync  | granted / grantedWithMods / rejection TSR         |
| `fuzz-token`    | `tsa/token-validation.ts` `parseTimestampToken` | sync  | raw token / full TSR / dummy token                |
| `fuzz-ocsp`     | `pki/ocsp-utils.ts` `parseOCSPResponse`         | sync  | good / revoked / 2 fuzz-minimized crashes         |
| `fuzz-extract`  | `pdf/extract.ts` `extractTimestamps` (awaited)  | async | timestamped / unsigned / garbage PDF              |
| `fuzz-der`      | `pki/der-utils.ts` both canonical-DER entries   | sync  | valid / budget-exhaustion / depth-limit / garbage |
| `fuzz-rfc5544`  | `rfcs/rfc5544.ts` `parseTimeStampedData`        | sync  | envelope with data / minimal envelope             |

Seed provenance: TSR/token seeds come from `createRFC3161TokenFixture`
(real DER the strict parser accepts; the legacy `TSA_FIXTURES` buffers
are truncated placeholders and are NOT used). OCSP seeds come from
`createOcspResponseCandidate`. The PDF seeds are a one-page input and its
offline-timestamped revision. DER seeds are synthesized with asn1js. The
two `ocsp/` crash seeds are minimized Jazzer.js findings (1 byte each);
the matching unit regressions live in
`test/unit/ocsp-schema-normalization.test.ts`.

The `der` target derives its node budget (1..4096) from the first 2 seed
bytes and parses the remainder with both DER entries under fresh
budgets. Depth-64 nesting needs ~256 bytes, so the standard 64 KiB cap
exercises every DER boundary with no larger-input justification.

## Failure semantics

- Only the expected `TimestampError` is caught; unknown exceptions,
  hangs, and crashes fail the run.
- Networking is stubbed in every target (`globalThis.fetch` throws).
  Attempts are **counted at the fetch seam**, so an attempt fails even
  when core's retry shell wraps the rejection into an "expected"
  `TimestampError(NETWORK_ERROR)`. Core has no other network seam (bare
  global `fetch` only; no `node:http` imports).
- Per-input timeout 2 s (`--timeout 2000` plus libFuzzer `-timeout=2`),
  RSS cap 1 GiB (`-rss_limit_mb=1024`), input cap 64 KiB
  (`-max_len=65536`), outer `timeout 300` per target run.

## Commands (from `packages/tests`)

```bash
corepack pnpm fuzz:build    # tsc -p tsconfig.fuzz.json -> fuzz/build
corepack pnpm fuzz:replay   # REQUIRED gate: regression replay + coverage proof
corepack pnpm fuzz:explore  # OPTIONAL: 60 s/target bounded exploration
corepack pnpm fuzz:explore -- ocsp  # explore one target
```

`fuzz:replay` fails unless every Jazzer run exits 0 AND the Istanbul
coverage proof shows each intended core function hit > 0 times. It also
fails on a missing/empty corpus, so seeds cannot silently vanish.
Per-target logs and `coverage-final.json` land under `work/replay/`.

`fuzz:explore` copies seeds to a scratch corpus per target (the
checked-in corpus stays pristine), runs 60 s per target, and writes
`run.log`, the grown corpus, and any `crash-*`/`timeout-*`/`leak-*`
artifacts under `work/explore/<target>/`. A nonzero exit lists the
artifact paths; minimize and file a regression before re-running.

## Measured costs (Node 24.21.0, Linux x86_64, 2026-10-03)

- Replay: ~1-2 s per target, ~7 s total for all six.
- Exploration: ~62 s per target, ~6.5 min total for all six.
- Throughput per 60 s run: response ~448k, token ~466k, ocsp ~2.05M,
  extract ~8k (async PDF parsing), der ~2.18M, rfc5544 ~347k runs.

## Pilot findings

Exploration found two real bugs in `parseBasicOCSPResponse`, both raw
pkijs `AsnError` escapes normalized to `INVALID_RESPONSE` by this task:

1. `crash-17a37...f69` (52 runs in): nested `BasicOCSPResponse` content
   failing pkijs schema verification (e.g. certStatus `[1]` with
   non-RevokedInfo content). Seed: `ocsp/nested-schema-mismatch.der`.
2. `crash-dc004...bb5` (248k runs in): outer `OCSPResponse` with a
   primitive-encoded inner tag that passes the exact-grammar precheck
   but fails pkijs verification. Seed: `ocsp/primitive-wrapper.der`.

Both minimized to a single flipped byte; see the unit test above.
