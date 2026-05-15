# pdf-rfc3161

Pure-JS RFC 3161 PDF timestamping library. Monorepo with edge-runtime support (no native deps).

`AGENTS.md` is a symlink to this file — keep it that way (works for Codex, Cursor, Jules CLI, etc.).

## Commands

```bash
pnpm install            # uses pnpm workspaces — npm/yarn won't work
pnpm build              # builds all packages (tsup → ESM + CJS dual)
pnpm test               # 501 unit tests; ~65s wall-clock (real backoff timers)
pnpm typecheck          # tsc --noEmit, all packages
pnpm lint               # eslint --fix, all packages
pnpm cli -- <args>      # run CLI from source (tsx)
pnpm test:full          # adds robustness + e2e (slow)

# Filtered:
pnpm --filter pdf-rfc3161-tests test
pnpm --filter pdf-rfc3161-tests test:integration   # needs LIVE_TSA_TESTS=true
pnpm --filter pdf-rfc3161-demo dev                 # Vite dev server
```

## Architecture

```
packages/
  core/   # pdf-rfc3161 — the library
    src/
      index.ts             # public API: timestampPdf, timestampPdfMultiple, KNOWN_TSA_URLS
      session.ts           # TimestampSession — step-by-step API
      constants.ts         # MAX_PDF_SIZE, DEFAULT_SIGNATURE_SIZE, LTV_SIGNATURE_SIZE
      tsa/                 # request/response/client (RFC 3161 protocol)
      pdf/                 # prepare, embed, extract, ltv, archive (PDF I/O)
      pki/                 # cert/ocsp/crl clients, validation-session, trust-store
      utils/               # logger (pluggable), circuit-breaker, fetchers
  cli/    # pdf-rfc3161-cli — published binary
  tests/  # pdf-rfc3161-tests — private; aliases pdf-rfc3161 → ../core/src
  demo/   # pdf-rfc3161-demo — private; Vite + React 19 + Playwright e2e
```

**PDF I/O quirk:** Uses `pdf-lib-incremental-save` (not vanilla `pdf-lib`) so existing signatures are preserved across timestamps. Don't switch.

**Module-level singletons:** OCSP/CRL/cert clients use shared `CircuitBreaker` instances. Serverless cold starts reset them; long-lived processes share state across calls. Tests must call `reset*Circuits()` between cases.

**Test imports point at source, not dist:** `packages/tests/vitest.config.ts` aliases `pdf-rfc3161` → `../core/src/index.ts`. Tests don't require a build, but type errors in core surface only via `pnpm typecheck`.

## Code style

- TypeScript strict + `noUncheckedIndexedAccess` + `noUnusedLocals/Parameters`
- Prettier: 4-space indent, double quotes, semicolons, 100-col, `"endOfLine":"lf"`
- ESLint: `typescript-eslint/strict-type-checked` + `eslint-plugin-security`
  - `security/detect-unsafe-regex` is **error** — use bounded quantifiers (`\s{1,100}` not `\s+`) for any regex over untrusted input (PDF bytes)
  - `security/detect-non-literal-regexp` is **warn** — add `// eslint-disable-next-line` only when length is bounded by code, not input
- `console.warn/error` allowed by lint; prefer `getLogger()` in library code (one offender at `pdf/archive.ts:95` — M5)
- ASCII-only in source files (historical commit: `use ASCII only characters in source`)

## Known issues (do not regress)

- **H3 — Default trust store is empty.** `packages/core/src/pki/default-trust-store.ts:BUNDLED_ROOT_CERTS_BASE64` is an empty array. `getDefaultTrustStore()` throws `STATE_ERROR` until a maintainer with network access and trust-anchor verification authority populates the curated root list. The procedure lives in `docs/maintain-trust-store.md`. Until then, callers must either pass a custom `SimpleTrustStore` with pinned roots, or `{ trustStore: null }` to skip chain validation explicitly.

For the full history of issues fixed across 0.1.x -> 0.2.0, see `CHANGELOG.md`.

When fixing a regression, add a test in `packages/tests/test/unit/`.

## Jules sessions

`mingulov/pdf-rfc3161` has weekly automated review sessions (~45 over ~3 months) on 4 themes: Security / Performance / Testing / Code-Health. Patches are **suggestions**, not auto-merged.

```bash
jules remote list --session
jules remote pull --session <id>            # show diff
jules remote pull --session <id> --apply    # apply locally
jules teleport <id>                         # clone+branch+apply
```

When reviewing a Jules patch: check whether it touches files listed in "Known issues" above — those are pre-existing and may need a different fix than the one Jules proposed.

## Gotchas

- Tests use **real** `setTimeout`/`AbortSignal.timeout` for retry backoff → suite takes ~65s. Don't add global `vi.useFakeTimers()` — it breaks fetcher tests. Per-test fake timers are fine (see `tests/test/unit/tsa-client.test.ts`).
- `tsconfig.base.json` sets `preserveSymlinks: true`. The `AGENTS.md → CLAUDE.md` symlink is intentional, don't replace with a copy.
- Integration job only runs on `main` (TSAs rate-limit). Don't expect them on PRs.
- Per-package `CHANGELOG.md` is gitignored; only root `CHANGELOG.md` is canonical.
- `packages/core/src/utils.ts` (legacy top-level helpers) and `packages/core/src/utils/` (newer subdir) both exist — new code goes into `utils/`.
- `KNOWN_TSA_URLS` is a const object — adding a TSA there is the right way to expose it; don't hardcode TSA URLs elsewhere.
