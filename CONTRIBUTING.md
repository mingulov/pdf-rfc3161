# Contributing to pdf-rfc3161

Thanks for your interest! This is a pnpm 10 monorepo targeting Node 20+.

## Setup

```bash
git clone https://github.com/mingulov/pdf-rfc3161.git
cd pdf-rfc3161
pnpm install
pnpm -r build
pnpm test
```

You'll need Node 20 or newer (`.nvmrc` pins 24 for CI; older minors are tested in the matrix) and pnpm 10+ (`engines.pnpm`).

## Project structure

```
pdf-rfc3161/
|-- packages/
|   |-- core/    # pdf-rfc3161 — the library
|   |-- cli/     # pdf-rfc3161-cli — published binary
|   |-- tests/   # private; aliases pdf-rfc3161 -> ../core/src
|   `-- demo/    # private; Vite + React 19 + Playwright
|-- docs/              # maintainer docs
`-- .changeset/        # pending changesets
```

## Commands

| Command | What it does |
|---|---|
| `pnpm test` | Full unit suite across all packages |
| `pnpm typecheck` | `tsc --noEmit` on every workspace package |
| `pnpm lint` | ESLint `--fix` on every workspace package |
| `pnpm format` | Prettier `--write` on every workspace package |
| `pnpm -r build` | tsup builds for core + cli; Vite build for demo |
| `pnpm --filter pdf-rfc3161-tests run test:integration` | Hits live TSAs — set `LIVE_TSA_TESTS=true` first |
| `pnpm --filter pdf-rfc3161-tests run test:robustness` | Long-running adversarial suite |
| `pnpm --filter pdf-rfc3161-tests run test:coverage` | v8 coverage report |
| `pnpm --filter pdf-rfc3161-demo dev` | Vite dev server for the demo app |
| `pnpm cli -- <args>` | Run the CLI from source via tsx |

## Before opening a PR

1. **Add a changeset** describing user-visible changes:

   ```bash
   pnpm changeset
   ```

   Pick affected packages and bump type. Commit the generated `.changeset/*.md` along with your code. Skip the changeset only for internal-only edits (tests, docs, CI, examples that don't affect published output).

2. **Run the full check**: `pnpm test && pnpm typecheck && pnpm lint`.

3. **Network-touching changes** (TSA / OCSP / CRL / cert client, verify logic): also run the integration tests. They hit live TSA endpoints, so don't loop them — they're rate-limited.

4. **Security-relevant changes**: confirm the threat model was considered. The PR template has a section for this. If you're unsure, ask in the PR description.

## Code style

- TypeScript strict + `noUncheckedIndexedAccess` enabled.
- Prettier: 4-space indent, double quotes, semicolons, 100-col width, LF line endings (see `.editorconfig`).
- ESLint with `eslint-plugin-security`. ReDoS-prone unbounded regex quantifiers (`\s+`, `\d+`) are flagged — use bounded forms (`\s{1,N}`).
- Source files are **ASCII-only**, enforced by `packages/tests/test/unit/ascii.test.ts`. Use `--` instead of em-dash, `Sec.` instead of section sign, etc.

## Tests

Tests live in `packages/tests/test/{unit,integration,fixtures,utils}/`. The Vitest config aliases `pdf-rfc3161` → `../core/src/index.ts`, so tests import from source directly and don't require a built `dist/`.

Per-test fake timers are encouraged for retry/backoff logic — see `packages/tests/test/unit/cert-client.test.ts` for the canonical pattern. Do **not** introduce a top-of-file `vi.useFakeTimers()` — that has historically broken fetcher tests.

## Reporting bugs

Use the GitHub issue template: <https://github.com/mingulov/pdf-rfc3161/issues/new/choose>. Include the pdf-rfc3161 version, Node version, runtime (Node / Workers / Deno / Browser), and a minimal reproduction.

## Security issues

Please do **not** file public issues for security problems. See `SECURITY.md` for the disclosure procedure.

## License

By contributing you agree your work is MIT-licensed (see `LICENSE`).
