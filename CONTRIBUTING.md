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

## Releasing

Publishing uses npm staged publishing. The `Release` GitHub Actions workflow verifies and
stages `pdf-rfc3161` and `pdf-rfc3161-cli`, but it cannot make either package public. A
maintainer must inspect and approve each staged package with npm 2FA.

### One-time npm setup

For both npm packages, configure the GitHub Actions trusted publisher with:

- Organization or user: `mingulov`
- Repository: `pdf-rfc3161`
- Workflow filename: `release.yml`
- Allowed actions: `npm stage publish` only (disable direct `npm publish`)

Under each package's **Settings -> Publishing access**, select **Require two-factor
authentication and disallow tokens**. The workflow uses GitHub OIDC and has no `NPM_TOKEN`
secret.

### Stage a release

1. Merge all intended changes and their changesets into `main`.
2. Run `pnpm changeset version`, finalize the root `CHANGELOG.md`, and commit the release
   versions to `main`. The two public packages are a fixed Changesets group and release at
   the same version.
3. Wait for the normal `main` CI workflow to pass.
4. In GitHub Actions, select **Release**, choose `main`, enter the package version without a
   `v` prefix (for example, `0.2.0`), and click **Run workflow**. The equivalent GitHub CLI
   commands are:

    ```bash
    gh workflow run release.yml --ref main -f version=0.2.0
    gh run watch
    ```

5. Wait for **Verify and package**, **Stage pdf-rfc3161@VERSION on npm**, and **Stage
   pdf-rfc3161-cli@VERSION on npm** to pass.

Before retrying a failed staging job, use `npm stage list <package>` and `npm stage view
<stage-id>` to check whether npm reserved that version despite a lost response. Rerun failed
jobs only when the failed package has no stage. If a failed core job did create a stage,
reject that core stage before rerunning failed jobs so the CLI dependency chain can proceed.
If a failed CLI job did create its stage, both packages are ready for review and no rerun is
needed.

The workflow confirms the requested version matches both package manifests, builds,
typechecks, lints, runs the unit and offline PAdES interoperability suites, checks a packed
consumer, and audits both tarball file lists. The downloadable `npm-packages` GitHub
artifact contains the exact tarballs sent to npm.

### Review and approve

Use Node 22.14.0 or newer, npm CLI 11.15.0 or newer, and an npm account with package access
and 2FA. GitHub CLI can start and watch the workflow, but approval belongs to npm and
cannot be done with `gh`.

```bash
npm stage list pdf-rfc3161
npm stage list pdf-rfc3161-cli
npm stage view <core-stage-id>
npm stage view <cli-stage-id>
```

Download both staged tarballs into an empty temporary directory, install them together,
and exercise the packaged CLI:

```bash
review_dir=$(mktemp -d)
cd "$review_dir"
npm stage download <core-stage-id>
npm stage download <cli-stage-id>
npm init -y
npm install ./pdf-rfc3161-0.2.0-*.tgz ./pdf-rfc3161-cli-0.2.0-*.tgz
test "$(./node_modules/.bin/pdf-rfc3161 --version)" = "0.2.0"
./node_modules/.bin/pdf-rfc3161 --help
```

After review, approve core first and CLI second. Each command prompts for 2FA and makes that
package public:

```bash
npm stage approve <core-stage-id>
npm stage approve <cli-stage-id>
```

You can instead approve from the **Staged Packages** tab on npmjs.com. To discard a bad
stage, use `npm stage reject <stage-id>`; rejection also requires 2FA. Finally, confirm both
live versions:

```bash
npm view pdf-rfc3161 version
npm view pdf-rfc3161-cli version
```

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
