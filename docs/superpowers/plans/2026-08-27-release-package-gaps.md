# Release Package Gaps Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the `pdf-rfc3161@0.2.0` and `pdf-rfc3161-cli@0.2.0` npm artifacts lean, documented, reproducible, externally executable, and verified as the exact tarballs sent to npm staging.

**Architecture:** Keep core as the existing dual ESM/CJS library, but publish the CLI only through its declared CommonJS binary. Treat Commander like the CLI's other runtime dependencies instead of bundling it. Build packages during `prepack`, install and exercise both exact tarballs in a clean consumer, and bind staging jobs to a checked hash manifest.

**Tech Stack:** pnpm 10.30.3 workspaces, TypeScript 5.9, tsup 8.5, Vitest 4, GitHub Actions, npm staged publishing.

**Spec:** Approved bounded design in the 2026-08-27 conversation; no separate design document.

## Global Constraints

- Keep both public package versions exactly `0.2.0`.
- Use pnpm workspaces; do not use npm or yarn to build the repository.
- Keep `pdf-lib-incremental-save@1.17.4`; do not substitute vanilla `pdf-lib`.
- Keep source files ASCII-only.
- Do not approve, reject, replace, or otherwise mutate the existing npm stages.
- Preserve the user's untracked files in the main checkout.
- Final `main` history must contain exactly one new commit for all changes in this plan.
- The release workflow must stop after staging and continue to require human 2FA approval.

---

### Task 1: Define and enforce the published artifact contract

**Files:**

- Modify: `packages/tests/scripts/test-packed-consumer.ts`
- Modify: `packages/tests/package.json`

**Interfaces:**

- Consumes: package directories when invoked without arguments, or exact core and CLI tarball paths when supplied by release CI.
- Produces: a clean-consumer gate covering package contents, metadata, ESM/CJS core exports, TypeScript declarations, CLI dependency resolution, executable version/help, and deterministic local packing.

- [ ] **Step 1: Extend the package test before changing package configuration**

    Make the harness pack both packages when no tarball arguments are provided. When two tarball arguments are provided, consume those exact files without repacking. Install both in one temporary project and assert these literal contracts:

    ```text
    core: README.md, LICENSE, package.json, all declared runtime/type exports, no *.map
    cli: README.md, LICENSE, package.json, dist/cli.cjs only
    cli bin: pdf-rfc3161 -> dist/cli.cjs
    cli dependency: pdf-rfc3161 -> 0.2.0
    cli bundle: external require("commander"), no sourceMappingURL
    ```

    Exercise all five core export paths with ESM and CJS, compile `.mts` and `.cts` consumers with `moduleResolution: NodeNext`, run the installed CLI with `--version` and `--help`, and confirm all resolved package paths stay under the temporary consumer.

- [ ] **Step 2: Run the focused gate and verify RED**

    Run:

    ```bash
    pnpm --filter pdf-rfc3161-tests test:package
    ```

    Expected: failure because package READMEs are absent, `dist/cli.js` is present, Commander is bundled, and generated runtime files contain source-map references.

- [ ] **Step 3: Keep the failing harness uncommitted for Task 2**

    Do not weaken assertions to match current output. Record the exact RED failures in the task report.

---

### Task 2: Correct package builds, metadata, and consumer documentation

**Files:**

- Create: `packages/core/README.md`
- Create: `packages/cli/README.md`
- Modify: `packages/core/package.json`
- Modify: `packages/cli/package.json`
- Modify: `packages/core/tsup.config.ts`
- Modify: `packages/cli/tsup.config.ts`
- Modify: `packages/core/src/types.ts`
- Modify: `packages/cli/src/cli.ts`
- Modify: `package.json`
- Modify: `pnpm-workspace.yaml`

**Interfaces:**

- Consumes: the artifact contract introduced by Task 1.
- Produces: package-local npm documentation, a single declared CLI binary, externally owned Commander, map-free runtime output, clean prepack builds, and active pnpm overrides.

- [ ] **Step 1: Make package contents satisfy the contract**

    Apply these manifest/build rules:

    ```typescript
    // packages/cli/tsup.config.ts
    format: ["cjs"],
    sourcemap: false,
    // remove shims and noExternal
    ```

    ```typescript
    // packages/core/tsup.config.ts
    sourcemap: false,
    ```

    Keep `commander` in CLI `dependencies`; remove only bundling. Replace core `prepublishOnly` with `prepack: "pnpm run build"` and add the same `prepack` script to CLI. Remove obsolete map exclusions and the CLI `dist/cli.js` side-effect entry. Move root pnpm overrides from `package.json` into `pnpm-workspace.yaml` without changing locked versions.

- [ ] **Step 2: Add focused package-local READMEs**

    Core README must cover installation, a minimal timestamp example, the default LTV candidate-material behavior, the one-call 8KB initial placeholder and direct LTV-enabled `TimestampSession` 16KB default, explicit caller-owned trust, `getDefaultTrustStore()` throwing while bundled roots are empty, and absolute GitHub links for full docs.

    CLI README must cover install/npx usage, the executable name `pdf-rfc3161`, timestamp/verify/archive examples, default LTV and `/M` behavior, `--trust-store`, and the distinction between cryptographic consistency and TSA trust.

- [ ] **Step 3: Correct adjacent public help and type documentation**

    Change `--omit-m` help to identify it as compatibility syntax because `/M` is already omitted by default. Document `TimestampOptions.signatureSize` as an initial 8KB reservation that the one-call API grows on retry; distinguish this from the direct LTV-enabled `TimestampSession` 16KB default.

- [ ] **Step 4: Run the focused gate and verify GREEN**

    Run:

    ```bash
    pnpm --filter pdf-rfc3161-tests test:package
    ```

    Expected: both package tarballs install together; all package, type, bundler, and CLI assertions pass with no pnpm override warning.

---

### Task 3: Bind release CI to the exact audited tarballs

**Files:**

- Modify: `packages/tests/test/unit/pades-oracle-policy.test.ts`
- Modify: `.github/workflows/release.yml`
- Modify: `CONTRIBUTING.md`

**Interfaces:**

- Consumes: Task 1's optional exact-tarball arguments and Task 2's final file lists.
- Produces: a release job graph that verifies supported Node versions, packs once for release, audits and executes those exact files, records hashes, verifies hashes again before each stage publish, and still stops for manual approval.

- [ ] **Step 1: Add failing release-policy assertions**

    Require the workflow to contain, in order:

    ```text
    compatibility matrix: Node 20, 22, 24
    pack public packages
    audit packed contents
    test exact release artifacts
    generate SHA256SUMS and SHA512SUMS
    upload npm-packages
    ```

    Require each staging job to run `sha256sum --check` and `sha512sum --check` before its single `npm stage publish`. Require the manual instructions to verify downloaded tarballs against the recorded digest.

- [ ] **Step 2: Run the focused policy test and verify RED**

    Run:

    ```bash
    pnpm --filter pdf-rfc3161-tests test -- test/unit/pades-oracle-policy.test.ts
    ```

    Expected: failure because the compatibility job, exact-artifact test step, and hash manifests do not yet exist.

- [ ] **Step 3: Implement the release workflow changes**

    Add a basic compatibility matrix for Node 20/22/24 using frozen pnpm install, build, typecheck, and tests. Make `verify` depend on it. Move `test:package` after release packing and invoke it with the two exact tarballs. Update the file allowlists to require both READMEs and only `dist/cli.cjs` for CLI. Generate both checksum manifests inside `release-artifacts`; verify them in both staging jobs and print commit identity plus hashes in the job summary.

- [ ] **Step 4: Update maintainer review instructions**

    Document downloading each stage, comparing its SHA-256/SHA-512 digest with the workflow summary, installing both downloaded tarballs together, invoking the CLI, then approving only after review.

- [ ] **Step 5: Run focused workflow and artifact tests and verify GREEN**

    Run:

    ```bash
    pnpm --filter pdf-rfc3161-tests test -- test/unit/pades-oracle-policy.test.ts
    pnpm --filter pdf-rfc3161-tests test:package
    ```

    Expected: both commands pass.

---

### Task 4: Make release documentation describe `0.2.0` truthfully

**Files:**

- Modify: `README.md`
- Modify: `MIGRATION.md`

**Interfaces:**

- Consumes: actual `0.2.0` defaults from core and CLI.
- Produces: release-ready root documentation consistent with package-local READMEs and runtime behavior.

- [ ] **Step 1: Replace prerelease language with `0.2.0` language**

    Change the migration heading to `0.1.x -> 0.2.0 (breaking)` and replace references to the "unreleased API" or "unreleased next major" with `0.2.0`.

- [ ] **Step 2: Correct trust, TSA, and placeholder guidance**

    Mark FreeTSA examples as testing examples with a caller-selected trust policy. Make verification without a trust store explicitly cryptographic-only. State that `getDefaultTrustStore()` throws in `0.2.0` while the curated root bundle is empty. State that `timestampPdf()` initially reserves 8KB and grows it on retry, while a direct `TimestampSession` defaults to 16KB with LTV and 8KB without it.

- [ ] **Step 3: Verify documentation consistency**

    Run:

    ```bash
    rg -n "unreleased next major|unreleased API|Now \(unreleased" README.md MIGRATION.md
    ```

    Expected: no matches.

---

### Task 5: Full verification, review, and one-commit integration

**Files:**

- Review all files changed by Tasks 1-4.

**Interfaces:**

- Consumes: all corrected source, documentation, tests, and workflow configuration.
- Produces: one reviewed commit merged and pushed to `main`, with npm stages still untouched.

- [ ] **Step 1: Run the complete local release-quality gate**

    Run:

    ```bash
    pnpm install --frozen-lockfile
    pnpm build
    pnpm lint
    git diff --check
    pnpm typecheck
    pnpm test
    pnpm --filter pdf-rfc3161-tests test:package
    ```

    If lint changes tracked files, inspect and retain valid formatting changes, then rerun the complete gate from `pnpm build`.

- [ ] **Step 2: Recreate release tarballs and inspect them independently**

    Pack both packages into a temporary directory. Confirm exact file lists, executable mode, absence of source-map references, external Commander resolution, normalized core dependency, README/license presence, matching `0.2.0` versions, and zero production audit findings.

- [ ] **Step 3: Request independent whole-branch code review**

    Review the full diff from `b95f146` for requirements, package correctness, workflow safety, and test quality. Fix every Critical or Important finding and rerun affected checks.

- [ ] **Step 4: Create exactly one final commit**

    Squash any temporary task commits into one commit with subject:

    ```text
    fix: harden npm release artifacts
    ```

- [ ] **Step 5: Merge to main, verify the merged tree, and push**

    Fast-forward or squash-merge the single feature commit into `main`, rerun the full test suite on merged `main`, verify `origin/main` has not diverged, and push normally without force.
