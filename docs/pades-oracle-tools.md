# Offline PAdES oracle tools

The offline PAdES conformance gate deliberately uses external programs as
independent PDF and RFC 3161 oracles. Their exact Ubuntu package revisions,
artifact URLs, and SHA-256 values are defined once in
`packages/tests/scripts/pades-oracles.ts`.

CI, release, and manual publish run on `ubuntu-24.04`. The installer downloads
only the fixed HTTPS artifacts below from official Ubuntu hosts, refuses
redirects, and verifies each committed SHA-256 and Debian package metadata.
It then uses `dpkg-deb --extract` into a policy-versioned local test directory.
Package maintainer scripts never run, the runner's dpkg database is never
changed, and neither host OpenSSL nor host qpdf is downgraded or replaced.

| Package | Ubuntu 24.04 revision | Artifact | SHA-256 |
| --- | --- | --- | --- |
| qpdf | `11.9.0-1.1ubuntu0.1` | [qpdf_11.9.0-1.1ubuntu0.1_amd64.deb](https://archive.ubuntu.com/ubuntu/pool/universe/q/qpdf/qpdf_11.9.0-1.1ubuntu0.1_amd64.deb) | `b50d1aca530cd8f7b68214f8b19bdf348c6c01b7110ca1c335e6662cdb442af8` |
| libqpdf29t64 | `11.9.0-1.1ubuntu0.1` | [libqpdf29t64_11.9.0-1.1ubuntu0.1_amd64.deb](https://archive.ubuntu.com/ubuntu/pool/main/q/qpdf/libqpdf29t64_11.9.0-1.1ubuntu0.1_amd64.deb) | `8ffa418e72ab62013d7bd97b737f6eac8311853e50e4972b3db414c6fdbab445` |
| OpenSSL | `3.0.13-0ubuntu3.12` | [openssl_3.0.13-0ubuntu3.12_amd64.deb](https://security.ubuntu.com/ubuntu/pool/main/o/openssl/openssl_3.0.13-0ubuntu3.12_amd64.deb) | `321b30ad5a1c3783cb3d73ae439f824f6d3874d76a93a62f4a984959b490aa7b` |
| libssl3t64 | `3.0.13-0ubuntu3.12` | [libssl3t64_3.0.13-0ubuntu3.12_amd64.deb](https://security.ubuntu.com/ubuntu/pool/main/o/openssl/libssl3t64_3.0.13-0ubuntu3.12_amd64.deb) | `6a963adb1106fca567d24d4a1e5da0bad25de79ac2564cd1ba846e677e1c951b` |

The installer exports the local `usr/bin` directory through `GITHUB_PATH` and
the local library directory through `GITHUB_ENV` for subsequent workflow
steps. The conformance harness rechecks the retained artifacts' SHA-256 and
metadata, verifies that qpdf resolves its pinned `libqpdf` and OpenSSL resolves
its pinned `libssl` and `libcrypto`, then checks executable banners before it
calls either oracle. This pins the command binaries and those direct runtime
libraries. The dynamic loader and remaining transitive system libraries are
host-runner dependencies; this gate is intentionally not a fully hermetic
qpdf/OpenSSL runtime. Runner-image or package drift in the asserted artifacts
therefore fails closed, while host-runtime dependency changes remain a separate
Ubuntu runner compatibility boundary.

Sources and licenses:

- The official Ubuntu package pages publish the selected qpdf
  [artifact SHA-256](https://packages.ubuntu.com/noble-updates/amd64/qpdf/download),
  [runtime-library SHA-256](https://packages.ubuntu.com/noble-updates/amd64/libqpdf29t64/download),
  [OpenSSL package metadata](https://packages.ubuntu.com/noble-updates/openssl),
  and [OpenSSL runtime SHA-256](https://packages.ubuntu.com/noble/amd64/libssl3t64/download).
- [QPDF licensing](https://qpdf.sourceforge.io/) is Apache License 2.0.
  [OpenSSL 3 licensing](https://www.openssl.org/source/license.html) is Apache
  License 2.0. Ubuntu packaging metadata and copyright files remain applicable
  to the distro packages; no third-party binary is vendored in this repository.

## Bumping the policy

1. Select exact AMD64 `.deb` files from the official Ubuntu 24.04 package
   pages. Record their package revisions, direct HTTPS URLs, and published
   SHA-256 values; do not substitute a mirror, redirect, floating version, or
   unverified download.
2. Update the command version, package revision, artifact filename, URL, and
   SHA-256 together in `pades-oracles.ts`. Include direct runtime packages,
   such as `libqpdf29t64` for qpdf and `libssl3t64` for OpenSSL.
3. Update this table, source links, and license notice if the Ubuntu package
   location or licensing changes.
4. On Ubuntu 24.04, run
   `pnpm --filter pdf-rfc3161-tests run install:pades-oracles`, then
   `pnpm --filter pdf-rfc3161-tests run assert:pades-oracles` and
   `pnpm --filter pdf-rfc3161-tests test:conformance`.
5. Keep the static policy regression green so CI, release, publish, installer,
   and harness remain on the same policy.
