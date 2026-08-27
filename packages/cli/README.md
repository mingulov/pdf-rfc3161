# pdf-rfc3161-cli

`pdf-rfc3161-cli` is the command-line interface for RFC 3161 PDF timestamping.

## Install and run

```bash
npm install --global pdf-rfc3161-cli
pdf-rfc3161 --help
```

Or run it without a global installation:

```bash
npx pdf-rfc3161-cli --help
```

## Commands

```bash
pdf-rfc3161 timestamp https://freetsa.org/tsr document.pdf timestamped.pdf
pdf-rfc3161 verify timestamped.pdf
pdf-rfc3161 archive https://freetsa.org/tsr timestamped.pdf renewed.pdf
```

FreeTSA is used here only as a testing/development endpoint. Selecting a TSA URL does not trust
its timestamps; choose a production TSA and verification roots according to your policy.

`timestamp` enables LTV by default and collects DSS candidate material. Use `--no-ltv` for a basic signature without automatic collection. The signature dictionary omits `/M` by default because the timestamp token carries signed `genTime`; `--omit-m` is retained only as compatibility syntax.

## Verify with an explicit trust policy

```bash
pdf-rfc3161 verify timestamped.pdf --trust-store roots.pem
```

`--trust-store` accepts a PEM file containing trusted CA certificates. Without it, verification reports cryptographic consistency but does not evaluate TSA trust. LTV data and a valid timestamp structure are not substitutes for a trust policy.

Encrypted-PDF parsing remains disabled by default. Use `verify --ignore-encryption` only for
explicit diagnostic workflows where accepting the parser's encrypted-document handling is
appropriate.

See the [full documentation](https://github.com/mingulov/pdf-rfc3161#readme), [CLI source](https://github.com/mingulov/pdf-rfc3161/tree/main/packages/cli), and [trust-store guidance](https://github.com/mingulov/pdf-rfc3161/blob/main/docs/maintain-trust-store.md).
