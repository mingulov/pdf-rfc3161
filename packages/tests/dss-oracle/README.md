# dss-oracle

EU DSS validation driver for the PAdES conformance harness
(`../scripts/offline-pades-conformance.ts`). Validates one PDF against
a caller-supplied trust anchor and prints a JSON verdict the harness
parses and asserts.

## Build

```bash
mvn -q -DskipTests package   # produces target/dss-oracle-jar-with-dependencies.jar
```

DSS is pinned at 6.2 in `pom.xml`; Maven Central artifacts are
immutable and checksum-verified on download. The build filters the
DSS version into the jar; `--version` prints it and the harness
asserts the exact value.

## Run

```bash
java -jar target/dss-oracle-jar-with-dependencies.jar --pdf <file.pdf> --trust <root.pem>
```

Exit 0 prints one JSON report on stdout for valid, invalid, and
unsigned PDFs alike (verdicts are data). Any nonzero exit means the
harness itself failed; the message goes to stderr.

## License

DSS core is LGPL-2.1. It runs here as a separately installed CI tool
in its own JVM process and is never bundled into the published
JavaScript package. See `../../docs/validation-tools.md`.
