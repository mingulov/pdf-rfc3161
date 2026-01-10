# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [unknown]

### Added

- Demo website for easy testing and visualization
- Improved internal engine (TimestampSession, VRI support, OCSP/CRL handling)

### Changed

- Refactored library structure for better maintainability

## [0.1.2] - 2026-01-10

### Added

- PAdES-LTA support: `timestampPdfLTA` for archival workflows
- Structural validation tests for LTV

### Changed

- Cleaned up API by removing deprecated functions (`timestampPdfWithLTV`, `fetchOCSP`)

## [0.1.1] - 2026-01-09

### Fixed

- LTV PDF fixed implementation (fixed issues where some PDFs could not be opened by some viewers)
- Signature validation (fixed ByteRange calculation and dictionary structure for Adobe validation)

### Added

- Unified `timestampPdf` API with `enableLTV` support
- LTV support in `timestampPdfMultiple`

### Deprecated

- `timestampPdfWithLTV` (use `timestampPdf` with `enableLTV: true`)

## [0.1.0] - 2026-01-07

### Added

- Initial release
- `timestampPdf()` function for adding RFC 3161 timestamps to PDFs
- Support for SHA-256, SHA-384, and SHA-512 hash algorithms
- Document timestamp (DocTimeStamp with ETSI.RFC3161 SubFilter)
- Cloudflare Workers and edge runtime compatibility
- Browser support via Web Crypto API
- TypeScript type definitions
- Low-level API for advanced usage
- Known TSA server constants
