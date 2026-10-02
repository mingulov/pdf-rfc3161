# Migration Guide

This document covers breaking changes between major releases of `pdf-rfc3161`.

## Unreleased

### HTTP transport rejects redirects, fails fast on 4xx, and bounds bodies

TSA, OCSP, CRL, and AIA fetches now use `redirect: "manual"`: a 3xx (or
opaque/opaqueredirect) response is a terminal `NETWORK_ERROR` and the
`Location` is never fetched. If your TSA or responder sits behind a
redirect, reconfigure the client with the final URL; there is no
automatic manual-hop support in this iteration. Likewise every 4xx,
including 408 and 429, now fails in one attempt without retrying, so
callers that relied on 429 retries must implement their own backoff
(this iteration does not honor `Retry-After`; adopting that policy is a
separate decision). A response body that stalls past the per-attempt
`timeout` now rejects with `TIMEOUT` after the configured retries
instead of hanging; raise `timeout` if you serve slow responders.

An open circuit breaker now surfaces as `TimestampError` with code
`"CIRCUIT_OPEN"` rather than `CircuitBreakerError`, and deadline
exhaustion reports `TIMEOUT` rather than `NETWORK_ERROR`. The
`CircuitBreakerError` class remains exported for direct
`CircuitBreaker.execute()` users. Invalid numeric `retry`, `retryDelay`,
`timeout`, or `maxResponseBytes` options now reject with
`INVALID_ARGUMENT` before any fetch. Optional AIA/OCSP/CRL failures
still yield a signed PDF with partial LTV material plus diagnostics;
only the mandatory TSA path fails signing.

Transport error messages now carry the origin plus path only: embedded
credentials, query strings, and fragments are redacted. `timeout` and
`retryDelay` above the 2^31 - 1 ms platform timer ceiling now reject
with `INVALID_ARGUMENT`, and exponential backoff is capped at that
ceiling instead of misfiring. A bare `AbortError` with a live attempt
signal and unexpired deadline now reports `NETWORK_ERROR`; `TIMEOUT`
requires owned-deadline state (timer fired or elapsed).

### Direct-TSA browser calls need TSA CORS; `no-cors` cannot help

A page calling a TSA directly issues a cross-origin TSQ `POST` whose
`Content-Type: application/timestamp-query` triggers a CORS preflight,
so the TSA must answer `Access-Control-Allow-Origin` for the page
origin (and allow the content type); otherwise the browser blocks the
response and signing fails with `NETWORK_ERROR`. Retrying that request
with `mode: "no-cors"` cannot recover the token: the response becomes
opaque, hiding its status and bytes from the page, so there is nothing
usable to embed. The library therefore never uses `no-cors` itself.

When the TSA does not serve CORS, use the existing manual
request/response workflow instead of the one-call path: build the
request with `TimestampSession.createTimestampRequest()`, carry the
TSQ bytes to the TSA over a channel of your choice (for example a
server-side fetch), and hand the TSR bytes back to
`TimestampSession.embedTimestampToken()`, which runs the same
request-bound pre-embed validation before writing the PDF. See the
"Session Pattern for Complex Workflows" section in
[README.md](./README.md). These requirements were exercised in
the controlled local-TSA browser gate only; live-TSA CORS behavior
varies by operator and still needs per-TSA confirmation.

### `verifyChain` verifies `chain[0]` (trust-target binding)

`TrustStore.verifyChain(chain)` now defines first-certificate target
semantics: only `chain[0]` is verified, and the remaining entries are
untrusted path-building candidates rather than additional trust sources.
Previously the verdict could follow an unrelated trusted intermediate
elsewhere in the array, so an untrusted signer with such a bag entry could
verify as trusted. That input now returns `false`, and
`verifyTimestamp`/`verifyPdfTimestamps` report "Certificate chain not
trusted".

No change is needed if you already pass the selected signer first (as
`verifyTimestamp` does). If you relied on the old order-dependent behavior,
place the intended target at index 0. A target that is itself a pinned
anchor is verified against that anchor without needing intermediates, but
engine validation still applies: CA-ness, validity-period, and name-chaining
checks must pass. In particular a pinned self-signed end-entity (non-CA)
target still returns `false`, while a pinned intermediate still chains to
its issuer anchor.

### Signature reservations and PDF ceilings are validated at every entry

`signatureSize` must now be omitted, 0 (auto), or a positive safe integer of
at most 65,536 bytes; fractional, negative, `NaN`, infinite, and over-cap
values reject with `INVALID_ARGUMENT` before any allocation, PDF parsing, or
TSA request. Previously `Infinity` threw an uncategorized `RangeError` while
negative, `NaN`, and over-cap values were silently accepted or remapped to
the default. If you passed a reservation above 65,536 bytes, lower it to the
cap: ordinary TSA tokens (including chained RSA fixtures at ~1.5 KB against
the 8/16 KB defaults) fit with wide headroom, and the retry loop now grows
automatically up to the cap instead of past it.

`maxSize` must now be a positive safe integer of at most 250 MiB
(`MAX_PDF_SIZE`); invalid overrides reject with `INVALID_ARGUMENT`, and
inputs above the effective ceiling reject with `PDF_ERROR` before parsing.
The ceiling is now enforced at every entry -- `timestampPdf`,
`TimestampSession` (new `maxSize` option), `extractTimestamps`,
`verifyPdfTimestamps`, archive discovery, and archive renewal -- instead of
only the one-call path. `extractTimestamps` previously attempted a full parse
(returning timestamps or `[]`) for over-ceiling inputs; it now throws `PDF_ERROR`.
If you relied on scanning inputs above 250 MiB, split the document first: the ceiling
itself cannot be raised.

Placeholder exhaustion now throws the internal typed `PlaceholderTooSmallError`
(still `PDF_ERROR`-coded with the historical "Increase signatureSize" message,
plus a `requiredSignatureSize` lower bound), and the one-call retry loop
matches on that type rather than the message text. An unrelated error that
merely mentions the placeholder no longer triggers another TSA request. The
class is internal to the signing path (not on a published subpath), so
external callers keep matching `code === "PDF_ERROR"` as before. The loop
also never repeats an identical too-small reservation and stops with a
cap-citing error instead of issuing another TSA request once the 65,536-byte
reservation cap is reached.

DER decoding keeps its contracted 1,000,000-node preflight budget, but the effective node ceiling is the binding asn1js 10,000-node default (the 1M preflight binds only above it).

### Advanced revocation results now default to unknown

`ValidationSession` results (the `pdf-rfc3161/advanced` entry) now carry
`revocationStatus: "good" | "revoked" | "unknown"`, and `isValid` is a
deprecated alias for `revocationStatus === "good"`. Only authenticated
evaluators may produce "good" or "revoked": a certificate with no
revocation endpoints, a missing issuer, a total outage, a malformed
response, or unauthenticated (including forged) OCSP/CRL evidence all
yield "unknown" with `isValid` false. Previously most of these cases
returned `isValid` true, so a forged GOOD response -- or no evidence at
all -- read as valid.

Both authenticated evaluators have landed since (OCSP, then CRL),
so evidence that authenticates now yields "good" or "revoked".
Otherwise treat "unknown" as unknown: do not map it to valid, and do
not gate signing on it. There is no compatibility switch to restore
the old `true`, by design. The one-call signing path is unaffected:
it never consumed these verdicts, and optional AIA/OCSP/CRL failures
still yield a signed PDF with partial LTV material plus diagnostics.

Two related repairs ship with this change. `parseCRLInfo` (the
`pdf-rfc3161/internals` entry) now detects delta CRLs via the
DeltaCRLIndicator extension -- previously every CRL reported non-delta --
and reports a new additive `parsed` flag separating malformed input from
a parsed complete non-delta CRL. The session CRL scan now reads the real
pkijs `revokedCertificates` list (previously a nonexistent property, so
listed serials were never found). Neither repair produces a verdict on
its own. Finally, `preferOCSP: false` now falls back to OCSP after CRL
instead of never trying OCSP, and the default `preferOCSP` mode now also
fetches CRL after an OCSP success instead of suppressing it: same
collection APIs (`sources`, `ocspResponses`, `crls`, `exportLTVData`),
but collection is now strictly more complete. Success-path `errors`
entries also carry new structural diagnostic strings.

### Pre-embed signing rejects signers outside their genTime window

`timestampPdf` and `TimestampSession.embedTimestampToken` now reject a
token whose SID-selected signer certificate was expired, not yet valid,
or carried unparseable validity dates at the token `genTime`, with
`VERIFICATION_FAILED` ("Timestamp signer certificate was not valid at
genTime"). Previously such tokens embedded successfully and only the
post-embed `verifyTimestamp` default caught them (still opt-outable via
`requireCertValidAtGenTime: false` for historical verification). There
is no opt-out for the pre-embed check: a TSA that mints tokens outside
its signer window must fix its certificate; callers cannot re-enable
embedding those tokens.

The gate compares against the token `genTime`, not the current time, so
a token whose signer has lapsed since issuance still embeds and
verifies. Signers whose `notBefore` or `notAfter` exactly equals the
`genTime` are accepted (the window is inclusive). Accepted tokens embed
byte-for-byte: the PDF `/Contents` value is the token plus reservation
zero padding, unchanged.

### Issuers are verified and caches use exact byte identity

`ValidationSession` (the `pdf-rfc3161/advanced` entry) now verifies
issuers before building OCSP requests. An explicitly supplied issuer
must have issued the target certificate -- same-subject names are not
enough; the target signature must verify with the issuer key -- and
`queueChain` stores every name-matching chain member as a candidate
instead of picking the first match. When no candidate verifies, the
result is "unknown" with an issuer diagnostic and no OCSP request is
built or fetched. If you queue certificates with explicit issuers, pass
the certificate that actually signed each target; a wrong-key or
unrelated issuer that previously produced requests now yields "unknown".
The target itself is never used as its own issuer.

`getResultForCert` now matches by exact certificate bytes rather than
serial strings: serial twins under different issuers resolve to their
own results. `exportLTVData` dedupes CRL/OCSP artifacts by full bytes
rather than length plus a 64-byte prefix, so same-length same-prefix
evidence with different tails is all embedded; previously all but one
were dropped from the DSS.

`InMemoryValidationCache` entries are now keyed by the full OCSP request
bytes scoped by the exact URL (previously the first 32 request bytes),
so requests that share a prefix but differ in the tail no longer
collide; fresh random-nonce requests normally miss. Bytes are copied on
insertion and retrieval, so mutating caller arrays can no longer poison
the cache. Entries expire after 300,000 ms, the cache holds at most 256
entries and 20 MiB with oldest-first eviction, and single entries larger
than the byte budget are not cached; pass
`new InMemoryValidationCache({ maxEntries, maxTotalBytes, retentionMs })`
to tune these. The `ValidationCache` interface itself is unchanged, so
existing custom caches keep typechecking, but the session now
revalidates cached bytes on use and refetches once after rejecting
poisoned entries -- a custom cache that serves structurally invalid
bytes will see one refetch per use instead of silent reuse.

`completeLTVData` (used by the one-call `timestampPdf` LTV path) now
only accepts an AIA-fetched certificate that actually issued its target
-- fetched bytes with a non-matching subject name or a non-verifying key
are skipped with a diagnostic error instead of joining the chain -- and
tracks collected certificates by exact bytes rather than serials, so
same-serial distinct issuers are now both retained. If your chain
relies on AIA responses that do not verify against their targets, those
issuers will no longer be collected; embed the correct intermediates
directly or via `revocationData` instead.

### OCSP evidence is authenticated and requests carry a real nonce

`ValidationSession` (the `pdf-rfc3161/advanced` entry) now
authenticates OCSP evidence instead of reporting "unknown" for every
certificate. A response yields "good" or "revoked" only when it is
signed by the verified issuer or an authorized delegate, answers the
exact request CertID and nonce, and is fresh at the check date;
anything else -- wrong signer, CertID or nonce mismatch, stale or
future-dated times, unauthorized responder -- yields "unknown" with a
diagnostic, and `isValid` stays true only for authenticated "good".
CRL evidence is authenticated too; see the next section. Fetched
OCSP bytes are still collected into
`sources`, `ocspResponses`, and `exportLTVData` even when strict
evaluation stays unknown, so LTV embedding never loses candidate
material to a strict verdict.

A revoked verdict additionally requires a finite `revocationTime`
no later than `thisUpdate` plus skew (inclusive boundary): an
authenticated, bound, and fresh response that names a later instant
yields "unknown" with a `revocationTime` diagnostic instead of
"revoked". Every matching SingleResponse is evaluated, so one
out-of-bound instant fails the response even when its siblings are
in bound. Unparseable or misshapen revocation instants stay
"unknown" as well. This closes the T06 deferral ("revoked means
revoked regardless of revocationTime").

OCSP requests now carry a fresh random 32-byte nonce inside
`requestExtensions` (previously the nonce never reached the wire), and
responses must echo it exactly. A responder that drops or rewrites the
nonce yields "unknown" rather than a decisive verdict; if your
responder cannot echo nonces, pass `includeOCSPNonce: false` to send
nonce-free requests (the exchange then loses replay protection).
Because every request carries a fresh nonce, consecutive OCSP cache
lookups normally miss; pre-fetched or custom-cache responses are
validated against the current request bytes exactly like fetched ones.

One deliberate narrowing of the T05 cache contract rides along: a
cached entry that fails to parse is still refetched once, but a
cached entry that parses and then fails authentication -- wrong
signer, CertID or nonce mismatch, staleness -- yields "unknown" with
no refetch. An authentication verdict is the responder's answer about
this request, not cache corruption, so refetching cannot change it;
retention bounds keep the stale entry from lingering.

Delegated responders must be issued directly by the certificate issuer,
carry the `id-kp-OCSPSigning` extended key usage (plus
`digitalSignature` key usage when the extension is present), be live at
the check date, and carry `id-pkix-ocsp-nocheck`. The last requirement
is a deliberate profile boundary: the session does not check delegate
revocation, so a delegate that requires revocation checking is reported
"unknown", never silently trusted. Issuer-signed responses need no
embedded responder certificate. When the ResponderID matches the issuer
name but the issuer key does not verify, the session now falls through
to matching embedded delegates instead of stopping at the issuer
failure. Strict validation additionally rejects any critical extension
it does not process (only the nonce echo in responseExtensions; no
SingleResponse extension is processed, so any critical single
extension fails closed; only key usage, EKU, and nocheck on the
selected delegate), requires complete TBS consumption and v1-only
versions on
both request and response sides, complete TBSCertificate consumption
plus explicit Name/RDN/AttributeTypeAndValue grammar for the selected
delegate (a malformed responder name matches nothing; an empty RDN SET
fails while an entirely empty Name passes), requires X.509 v3 for the
selected delegate, requires the delegate inner/outer signature
algorithms to agree and suit the issuer key family (RSA keys pair only
with RSASSA-PKCS1-v1_5 OIDs and EC keys only with ECDSA OIDs; RSA-PSS
and unrecognized OIDs are unsupported), requires primitive
octet-aligned signature BIT STRINGs with canonical two-INTEGER ECDSA
payloads on both the response and the delegate certificate, requires
strict delegate public-key encodings (RSA parameters NULL-or-absent
with a canonical two-INTEGER key payload, EC parameters exactly the
named-curve OID), rejects inverted delegate validity intervals before
skew is applied, requires canonical DER extension payloads (nonce,
key usage with zeroed padding bits, EKU) with complete consumption,
requires canonical DER OBJECT IDENTIFIER contents (nonempty,
terminated, minimal base-128) in every EKU member and Name attribute
type, rejects empty extension OIDs (extnID) in response,
SingleResponse, and delegate-certificate extension lists, requires exactly
one NULL-valued
nocheck and an EKU sequence of only OIDs containing `id-kp-OCSPSigning`,
and checks the declared signature algorithm against the responder key:
RSA keys pair only with RSASSA-PKCS1-v1_5 OIDs (NULL or absent
parameters) and EC keys only with ECDSA OIDs (parameters must be
absent); RSA-PSS and unrecognized OIDs are unsupported. Anything outside
this narrowed profile yields "unknown" with a diagnostic. Tune the time policy with the new
`checkDate` (default: when `validateAll()` runs), `clockSkewMs`
(default: 300,000, i.e. 5 minutes), and
`maxAgeWithoutNextUpdateMs` (default: 604,800,000, i.e. 7 days)
session options; invalid values reject with `INVALID_ARGUMENT`.

Two smaller changes ride along: a certificate with no OCSP responder
URL and no CRL distribution points now records one "No revocation
endpoints attempted" diagnostic in `errors` instead of succeeding
silently, and the one-call signing path is unchanged -- LTV collection
stays structural and never depends on nonce echo or strict validation.

### CRL evidence is authenticated

`ValidationSession` (the `pdf-rfc3161/advanced` entry) now
authenticates CRL evidence instead of reporting "unknown" for every
certificate. A CRL yields "good" or "revoked" only when it is a
complete CRL issued directly by the T05-verified issuer key, in scope
for the certificate distribution point, and fresh at the check date;
anything else -- wrong key, forged signature, stale/future/missing
dates, missing cRLSign key usage, unknown critical extensions, scope
mismatch, indirect/partitioned/delta CRLs, malformed framing -- yields
"unknown" with a diagnostic, and `isValid` stays true only for
authenticated "good". Fetched CRL bytes are still collected into
`sources`, `crls`, and `exportLTVData` even when strict evaluation
stays unknown, so LTV embedding never loses candidate material to a
strict verdict; fetching needs only the leaf distribution point, so a
CRL is fetched and preserved even when no issuer can validate it
(only the verdict needs the verified issuer).

A revoked verdict additionally requires a finite `revocationDate`
on the matching entry no later than `thisUpdate` plus skew
(inclusive boundary): an authenticated, in-scope, fresh CRL that
lists the serial with a later instant yields "unknown" with a
`revocationDate` diagnostic instead of "revoked". This closes the
T07 deferral ("revoked means revoked regardless of
revocationDate").

Delta CRLs are explicitly deferred, never treated as complete: a CRL
carrying a DeltaCRLIndicator extension (detected by OID before value
parsing, at any criticality, even with a garbage value) always yields
"unknown", and the session moves on to the next CRL URL or falls back
to OCSP. Full base/delta merging is future work; it lands when a
follow-up task defines base-CRL selection (matching issuer, scope,
and CRL numbers across the fetched set), merge ordering and conflict
semantics, freshness rules for the merged view, and resource bounds
for the fetch-and-merge fan-out. Until then, point distribution
points at complete CRLs.

Strict validation additionally rejects any critical extension it
does not process (only CRL number, authority key identifier, and
issuing distribution point at CRL level; only reason code,
certificate issuer, hold instruction code, and invalidity date at
entry level), requires v1/v2 CRL versions with byte-exact
version identity (negative and out-of-range versions fail closed)
and v2 whenever any extension is present, requires a nextUpdate
horizon (a CRL without one fails closed as unbounded freshness),
requires inner/outer signature algorithms to agree and suit the
issuer key family (same RSA/ECDSA rules as OCSP), requires primitive
octet-aligned signature BIT STRINGs with canonical two-INTEGER ECDSA
payloads, requires complete schema consumption with an explicit Name
grammar walk (an empty RDN SET fails while an entirely empty Name
passes) and 64/256 RDN/attribute caps, compares serial numbers by
exact numeric identity (no float extraction past 2^53, no -128/128
conflation, one malformed entry fails the whole CRL), and caps each
CRL at 2000 revoked entries and 64 extensions per list. Partitioned,
indirect, and delta CRLs are outside the profile, as are RSA-PSS and
unrecognized signature OIDs. Anything outside this narrowed profile
yields "unknown" with a diagnostic. The time policy reuses the T06
`checkDate` and `clockSkewMs` session options; there is no
maximum-age fallback for a missing nextUpdate by design.

Entry processing is whole-CRL: every revoked entry's extension list
is gated before any verdict is selected (scan cap, empty-OID and
unknown-critical identifiers, recognized-OID duplicates, and the
payload grammar of every critical recognized extension), because RFC
5280 5.3 forbids using a CRL for any certificate when a critical
entry extension cannot be processed -- so an unknown critical
extension on a non-matching entry now fails the whole CRL (this
reverses the earlier rule that ignored non-selected entries).
Duplicate serial numbers reject outright instead of first-match. Only
non-critical recognized payloads on non-selected entries stay
verdict-neutral (the selected entry still gets the full grammar).

Entry-issuer scope follows certificateIssuer with the complete
payload grammar: the GeneralNames value must be nonempty and bounded,
every name must be a well-formed directoryName in a single-Name [4]
wrapper (a wrapper carrying trailers fails even when the first Name
matches), and every directoryName must equal the verified issuer
subject (a same-issuer scope restates the direct-issuance default and
is accepted). Any foreign, unbindable, or malformed scope on any entry
fails the CRL -- there is no per-entry skip, since RFC 5280 5.3.3
inheritance would propagate a foreign scope to following entries
without the extension.

Distribution-point scope likewise narrowed: a point carrying
cRLIssuer is always out of scope for this direct-only profile, even
one naming the verified issuer, because RFC 5280 6.3.3(b)(1) requires
a CRL matching such a point to carry an issuing distribution point
with indirectCRL asserted (conforming CAs MUST omit the redundant
same-issuer field anyway, RFC 5280 4.2.1.13). OpenSSL 3.5.5 accepts
same-issuer cRLIssuer with direct CRLs in both default and extended
modes; this strict profile deliberately does not. Distribution-point
metadata itself is grammar-checked before scope evaluation (the
distributionPoint-or-cRLIssuer presence rule, member order and
uniqueness, single-choice [0] framing, GeneralName wrapper
completeness, GeneralNames cardinality, directoryName grammar,
implicit ReasonFlags encoding), and cRLIssuer entries must be
well-formed directoryNames in single-Name wrappers
(`DistributionPointMetadata.hasUnbindableCrlIssuer` is retained for
API compatibility but always false now). otherName, x400Address,
and ediPartyName wrappers are outside the profile everywhere they
are walked: their flattened decoder grammar cannot prove complete
consumption (pkijs matches only leading ORAddress members for [3]),
so any such wrapper fails the CRL instead of resolving to an
ignored choice. CRL authority key identifiers carry the same bar:
[0]/[1]/[2] members must be unique and DER-ordered ([0]/[2]
primitive), and authorityCertIssuer must be a non-empty GeneralNames
under the same name profile (no undecidable wrappers, single-Name
directoryNames with strict Name grammar).

Reason codes are validated against the supported enumeration:
removeFromCRL (8) is restricted to delta CRLs and fails this
complete-CRL profile, as do negative and undefined values; every
other defined reason (0-7, 9, 10) confirms the listing, including
certificateHold (6), which does NOT soften "revoked" (hold/release
semantics belong to a later task). Invalidity dates must be canonical
`YYYYMMDDHHMMSSZ` with a real calendar date (the value itself stays
unevaluated). The issuer public key is gated before it executes in
WebCrypto (primitive octet-aligned SPKI framing, canonical two-INTEGER
RSA payload, NULL-or-absent RSA parameters, named-curve EC
parameters).

Two smaller changes ride along with the same verdict-vs-corruption
distinction as OCSP: a cached CRL that fails to parse is still
refetched once, but a cached CRL that parses and then fails
authentication yields "unknown" with no refetch; and issuer
resolution for CRL validation happens after the first fetch, so a
certificate whose issuer cannot be resolved records one issuer
diagnostic and stops instead of fetching every remaining URL.

### Historical chain validation via `chainValidationTime`

`verifyTimestamp` and `verifyPdfTimestamps` accept an optional
`VerificationOptions.chainValidationTime`: `"current"` (the default,
one wall-clock capture per call, works with any store), `"genTime"`
(the token's own genTime), or an explicit finite `Date`. Historical
requests validate `chain[0]` -- the same target the default call
verifies -- as of the carried date, and require a trust store with
the optional `TrustStore.verifyChainAtTime(chain, checkDate)`
capability (implemented by `SimpleTrustStore`). A historical request
against a store without the capability, or with a non-finite date,
fails as `verified: false` with `verificationErrorCode:
"INVALID_ARGUMENT"` and a diagnostic message; it never silently
validates at the wrong date. Custom `TrustStore` implementations
without the new method keep working for default current-time calls.

Historical path validity alone establishes neither historical
revocation nor archival qualification: a chain that was valid at
genTime says nothing about whether the signer was already revoked
then, and nothing about long-term archival policy. Revocation and
network cache retention plus circuit-breaker TTL clocks stay
wall-clock by design; only path validity is evaluated historically.

`SimpleTrustStore` inputs are now fully consumed, and every decode
failure carries a code: `addCertificate` and `verifyChain` /
`verifyChainAtTime` reject DER-encoded anchors and chain entries with
trailing garbage (or unparseable framing) with `INVALID_RESPONSE`.
Anchors with trailing bytes were previously pinned silently, and
undecodable inputs (schema mismatch such as `05 00` / `30 00`, or
corrupted content such as a bad GeneralizedTime) surfaced a raw
`Error`; all of these now fail closed with `INVALID_RESPONSE`.
`pkijs.Certificate` objects are unaffected, and CRLs are still never
consulted during path validation. One bound remains: framing
strictness is not canonical DER -- indefinite-length, non-minimal, or
shortened outer lengths still pin (and a shortened framing of an
otherwise valid anchor still verifies), because the ASN.1 decoder
consumes them leniently. Tightening acceptance is future work pending
ecosystem profiling; boundary tests pin the current behavior.

### Parser contracts: request digests, TSTInfo profile, coded decode errors

`createTimestampRequestFromHash` now rejects a precomputed digest whose
length does not match the hash algorithm (32 bytes for SHA-256, 48 for
SHA-384, 64 for SHA-512) with `INVALID_ARGUMENT` before serializing;
callers passing truncated or over-long digests must fix the input
length. Offset views are measured by the view, not the backing buffer.
`createTimestampRequest` (which hashes internally) is unaffected.

The strict token parser now enforces the TSTInfo profile: the version
must be 1 (RFC 3161 defines no v2), unsupported critical extensions
reject (the library supports none; non-critical unknown extensions
stay accepted), and message-imprint digest parameters must be absent
or NULL (RFC 5754: SHA-2 identifiers must accept NULL and generate
absent). Tokens violating any of these now fail with
`MALFORMED_RESPONSE` where they previously parsed.

Decode failures that previously surfaced a raw `Error` (asn1js
"conversion" errors on corrupted GeneralizedTime, pkijs schema
errors) are now coded `TimestampError`s (`INVALID_RESPONSE` on parse
paths; EKU/AIA/SKI helpers fail closed to `false` / `null` / no
match). `TimeStampedData` (RFC 5544) schema failures likewise reject
with a stable `INVALID_RESPONSE` message instead of embedding
engine-specific crash text. Callers matching on the old raw messages
must switch to error codes.

## 0.2.1 -> 0.2.2

Both the library and CLI now require Node.js >=22.12.0. Upgrade Node.js before
installing 0.2.2 if you are using Node.js 20. The public timestamping API is
unchanged. Repository contributors should use the pnpm version declared in
the root `packageManager` field.

## 0.1.x -> 0.2.0 (breaking)

This guide describes the 0.2.0 release, which combines security hardening, an
API redesign with stricter defaults, and PDF timestamp interoperability fixes.
The basic `timestampPdf({ pdf, tsa })` call signature is unchanged, but the
verify / extract path and several helpers have defaults that are stricter than
0.1.x.

### 1. `createTimestampRequest` / `createTimestampRequestFromHash` return `{ request, nonce }`

The functions previously returned just `Uint8Array` (the DER-encoded request).
In 0.2.0, the API returns an object containing the request _and_ the 8-byte
nonce that was embedded inside it, so callers can verify the TSA echoed the
nonce back (RFC 3161 Sec. 2.4.2).

```diff
- const request = await createTimestampRequest(data, config);
- const responseBytes = await sendTimestampRequest(request, config);
+ const { request, nonce } = await createTimestampRequest(data, config);
+ const responseBytes = await sendTimestampRequest(request, config);
+ // Keep `nonce` with this exact request/response pair.
```

The main entry does not publish a standalone `validateTimestampResponse`
helper. Do not import an internal response helper to embed into a PDF. Use the
supported session flow, which performs request-bound validation immediately
before embedding the timestamp into the PDF:

```typescript
import { TimestampSession, sendTimestampRequest } from "pdf-rfc3161";

const session = new TimestampSession(pdfBytes, { hashAlgorithm: "SHA-256" });
const request = await session.createTimestampRequest();
const responseBytes = await sendTimestampRequest(request, { url: tsaUrl });
const timestampedPdf = await session.embedTimestampToken(responseBytes);
```

The session preserves its request nonce and checks it with the prepared
ByteRange, requested policy, CMS signer, ESS binding, and timestamping EKU.
Skipping that checked session embed defeats the protection the new request
shape is meant to enable.

### 2. `createTimestampRequest` / `createTimestampRequestFromHash` take `TimestampRequestOptions`

These helpers previously accepted a partial `TSAConfig` (URL-less). They now
accept a focused `TimestampRequestOptions` covering only what shapes the
request body (`hashAlgorithm`, `policy`, `requestCertificate`). Network
details remain on `TSAConfig` and are passed to `sendTimestampRequest`
instead.

```diff
- const { request, nonce } = await createTimestampRequest(data, {
-     url: "http://...",          // ignored, but accepted
-     hashAlgorithm: "SHA-256",
-     policy: "1.2.3.4",
- });
+ const { request, nonce } = await createTimestampRequest(data, {
+     hashAlgorithm: "SHA-256",
+     policy: "1.2.3.4",
+ });
+ // The TSA URL belongs on sendTimestampRequest:
+ const responseBytes = await sendTimestampRequest(request, { url: "http://..." });
```

`createTimestampRequestFromHash` is now also exported from the main entry
point.

### 3. `extractTimestamps`: `ignoreEncryption` defaults to `false`

In 0.1.x, the library silently treated encrypted PDFs as if they were plain
documents, which produced misleading "no timestamps found" results. In 0.2.0,
the default is `false`: calling `extractTimestamps` on an encrypted PDF now
throws `TimestampError` with code `PDF_ERROR`. If you need the old behaviour
(useful for diagnostic tooling on hostile inputs), set it explicitly:

```diff
- const timestamps = await extractTimestamps(pdfBytes);
+ const timestamps = await extractTimestamps(pdfBytes, { ignoreEncryption: true });
```

This flag is also exposed on the `verify` CLI command.

### 4. `timestampPdf({ enableLTV })` defaults to `true`

In 0.1.x, `timestampPdf` defaulted `enableLTV` to `false`. This was
inconsistent with `TimestampSession` (which defaulted to `true`) and meant a
typical call would produce a signature without candidate validation material,
requiring an opt-in to embed it. In 0.2.0, the default is `true`. If
you intentionally want a signature _without_ the embedded validation data,
set `enableLTV: false` explicitly.

```diff
- const result = await timestampPdf({ pdf, tsa });            // no LTV in 0.1.x
+ const result = await timestampPdf({ pdf, tsa });            // LTV in 0.2.0
+ // Or, to keep 0.1.x behaviour:
+ const result = await timestampPdf({ pdf, tsa, enableLTV: false });
```

The one-call `timestampPdf()` path initially reserves 8KB for the RFC 3161
token, including when LTV is enabled, because it adds the candidate validation
material after embedding that token. If the token does not fit, the one-call
retry loop grows the placeholder. A directly constructed `TimestampSession`
uses a 16KB default when `enableLTV: true` and 8KB otherwise. Set
`signatureSize` explicitly if the TSA token for your policy requires more
space.

### 5. `verifyTimestamp` enforces id-kp-timeStamping EKU and cert-validity-at-genTime by default

The timestamping-EKU and certificate-validity checks previously had to be
enabled via `requireTimestampingEKU: true` / `requireCertValidAtGenTime: true`.
In 0.2.0 both default to `true`. Verifying a legacy or
non-conforming token whose certificate lacks the required RFC 3161 EKU (or was
outside its validity window at `genTime`) now fails by default; pass
`{ requireTimestampingEKU: false }` or
`{ requireCertValidAtGenTime: false }` to restore the looser behaviour.

```typescript
// 0.2.0: same call, stricter result
const verified = await verifyTimestamp(ts, { trustStore });

// To match 0.1.x leniency exactly:
const verified = await verifyTimestamp(ts, {
    trustStore,
    requireTimestampingEKU: false,
    requireCertValidAtGenTime: false,
});
```

### 6. `getDefaultTrustStore()` throws on empty bundle

The function returned an empty `SimpleTrustStore` in 0.1.x. This was
hazardous: a custom `TrustStore` wrapper that returns `true` on empty trust
could silently accept any chain. In 0.2.0, the bundled root list is empty, so
the function throws `TimestampError(STATE_ERROR, ...)` until maintainers
populate it with curated roots.

Three correct migrations:

```typescript
// 1. Pin your own roots (recommended for production):
import { SimpleTrustStore } from "pdf-rfc3161";
const trustStore = new SimpleTrustStore();
trustStore.addCertificate(myRootDer);
const result = await verifyTimestamp(ts, { trustStore });

// 2. Skip chain validation explicitly (cryptographic-only verify):
const result = await verifyTimestamp(ts, { trustStore: null });

// 3. Omit trustStore only when cryptographic-only verification is intentional:
const result = await verifyTimestamp(ts);
```

Omitting `trustStore` does not select default roots now or automatically later.
It performs cryptographic and, when `pdf` is supplied, PDF-consistency checks
only; it does not trust the TSA chain. For a trust decision, explicitly provide
and maintain a trust store appropriate to the relying party's policy.

### 7. Low-level helpers moved to `pdf-rfc3161/internals`

The top-level entry retains the common signing/verification surface
(`timestampPdf`, `archiveTimestamp`, `timestampPdfMultiple`,
`extractTimestamps`, `verifyTimestamp`, `verifyPdfTimestamps`,
`TimestampSession`), request/response helpers, trust-store types, errors,
constants, and RFC helpers. Lower-level PDF and PKI helpers moved to the
`pdf-rfc3161/internals` subpath.

```diff
- import {
-     addDSS, addVRI, extractLTVData, completeLTVData, getDSSInfo,
-     embedTimestampToken, preparePdfForTimestamp, extractBytesToHash,
-     getOCSPURI, createOCSPRequest, parseOCSPResponse,
-     getCaIssuers, fetchCertificate, getCRLDistributionPoints,
- } from "pdf-rfc3161";
+ import {
+     addDSS, addVRI, extractLTVData, completeLTVData, getDSSInfo,
+     preparePdfForTimestamp, extractBytesToHash,
+     getOCSPURI, createOCSPRequest, parseOCSPResponse,
+     getCaIssuers, fetchCertificate, getCRLDistributionPoints,
+ } from "pdf-rfc3161/internals";
```

The raw PDF embed primitive is intentionally no longer published. Move manual
flows to `TimestampSession.createTimestampRequest()` followed by
`TimestampSession.embedTimestampToken()`. The session validates the response
against the prepared ByteRange, request nonce, requested policy, CMS signer,
ESS binding, and exclusive critical timestamping EKU immediately before it
embeds the timestamp into the PDF. This is mandatory request-bound pre-embed validation, not an
optional post-write check.

The main bundle's `.d.ts` is now about 40% smaller (~41 KB -> ~24 KB).

`/internals` does **not** re-export the circuit-breaker reset functions
(`resetCertCircuits`, `resetCRLCircuits`, `resetOCSPCircuits`). They mutate
process-shared singleton state; exposing them on a supported public surface
let any plugin in the same import graph defeat rate-limiting telemetry meant
to absorb outages against revocation responders. **There is no replacement
on the published API surface.** Module-level singletons reset on process
restart (serverless cold start, Workers isolate recycle, Deno deploy
restart). For long-running Node processes, restructure so each request
builds its own client.

### 8. `timestampPdfMultiple` forwards every `TimestampOptions` field; `timestampPdfLTA` renamed to `archiveTimestamp`

`timestampPdfMultiple` previously only forwarded `reason`, `location`,
`contactInfo`, and `enableLTV` to each underlying `timestampPdf` call.
In 0.2.0, every active `TimestampOptions` field is forwarded (for example,
`signatureFieldName` and `revocationData`), so you can configure the
whole pipeline once. `rejectOnRevocationWarning` remains accepted only for
source compatibility; it is a deprecated no-op because TSA statuses 4/5 are
always fatal.

```typescript
const result = await timestampPdfMultiple({
    pdf,
    tsaList: [tsa1, tsa2],
    signatureFieldName: "Timestamp", // forwarded to each timestamp request
    enableLTV: false,
});
```

`timestampPdfLTA` is now exposed as `archiveTimestamp`. The old name remains
as a `@deprecated` alias and continues to work; new code should use
`archiveTimestamp`. `ArchiveTimestampOptions` now `extends TimestampOptions`,
so every flag you can pass to `timestampPdf` is also accepted on the archive
path.

### 9. New `TimestampErrorCode.MALFORMED_RESPONSE`

Existing `catch` blocks that test for `TimestampError` generically are
unaffected; code that `switch`-es on the error code may want to add a case
for this. The new code is thrown when a TSR's outer ASN.1 parses but the
inner TSTInfo / token extraction fails -- previously this was conflated under
`INVALID_RESPONSE` and silently swallowed by the session, allowing an MITM
to substitute the wrong token.

### 10. CLI flag changes

Several CLI flag groups switched from positive to negative form. The default
behaviour for each is now to ENFORCE the security check (matching the new
library defaults). Pass the new `--no-*` form to opt out.

| Was (0.1.x)          | Now (0.2.0)             | New default                                          |
| -------------------- | ----------------------- | ---------------------------------------------------- |
| `--ltv`              | `--no-ltv`              | LTV enabled                                          |
| `--require-eku`      | `--no-require-eku`      | EKU enforced                                         |
| `--require-validity` | `--no-require-validity` | validity enforced                                    |
| (n/a)                | `--strict-ess`          | strict ESS still opt-in (library default is `false`) |

If you were invoking the CLI with an explicit positive flag (e.g.
`pdf-rfc3161-cli timestamp ... --ltv`), drop the flag -- the protections are
now on by default. To restore the 0.1.x CLI behaviour of producing a
non-LTV signature, pass `--no-ltv` explicitly.

`archive --no-update` previously was documented but ineffective. It now skips
embedded OCSP/CRL candidates from verified existing document timestamps. Their
certificates are still retained, and fresh OCSP/CRL candidates may still be
fetched. The archive path is RFC 3161 document-timestamp renewal: it verifies
recognized document timestamps, merges global DSS candidate material, and adds
a new document timestamp. It is not a general PAdES-LTA upgrader or an
indefinite-validity guarantee, and it never creates VRI entries automatically.

### 11. Removed: `rfcs/rfc4998` deep import

The `rfcs/rfc4998` module was a stub: `extractTimestampsFromEvidence` returned
`[]` unconditionally, masking real ERS evidence. It has been removed.
If you depended on the import path, please open an issue describing your use
case -- a real RFC 4998 implementation is on the roadmap.

```diff
- import { extractTimestampsFromEvidence } from "pdf-rfc3161/rfcs/rfc4998";
+ // No replacement yet. Track progress at:
+ // https://github.com/mingulov/pdf-rfc3161/issues
```

### 12. Removed: `rfcs/rfc6211` deep import

`pdf-rfc3161/rfcs/rfc6211` was a stub: `validateAlgorithmProtectAttribute`
always returned `true` because its underlying `getProtectedAlgorithms`
returned `[]`. The real RFC 8933 algorithm protection is exposed via
`validateTimestampTokenRFC8933Compliance` from the main entry point.

### 13. Document timestamp metadata is omitted by default

New document timestamps write a value dictionary with `/Type /DocTimeStamp`
and `/SubFilter /ETSI.RFC3161`. The AcroForm field remains `/FT /Sig`; a
DocTimeStamp is not an approval or certification signature merely because it
uses the signature field type.

`/M`, `Reason`, `Location`, and `ContactInfo` are omitted unless requested.
`omitModificationTime: false` restores the legacy `/M` behavior for a
compatibility case. Treat metadata as an explicit opt-in, not as a baseline
default.

`signatureFieldName` is a requested base name. When a fully qualified field
name already exists, the library adds a deterministic numeric suffix rather
than overwriting an existing form field. Existing field and widget structures
remain unchanged; the new timestamp field and widget are appended. Do not
assume the requested string is always the literal final field name in a
pre-existing AcroForm.

### 14. Replace legacy VRI calls with `addVRIForSignature`

VRI is field-specific and optional. The legacy wrappers are still callable but
deprecated. They now require a `signatureFieldName`, reject reusable PDF
references from another load context, and reject unsupported key choices.
Move code that supplied a certificate and loose references to raw validation
bytes bound to one named PDF signature field:

```diff
- import { addVRI } from "pdf-rfc3161/internals";
+ import { addVRIForSignature } from "pdf-rfc3161/internals";

- const updated = await addVRI(pdf, signingCert, { crls, ocspResponses });
+ const updated = await addVRIForSignature(
+     pdf,
+     { fieldName: "Timestamp" },
+     {
+         validationData: {
+             certificates: [certificateDer], // DER-encoded Uint8Array
+             crls,
+             ocspResponses,
+         },
+     }
+ );
```

The replacement resolves the field in the loaded PDF, derives an uppercase
SHA-1 VRI key from that signature's complete decoded, padded `/Contents`
value, and puts VRI below Catalog `/DSS`. It preserves existing global DSS
arrays, VRI entries, and unknown DSS keys, reusing byte-identical validation
streams where possible. The decoded-and-padded interpretation is this
project's implementation reading of the relevant PDF and ETSI material; the
current ETSI text calls the input the complete hexadecimal `/Contents`
string, so do not treat this sentence as a verbatim ETSI quote or an assertion
that every producer uses the same encoding.

VRI is optional, and ETSI EN 319 142-1 says it `SHOULD NOT` be used in the
baseline profile. `archiveTimestamp` merges global DSS candidate material but
does not create VRI automatically. Use the explicit API only for a
field-specific interoperability need.

### 15. Validate the published artifact and document loader limits

On a clean Ubuntu 24.04 AMD64 runner, install the locked validation tools using
[the clean-run recipe](./docs/pades-oracle-tools.md#run-from-a-clean-checkout),
then run the offline structural/interoperability and packed-consumer gates:

```bash
pnpm build
PYTHON=/tmp/pdf-rfc3161-pades-python/bin/python \
  pnpm --filter pdf-rfc3161-tests test:interoperability
pnpm --filter pdf-rfc3161-tests test:package
```

For the tool-role boundaries and a reproducible later Acrobat Reader
observation, see [docs/validation-tools.md](./docs/validation-tools.md) and
[docs/manual-acrobat-validation.md](./docs/manual-acrobat-validation.md).
These tests do not change the official `pdf-lib-incremental-save@1.17.4`
loader boundary. Its hostile-PDF parsing and resource limitations remain
separate and deferred; see
[docs/pdf-lib-incremental-save-limitations.md](./docs/pdf-lib-incremental-save-limitations.md).

---

For the full list of changes, see [CHANGELOG.md](./CHANGELOG.md).
