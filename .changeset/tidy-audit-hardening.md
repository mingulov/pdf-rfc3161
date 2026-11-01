---
"pdf-rfc3161": minor
"pdf-rfc3161-cli": minor
---

Harden verification and trust boundaries: reject SHA-1 CMS signature
algorithms and *.localhost SSRF targets, bind LTV OCSP requests to
verified issuers, and exit 2 from CLI verify when trust was not
evaluated. Fix GeneralizedTime validity handling and strict RFC 5544
parsing.
