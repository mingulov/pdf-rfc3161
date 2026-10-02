// T07: real openssl-generated interop material (base64 DER, ASCII-only).
//
// A pkijs-only fixture suite cannot prove real-world CRLs authenticate:
// entry-extension framing, NULL algorithm parameters, GeneralizedTime
// horizons, and multi-byte CRL numbers all differ between emitters. These
// blobs were generated with OpenSSL 3.5.5 and are decoded at test time,
// so the suite pins genuine third-party bytes without binary files or an
// openssl dependency. Validity horizon: nextUpdate 2126-09-08, so the
// fixed interop check date stays deterministic for a century.
//
// Generation (kept byte-identical; see the T07 report for receipts):
//   openssl req -x509 -newkey rsa:2048 -keyout t07ca.key -out t07ca.pem \
//     -days 36500 -nodes -subj "/CN=T07 OpenSSL Interop CA" \
//     -addext "subjectKeyIdentifier=hash" \
//     -addext "authorityKeyIdentifier=keyid:always" \
//     -addext "basicConstraints=critical,CA:TRUE" \
//     -addext "keyUsage=critical,keyCertSign,cRLSign"
//   openssl req -newkey rsa:2048 -keyout t07leaf.key -out t07leaf.csr \
//     -nodes -subj "/CN=T07 OpenSSL Leaf"
//   openssl x509 -req -in t07leaf.csr -CA t07ca.pem -CAkey t07ca.key \
//     -CAcreateserial -out t07leaf.pem -days 36500 -extfile leaf.ext
//     # leaf.ext: basicConstraints, keyUsage, SKI/AKI, and
//     # crlDistributionPoints=URI:http://crl.example.com/t07.crl
//   openssl ca -gencrl -config ca.cnf -out empty.crl  # CRL number 4096
//   openssl ca -revoke t07leaf.pem -crl_reason keyCompromise
//     # after registering the leaf serial in index.txt
//   openssl ca -gencrl -config ca.cnf -out revoked.crl  # CRL number 4097
//
// SHA-256 receipts (openssl dgst):
//   t07ca.der:     bc23e56724b91bb0c3128b1ae2aef189f154b7139ac2e87769dc349083a5d5a6
//   t07leaf.der:   27870874758bc7c086a738b97ad22d0383221936de218e829f80dd8916863357
//   revoked.der:   ec1c1fa3cf00e74bbab4542ec7b6f853661fa86c8a33274bad40c4bc14a9ea6b
//   empty.der:     c44ddf4be0ca31f9fa41bfd931677be10316ac0c50f224524c4e92cc5095227f
//
// Shapes pinned: entry extensions are a BARE Extensions SEQUENCE (RFC 5280
// 5.1.2.6 -- no [0] tag, unlike CRL-level crlExtensions), signature
// AlgorithmIdentifiers carry explicit NULL parameters, nextUpdate uses
// GeneralizedTime (year 2126), and the revoked entry carries a reasonCode
// (keyCompromise) entry extension.

/** Self-signed interop CA (DER bytes as base64). */
export const OPENSSL_INTEROP_CA_BASE64 =
    "MIIDNTCCAh2gAwIBAgIUc5Xjj/3QPBudOJwcmbZ0SksJ51EwDQYJKoZIhvcNAQELBQAwITEfMB0GA1UEAwwW" +
    "VDA3IE9wZW5TU0wgSW50ZXJvcCBDQTAgFw0yNjEwMDIwMzE5NTNaGA8yMTI2MDkwODAzMTk1M1owITEfMB0G" +
    "A1UEAwwWVDA3IE9wZW5TU0wgSW50ZXJvcCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMTt" +
    "bpCZA1J9r5LobEvr2K0IhLgoIf0Js8u0OpM+Duji78du2VdPn3zvBEF2EydN4Y2bVcnOsE2MdbGqazWTIn9e" +
    "pQVpa12KoNOzMnBP9wZH9IX3G/LH5ZztH/sOqOEXT0ZYHhoWO9CdyJi5sxW90bu5XHGVdkaL1ckUfveNwiVr" +
    "CfnAdkP3f/XfLAiCjFcISDnmgnCuuC6/FL1bEDLPQC5tCHlby+OsPbXayDRuOcRClH6KsbEnaedAQyd6laod" +
    "72pG/hD6jO4rDuVUi/ws5cG4Kkso/RyKmK2njsAP+E1EWuGCfWK/LQmm34nqN3n3Y8SsLSib2BlzdZJFY52/" +
    "9hcCAwEAAaNjMGEwHQYDVR0OBBYEFMgMyLnQ7rCPrzD/by70gzgNMyjlMB8GA1UdIwQYMBaAFMgMyLnQ7rCP" +
    "rzD/by70gzgNMyjlMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3DQEBCwUAA4IB" +
    "AQCO7gVRUsCnri3AJj25xkKV8suclyaAGglGiTS/FQ1gpdqi7n49wNrJ5jBiGvr8jzU3yCk3WVsjkuMupgi" +
    "BmM5tTnnke0YH61GTBxZjbA4LKpN+vtARdJkS1bo/prAVm2tq4QI7nudIjfCcaEUcz3UC76WG03fbKTAXNOp" +
    "73SbRW+lkUJPktduUb8sg0WjjjuS66B5InlgSSmub+skLtwZVCT7UbveqKvSnInV+d4YVnRd8j0yf30LzAZ4" +
    "hBH5suGeqsE2LTJQpq8MjWfXv6RJdlo2c4kUMw/abauWc/sejldC4mWsk/saeNknMMJgS3xJeoeGB4HjPB2o" +
    "1lipPLlgu";

/** Leaf issued by the interop CA, carrying a CRL distribution point (DER base64). */
export const OPENSSL_INTEROP_LEAF_BASE64 =
    "MIIDWTCCAkGgAwIBAgIUYaCmuHLuCuW/8LHrexf6wswPqhUwDQYJKoZIhvcNAQELBQAwITEfMB0GA1UEAwwW" +
    "VDA3IE9wZW5TU0wgSW50ZXJvcCBDQTAgFw0yNjEwMDIwMzE5NTNaGA8yMTI2MDkwODAzMTk1M1owGzEZMBcG" +
    "A1UEAwwQVDA3IE9wZW5TU0wgTGVhZjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMXf5haLlYRg" +
    "d2ELJodOR9gdfe1/FwYYqmvOxQLnkUDx70hRocUHkqtw0YK0ZItw8juOrmuxCyOPMhpLZM6+UZ+6cN66ECyf" +
    "KhAobKNIZRHnyTDVRu3ADJsA6AO/6fAhTjKEbpWi2Rt4Wo0c5i23W3jKcgOtF4INzg6Ib5R2piJV/oeBCDi5" +
    "qCX7J8d0mJooFUM67G9kCkk8z/ta/AMFrxUZRhTewmoIqX4gzadPXQSHK1XFS62MhRPj2gpEuOsO+8eZDUi1" +
    "o0tJR8cAbC8iBZcHFTPG/FYkti/Z4yAv/Pfg86fJjW9ZiHWNQRoFO3TUEMSYPECav4LpgN7y17QywnECAwEA" +
    "AaOBjDCBiTAJBgNVHRMEAjAAMAsGA1UdDwQEAwIHgDAdBgNVHQ4EFgQUgI14kHk3Nz1KHGD0ELTT4fDAGC0w" +
    "HwYDVR0jBBgwFoAUyAzIudDusI+vMP9vLvSDOA0zKOUwLwYDVR0fBCgwJjAkoCKgIIYeaHR0cDovL2NybC5l" +
    "eGFtcGxlLmNvbS90MDcuY3JsMA0GCSqGSIb3DQEBCwUAA4IBAQCzvgGHXNOEGsfvT5xeFoR4RiqHgfbEU0+a" +
    "aAjB2b/M7AZEPcuiZOZojW0g3+S7KOFhtol6ugVEVrulhnNqM1wB+9roRncF/e8qTiykS88HwbTDbf7vhHnY" +
    "1cLG05M5aW3u09KKlNKn4QKUFJiPhwz89BVWTG259bXjYwaNfm1TBoejzjFpCIOzQONwOrcfZz6eLDtdckWC" +
    "Bi5e9ROman+xrWCTdevaAkLauF4MrbMO0XyevGHzewNIzILB+nzslxkyb3fCT/eTDZ8foraSemPRXQ7Wa+Fl" +
    "hD+YufpPZLT3uGfqTTrWRnUSfHcyy+oX+kQSGfVriWY1tnoEcGIu9B1h";

/** CRL listing the interop leaf (reasonCode keyCompromise; DER base64). */
export const OPENSSL_INTEROP_REVOKED_CRL_BASE64 =
    "MIIBtDCBnQIBATANBgkqhkiG9w0BAQsFADAhMR8wHQYDVQQDDBZUMDcgT3BlblNTTCBJbnRlcm9wIENBFw0y" +
    "NjEwMDIwMzE5NThaGA8yMTI2MDkwODAzMTk1OFowNTAzAhRhoKa4cu4K5b/wset7F/rCzA+qFRcNMjYxMDAy" +
    "MDMxOTU4WjAMMAoGA1UdFQQDCgEBoA8wDTALBgNVHRQEBAICEAEwDQYJKoZIhvcNAQELBQADggEBAJZpH8GB" +
    "Pccp3+7bC0uUpqyaKqAazv4A+O328c+xJ3XGNOywrsYy4vCbtr6GcRqPxbJ6MhfIAIVkbKroAAKsJ/ukqxqx" +
    "9MrEUPNhvd+IzMyKlCFwJh1lLsR1ypAIPrkQvZtDkAC+rKb2WQ6rHMjL3JGf5pg4PUMhXQ4B5TtudHhUCggh" +
    "mDngsDJYTacLreKNn1CPEop2WSJIP+JBoo+h4ZzACKQt6atD1ajJXVRrfaz8u7uVuFDsp3lsXMkQzEzQEqcM" +
    "WDVeHqEd1z70scWNBXl0j/iIRTF9m5VuvEghO0PvFFKd035iKC8f3pdFE0hXAYPVGsTPrnBVjuMAkrLUsd4=";

/** CRL from the same CA with no revoked certificates (DER base64). */
export const OPENSSL_INTEROP_EMPTY_CRL_BASE64 =
    "MIIBfDBmAgEBMA0GCSqGSIb3DQEBCwUAMCExHzAdBgNVBAMMFlQwNyBPcGVuU1NMIEludGVyb3AgQ0EXDTI2" +
    "MTAwMjAzMTk1OFoYDzIxMjYwOTA4MDMxOTU4WqAPMA0wCwYDVR0UBAQCAhAAMA0GCSqGSIb3DQEBCwUAA4IB" +
    "AQCRNlFfFGY7Z7qFt/s9vtZxP+u63RWVcBp3qHeo3j73frP9U3lW98KX0ivSJ8kWlDa4xKdS9b0rAtCBK7cV" +
    "qt3pAOaRC5zvM/ymdl402m+H5bMuilJ+2RiEtRloVRpJqgCEVRP8lxJ07IGDQX5x/6bkOcQhQbdxDDm2PUXU" +
    "IVcyewRzX0R5miWZPVLtsmredntTjHGvG6AF8Yfl50rJoI1JZUhIDY24y16iYYt6KUmT6xFiCaqyoVixn48P" +
    "dAUGGvRSYB83QxIuO/tdHGsAj0kZ25FxbdeUJpYyFUPPLm9LoIROAS1G6cXx6HVAsR5u9fEGZSjqYKv0SpmC" +
    "elDkNENe";

/** Decodes one base64 DER blob from this file. */
export function decodeInteropDer(base64: string): Uint8Array {
    return new Uint8Array(Buffer.from(base64, "base64"));
}
