/**
 * Known TSA (Time Stamping Authority) server URLs.
 *
 * This constant provides a curated list of known TSA server endpoints.
 * Usage of these services is governed by the respective providers' Terms of Service.
 *
 * All servers listed in the main section use certificates that chain to well-known CAs
 * included in standard system trust stores.
 *
 * @example
 * ```typescript
 * import { timestampPdf, KNOWN_TSA_URLS } from 'pdf-rfc3161';
 *
 * const result = await timestampPdf({
 *   pdf: pdfBytes,
 *   tsa: { url: KNOWN_TSA_URLS.DIGICERT },
 * });
 * ```
 */
export const KNOWN_TSA_URLS = {
    // Commercial TSA servers
    /**
     * DigiCert TSA - widely trusted.
     * Note: Public endpoint currently supports HTTP only.
     */
    DIGICERT: "http://timestamp.digicert.com",
    /**
     * Sectigo TSA - commercial, reliable.
     * Note: Requires 15s+ delay between requests when scripting.
     */
    SECTIGO: "https://timestamp.sectigo.com",
    /** Comodo TSA - Sectigo's legacy endpoint (HTTP only) */
    COMODO: "http://timestamp.comodoca.com",
    /** GlobalSign TSA - commercial (HTTP only) */
    GLOBALSIGN: "http://timestamp.globalsign.com/tsa/r6advanced1",
    /** Entrust TSA - commercial (HTTP only) */
    ENTRUST: "http://timestamp.entrust.net/TSS/RFC3161sha2TS",
    /** QuoVadis TSA - EU eIDAS (HTTP only) */
    QUOVADIS: "http://ts.quovadisglobal.com/eu",

    // Free/community TSA servers (may have rate limits or self-signed CAs)
    /** FreeTSA.org - free community TSA, uses self-signed CA */
    FREETSA: "https://freetsa.org/tsr",
    /**
     * CodeGic TSA - public test timestamp server.
     * Note: For integration testing only; not for production use.
     */
    CODEGIC: "http://pki.codegic.com/codegic-service/timestamp",
} as const;

/**
 * Extended TSA URLs with detailed server characteristics and error handling notes.
 * These servers have been tested and documented for compatibility.
 */
export const EXTENDED_TSA_URLS = {
    // === Apple ===
    /**
     * Apple Time Stamp Service.
     * Note: HTTP endpoint, returns RFC 3161 compliant responses.
     * May have rate limiting for bulk requests.
     */
    APPLE: "http://timestamp.apple.com/ts01",

    // === Certum ===
    /**
     * Certum TSA (Asseco).
     * Note: Polish TSA, EU eIDAS compliant.
     * Good reliability and free tier available.
     */
    CERTUM: "http://time.certum.pl",

    // === StartSSL ===
    /**
     * StartCom/StartSSL TSA.
     * Note: Previously free, now commercial.
     * HTTP endpoint, may have certificate issues.
     */
    STARTSSL: "http://tsa.startssl.com/rfc3161",

    // === DFN ===
    /**
     * DFN Zeitstempel (German academic network).
     * Note: HTTP endpoint, used by German institutions.
     * Good for documents in German legal context.
     */
    DFN: "http://zeitstempel.dfn.de",

    // === SignFiles ===
    /**
     * SignFiles TSA.
     * Note: Commercial service, HTTPS endpoint.
     * Returns proper RFC 3161 responses.
     */
    SIGNFILES: "https://ca.signfiles.com/tsa/get.aspx",

    // === GlobalTrustFinder ===
    /**
     * GlobalTrustFinder TSA.
     * Note: Commercial service, HTTP endpoint.
     * Returns GRANTED_WITH_MODS occasionally.
     */
    GLOBALTRUSTFINDER: "http://services.globaltrustfinder.com/adss/tsa",

    // === IAIK Graz ===
    /**
     * IAIK TU Graz TSA.
     * Note: Academic/research TSA from Graz University of Technology.
     * HTTPS endpoint, reliable.
     */
    IAIK_GRAZ: "https://tsp.iaik.tugraz.at/tsp/TspRequest",

    // === nCipher/Dell ===
    /**
     * nCipher (now Dell) TSA.
     * Note: Enterprise HSM vendor's test TSA.
     * May not be production-ready for all use cases.
     */
    NCIPHER: "http://dse200.ncipher.com/TSS/HttpTspServer",

    // === Mesign ===
    /**
     * Mesign TSA.
     * Note: Commercial service, HTTP endpoint.
     * Returns RFC 3161 compliant responses.
     */
    MESIGN: "http://tsa.mesign.com",

    // === GlobalSign Advanced ===
    /**
     * GlobalSign Advanced TSA.
     * Note: Alternative GlobalSign endpoint (HTTP only).
     * Similar to GLOBALSIGN but different path.
     */
    GLOBALSIGN_ADVANCED: "http://rfc3161timestamp.globalsign.com/advanced",

    // === Microsoft ACS ===
    /**
     * Microsoft ACS Time Stamp Service.
     * Note: HTTP endpoint, Microsoft Azure Certificate Service.
     * Returns proper responses for Microsoft ecosystem.
     */
    MICROSOFT_ACS: "http://timestamp.acs.microsoft.com",

    // === IdenTrust ===
    /**
     * IdenTrust Time Stamping Authority.
     * Note: Direct URL, HTTP endpoint.
     * Commercial TSA, widely recognized in US.
     */
    IDENTRUST: "http://timestamp.identrust.com",

    // === ADACOM ===
    /**
     * ADACOM Qualified Time Stamping Service.
     * Note: Direct URL, HTTPS endpoint.
     * Greek Qualified Trust Service Provider (QTSP), EU eIDAS compliant.
     */
    ADACOM: "https://tss.adacom.com/qtss",

    // === Aloaha ===
    /**
     * Aloaha Time Notary Test TSA.
     * Note: Test server - uses test certificate.
     * Limits to 50 timestamps per IP address.
     * Not for production use.
     */
    ALOAHA_TEST: "http://tsa.timenotary.com/tsa.aspx",

    // === Mahidol University ===
    /**
     * Mahidol University TSA.
     * Note: Direct URL, HTTPS endpoint.
     * Thai university timestamping service.
     * UNTRUSTED - not on Adobe or EU trust lists.
     */
    MAHIDOL_UNIVERSITY: "https://tsa.mahidol.ac.th/tsa/get.aspx",

    // === ACCV (Qualified - EU Trust List) ===
    /**
     * ACCV TSA (Agencia de Tecnologia de la Certificacion Electronica).
     * Note: Qualified TSA, EU eIDAS compliant.
     * Spanish government certification authority.
     */
    ACCV: "http://tss.accv.es:8318/tsa",

    // === APED (Qualified - EU Trust List) ===
    /**
     * APED TSA (Hellenic Ministry of Digital Governance).
     * Note: Qualified TSA, EU eIDAS compliant.
     * Greek government public digital services.
     */
    APED: "https://timestamp.aped.gov.gr/qtss",

    // === BaltStamp (Qualified - EU Trust List) ===
    /**
     * BaltStamp TSA.
     * Note: Qualified TSA, EU eIDAS compliant.
     * Baltic region timestamping service.
     */
    BALTSTAMP: "http://tsa.baltstamp.lt",

    // === Belgium (Qualified - EU Trust List) ===
    /**
     * Belgium TSA (Federal Government).
     * Note: Qualified TSA, EU eIDAS compliant.
     * Belgian government timestamping service.
     */
    BELGIUM: "http://tsa.belgium.be/connect",

    // === Portuguese Citizen Card (Qualified - EU Trust List) ===
    /**
     * Portuguese Citizen Card TSA.
     * Note: Qualified TSA, EU eIDAS compliant.
     * Portugal's Cartao de Cidadao timestamping service.
     */
    PORTUGAL_CITIZEN_CARD: "http://ts.cartaodecidadao.pt/tsa/server",

    // === Izenpe (Qualified - EU Trust List) ===
    /**
     * Izenpe TSA.
     * Note: Qualified TSA, EU eIDAS compliant.
     * Basque government CA (Instituto Vasco de Consumo).
     */
    IZENPE: "http://tsa.izenpe.com",

    // === Sectigo Qualified (Qualified - EU Trust List) ===
    /**
     * Sectigo Qualified TSA.
     * Note: Qualified endpoint, EU eIDAS compliant.
     * Higher assurance timestamping for EU compliance.
     */
    SECTIGO_QUALIFIED: "http://timestamp.sectigo.com/qualified",

    // === SSL.com ===
    /**
     * SSL.com TSA.
     * Note: Trusted by Adobe.
     * Commercial CA and trust service provider.
     */
    SSL_COM: "http://ts.ssl.com",

    // === SwissSign ===
    /**
     * SwissSign TSA.
     * Note: Trusted by Adobe, Swiss trust service provider.
     * EU eIDAS compliant qualified timestamps available.
     */
    SWISSSIGN: "http://tsa.swisssign.net",

    // === WoTrust ===
    /**
     * WoTrust TSA.
     * Note: Trusted by Adobe.
     * Commercial trust service provider.
     */
    WOTRUS: "https://tsa.wotrus.com",

    // === Cesnet (Untrusted) ===
    /**
     * Cesnet TSA.
     * Note: Czech academic network.
     * NOT trusted by Adobe or EU lists.
     */
    CESNET: "https://tsa.cesnet.cz:3162/tsa",

    // === SINPE (Untrusted) ===
    /**
     * SINPE TSA (Costa Rica).
     * Note: Costa Rica national payment system.
     * NOT trusted by Adobe or EU lists.
     * Trailing slash required.
     */
    SINPE: "http://tsa.sinpe.fi.cr/tsaHttp/",

    // === Lex-Persona (Untrusted) ===
    /**
     * Lex-Persona TSA.
     * Note: Commercial service.
     * NOT trusted by Adobe or EU lists.
     */
    LEX_PERSONA: "http://tsa.lex-persona.com/tsa",

    // === MConnect (Untrusted) ===
    /**
     * MConnect TSA.
     * Note: Commercial service.
     * NOT trusted by Adobe or EU lists.
     */
    MCONNECT: "https://time.mconnect.mc",

    // === Trustwave (Untrusted) ===
    /**
     * Trustwave TSA.
     * Note: Commercial CA.
     * NOT trusted by Adobe or EU lists.
     */
    TRUSTWAVE: "http://timestamp.ssl.trustwave.com",

    // === Nowina DSS (Untrusted) ===
    /**
     * Nowina DSS TSA (Luxembourg).
     * Note: Research/pKI factory service.
     * NOT trusted by Adobe or EU lists.
     */
    NOWINA: "http://dss.nowina.lu/pki-factory/tsa/good-tsa",
} as const;

/**
 * Type representing the keys of KNOWN_TSA_URLS
 */
export type KnownTSAName = keyof typeof KNOWN_TSA_URLS;

/**
 * Type representing a URL from KNOWN_TSA_URLS
 */
export type KnownTSAUrl = (typeof KNOWN_TSA_URLS)[KnownTSAName];

/**
 * Type representing the keys of EXTENDED_TSA_URLS
 */
export type ExtendedTSAName = keyof typeof EXTENDED_TSA_URLS;

/**
 * Type representing a URL from EXTENDED_TSA_URLS
 */
export type ExtendedTSAUrl = (typeof EXTENDED_TSA_URLS)[ExtendedTSAName];

/**
 * All known TSA URLs combined
 */
export const ALL_KNOWN_TSA_URLS = {
    ...KNOWN_TSA_URLS,
    ...EXTENDED_TSA_URLS,
} as const;

/**
 * Type representing any known TSA URL
 */
export type AnyKnownTSAUrl = (typeof ALL_KNOWN_TSA_URLS)[keyof typeof ALL_KNOWN_TSA_URLS];
