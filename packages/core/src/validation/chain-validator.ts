import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import {
    IChainBuilder,
    IRevocationChecker,
    IFetcher,
    IValidationCache,
    ChainBuilderOptions,
    RevocationCheckerOptions,
    RevocationInfo,
    ChainNode,
    CertificateChain,
    ValidationEvent,
    ValidationErrorCode,
    ValidationStatus,
    ValidationDetail,
    ValidationWarningCode,
} from "./contracts.js";
import { getCaIssuers, findIssuer } from "../pki/cert-utils.js";
import {
    getOCSPURI,
    createOCSPRequest,
    parseOCSPResponse,
    CertificateStatus,
} from "../pki/ocsp-utils.js";
import { getCRLDistributionPoints } from "../pki/crl-utils.js";
import { fetchOCSPResponse } from "../pki/ocsp-client.js";
import { fetchCRL } from "../pki/crl-client.js";
import { fetchCertificate } from "../pki/cert-client.js";
import { bytesToHex } from "../utils.js";
import { getLogger } from "../utils/logger.js";

function formatError(error: unknown): string {
    if (error instanceof Error) {
        return error.message;
    }
    return String(error);
}

class DefaultFetcher implements IFetcher {
    async fetchCertificate(url: string): Promise<Uint8Array> {
        return fetchCertificate(url);
    }

    async fetchOCSP(url: string, request: Uint8Array): Promise<Uint8Array> {
        return fetchOCSPResponse(url, request);
    }

    async fetchCRL(url: string): Promise<Uint8Array> {
        return fetchCRL(url);
    }
}

class MemoryCacheWrapper implements IValidationCache {
    private certCache = new Map<string, Uint8Array>();
    private ocspCache = new Map<string, Uint8Array>();
    private crlCache = new Map<string, Uint8Array>();

    getCertificate(url: string): Uint8Array | null {
        return this.certCache.get(url) ?? null;
    }

    setCertificate(url: string, cert: Uint8Array): void {
        this.certCache.set(url, cert);
    }

    private ocspKey(url: string, request: Uint8Array): string {
        return `${url}:${bytesToHex(request)}`;
    }

    getOCSP(url: string, request: Uint8Array): Uint8Array | null {
        return this.ocspCache.get(this.ocspKey(url, request)) ?? null;
    }

    setOCSP(url: string, request: Uint8Array, response: Uint8Array): void {
        this.ocspCache.set(this.ocspKey(url, request), response);
    }

    getCRL(url: string): Uint8Array | null {
        return this.crlCache.get(url) ?? null;
    }

    setCRL(url: string, crl: Uint8Array): void {
        this.crlCache.set(url, crl);
    }

    clear(): void {
        this.certCache.clear();
        this.ocspCache.clear();
        this.crlCache.clear();
    }

    size(): number {
        return this.certCache.size + this.ocspCache.size + this.crlCache.size;
    }
}

function createChainNode(
    cert: pkijs.Certificate,
    isTrusted: boolean,
    issuer?: ChainNode
): ChainNode {
    return {
        certificate: cert,
        isTrusted,
        isSelfSigned: cert.subject.toString() === cert.issuer.toString(),
        issuer,
        subject: cert.subject.toString(),
        serialNumber: cert.serialNumber.valueBlock.toString(),
        notBefore: cert.notBefore.value,
        notAfter: cert.notAfter.value,
    };
}

export class ChainBuilder implements IChainBuilder {
    private defaultFetcher = new DefaultFetcher();
    private defaultCache = new MemoryCacheWrapper();

    async buildChain(
        leafCertificate: pkijs.Certificate,
        options?: ChainBuilderOptions
    ): Promise<CertificateChain> {
        const logger = getLogger();
        const maxDepth = options?.maxDepth ?? 10;
        const enableAIAFetching = options?.enableAIAFetching ?? true;
        const fetcher = options?.fetcher ?? this.defaultFetcher;
        const cache = options?.cache ?? this.defaultCache;

        const nodes: ChainNode[] = [];
        const seenSerials = new Set<string>();
        let madeProgress = true;
        let depth = 0;

        const addNode = (
            cert: pkijs.Certificate,
            isTrusted: boolean,
            issuer?: ChainNode
        ): ChainNode => {
            const node = createChainNode(cert, isTrusted, issuer);
            nodes.push(node);
            seenSerials.add(cert.serialNumber.valueBlock.toString());
            return node;
        };

        addNode(leafCertificate, false);
        const allCerts: pkijs.Certificate[] = [leafCertificate];

        while (madeProgress && depth < maxDepth) {
            madeProgress = false;
            depth++;

            const currentCerts = [...allCerts];

            for (const cert of currentCerts) {
                const certSerial = cert.serialNumber.valueBlock.toString();

                if (seenSerials.has(certSerial) && cert !== leafCertificate) {
                    continue;
                }

                const isSelfSigned = cert.subject.toString() === cert.issuer.toString();
                if (isSelfSigned) {
                    continue;
                }

                const existingIssuer = findIssuer(cert, allCerts);
                if (existingIssuer) {
                    continue;
                }

                if (!enableAIAFetching) {
                    continue;
                }

                const caIssuersUrls = getCaIssuers(cert);
                if (caIssuersUrls.length === 0) {
                    continue;
                }

                for (const url of caIssuersUrls) {
                    try {
                        const cachedCert = cache.getCertificate(url);
                        let certBytes: Uint8Array;

                        if (cachedCert) {
                            certBytes = cachedCert;
                            logger.debug(`Using cached certificate from ${url}`);
                        } else {
                            certBytes = await fetcher.fetchCertificate(url);
                            cache.setCertificate(url, certBytes);
                        }

                        const asn1 = asn1js.fromBER(certBytes.slice().buffer);
                        if (asn1.offset === -1) {
                            continue;
                        }

                        const newCert = new pkijs.Certificate({ schema: asn1.result });
                        const newSerial = newCert.serialNumber.valueBlock.toString();

                        if (!seenSerials.has(newSerial)) {
                            logger.info(
                                `Fetched intermediate certificate: ${newCert.subject.toString()}`
                            );
                            allCerts.push(newCert);
                            addNode(newCert, false);
                            madeProgress = true;
                            break;
                        }
                    } catch {
                        const msg = `Failed to fetch CA issuer from ${url}`;
                        logger.warn(msg);
                    }
                }
            }
        }

        let trustedRoot: ChainNode | undefined;
        const roots = allCerts.filter((c) => c.subject.toString() === c.issuer.toString());

        if (roots.length > 0) {
            const root = roots[0];
            if (!root) {
                return {
                    nodes,
                    complete: false,
                    trustedRoot: undefined,
                    depth: nodes.length,
                };
            }
            const rootNode = createChainNode(root, true);
            nodes.push(rootNode);
            trustedRoot = rootNode;

            for (const node of nodes) {
                if (node.certificate.issuer.toString() === root.subject.toString()) {
                    node.issuer = rootNode;
                }
            }
        }

        return {
            nodes,
            complete: roots.length > 0,
            trustedRoot,
            depth: nodes.length,
        };
    }

    findIssuer(
        cert: pkijs.Certificate,
        knownCerts: pkijs.Certificate[]
    ): pkijs.Certificate | undefined {
        return findIssuer(cert, knownCerts);
    }
}

export class RevocationChecker implements IRevocationChecker {
    private defaultFetcher = new DefaultFetcher();
    private defaultCache = new MemoryCacheWrapper();

    async checkRevocation(
        certificate: pkijs.Certificate,
        issuer: pkijs.Certificate,
        options?: RevocationCheckerOptions
    ): Promise<RevocationInfo | null> {
        const fetcher = options?.fetcher ?? this.defaultFetcher;
        const cache = options?.cache ?? this.defaultCache;
        const preferOCSP = options?.preferOCSP ?? true;
        const timeout = options?.timeout ?? 30000;

        const ocspUrl = getOCSPURI(certificate);

        if (preferOCSP && ocspUrl) {
            try {
                const request = await createOCSPRequest(certificate, issuer);

                const cacheKey = request;
                const cachedResponse = cache.getOCSP(ocspUrl, cacheKey);

                let response: Uint8Array;
                let source: "NETWORK" | "CACHE" | "EMBEDDED" = "NETWORK";

                if (cachedResponse) {
                    response = cachedResponse;
                    source = "CACHE";
                } else {
                    const controller = new AbortController();
                    const timeoutId = setTimeout(() => {
                        controller.abort();
                    }, timeout);

                    try {
                        response = await fetcher.fetchOCSP(ocspUrl, request);
                        clearTimeout(timeoutId);
                        cache.setOCSP(ocspUrl, cacheKey, response);
                    } catch (e) {
                        clearTimeout(timeoutId);
                        throw e;
                    }
                }

                const parsed = parseOCSPResponse(response);

                return {
                    type: "OCSP",
                    url: ocspUrl,
                    status: parsed.certStatus,
                    thisUpdate: parsed.thisUpdate,
                    nextUpdate: parsed.nextUpdate,
                    rawResponse: response,
                    source,
                };
            } catch {
                if (options?.allowCRLFallback === false) {
                    return null;
                }
            }
        }

        const crlUrls = getCRLDistributionPoints(certificate);
        for (const url of crlUrls) {
            try {
                const cachedCRL = cache.getCRL(url);
                let crlBytes: Uint8Array;
                let source: "NETWORK" | "CACHE" | "EMBEDDED" = "NETWORK";

                if (cachedCRL) {
                    crlBytes = cachedCRL;
                    source = "CACHE";
                } else {
                    const controller = new AbortController();
                    const timeoutId = setTimeout(() => {
                        controller.abort();
                    }, timeout);

                    try {
                        crlBytes = await fetcher.fetchCRL(url);
                        clearTimeout(timeoutId);
                        cache.setCRL(url, crlBytes);
                    } catch (e) {
                        clearTimeout(timeoutId);
                        throw e;
                    }
                }

                return {
                    type: "CRL",
                    url,
                    status: "UNKNOWN",
                    rawResponse: crlBytes,
                    source,
                };
            } catch {
                continue;
            }
        }

        return null;
    }

    async checkChainRevocation(
        chain: CertificateChain,
        options?: RevocationCheckerOptions
    ): Promise<RevocationInfo[]> {
        const results: RevocationInfo[] = [];

        for (const node of chain.nodes) {
            if (node.isSelfSigned) {
                continue;
            }

            if (!node.issuer) {
                continue;
            }

            const revocation = await this.checkRevocation(
                node.certificate,
                node.issuer.certificate,
                options
            );
            if (revocation) {
                results.push(revocation);
            }
        }

        return results;
    }
}

export class ChainValidator {
    private chainBuilder: IChainBuilder;
    private revocationChecker: IRevocationChecker;
    private events: ValidationEvent[] = [];

    constructor(
        private config: {
            maxChainDepth?: number;
            enableRevocationCheck?: boolean;
            revocationOptions?: RevocationCheckerOptions;
            eventCallback?: (event: ValidationEvent) => void;
        }
    ) {
        this.chainBuilder = new ChainBuilder();
        this.revocationChecker = new RevocationChecker();
    }

    private emitEvent(event: Omit<ValidationEvent, "timestamp">): void {
        const fullEvent: ValidationEvent = {
            ...event,
            timestamp: new Date(),
        };
        this.events.push(fullEvent);
        this.config.eventCallback?.(fullEvent);
    }

    async validateChain(
        certificate: pkijs.Certificate,
        trustStore?: pkijs.Certificate[]
    ): Promise<{
        chain: CertificateChain;
        revocationInfo: RevocationInfo[];
        details: ValidationDetail[];
        errors: ValidationErrorCode[];
        warnings: ValidationWarningCode[];
    }> {
        const errors: ValidationErrorCode[] = [];
        const warnings: ValidationWarningCode[] = [];
        const details: ValidationDetail[] = [];

        this.emitEvent({
            type: "info",
            category: "CHAIN_BUILDING",
            code: "STARTING",
            message: "Starting certificate chain validation",
        });

        const chain = await this.chainBuilder.buildChain(certificate, {
            maxDepth: this.config.maxChainDepth,
            enableAIAFetching: true,
        });

        if (!chain.complete) {
            errors.push(ValidationErrorCode.INCOMPLETE_CHAIN);
            warnings.push(ValidationWarningCode.PARTIAL_CHAIN);
            details.push({
                stage: "CHAIN_BUILDING",
                status: ValidationStatus.INDETERMINATE,
                errorCode: ValidationErrorCode.INCOMPLETE_CHAIN,
                warningCode: ValidationWarningCode.PARTIAL_CHAIN,
                message: "Certificate chain is incomplete - no trusted root found",
            });
        } else {
            details.push({
                stage: "CHAIN_BUILDING",
                status: ValidationStatus.VALID,
                message: `Chain built successfully with ${String(chain.nodes.length)} certificates`,
            });
        }

        if (trustStore && chain.trustedRoot) {
            const isTrusted = trustStore.some((tc) => {
                const tcDer = tc.toSchema().toBER(false);
                const rootDer = chain.trustedRoot?.certificate.toSchema().toBER(false);
                if (!rootDer) {
                    return false;
                }
                return bytesToHex(new Uint8Array(tcDer)) === bytesToHex(new Uint8Array(rootDer));
            });

            if (!isTrusted) {
                errors.push(ValidationErrorCode.TRUST_ANCHOR_MISSING);
                warnings.push(ValidationWarningCode.NON_TLS_TRUST_ANCHOR);
                details.push({
                    stage: "CHAIN_BUILDING",
                    status: ValidationStatus.INVALID,
                    errorCode: ValidationErrorCode.TRUST_ANCHOR_MISSING,
                    message: "Trusted root not in trust store",
                });
            }
        }

        let revocationInfo: RevocationInfo[] = [];
        if (this.config.enableRevocationCheck !== false && chain.complete) {
            this.emitEvent({
                type: "info",
                category: "REVOCATION_CHECK",
                code: "STARTING",
                message: "Starting revocation checks",
            });

            try {
                revocationInfo = await this.revocationChecker.checkChainRevocation(
                    chain,
                    this.config.revocationOptions
                );

                const hasRevoked = revocationInfo.some(
                    (r) => r.status === CertificateStatus.REVOKED
                );
                if (hasRevoked) {
                    errors.push(ValidationErrorCode.REVOKED);
                    details.push({
                        stage: "REVOCATION_CHECK",
                        status: ValidationStatus.INVALID,
                        errorCode: ValidationErrorCode.REVOKED,
                        message: "Certificate has been revoked",
                    });
                } else {
                    details.push({
                        stage: "REVOCATION_CHECK",
                        status: ValidationStatus.VALID,
                        message: `Revocation checked for ${String(revocationInfo.length)} certificates`,
                    });
                }
            } catch (err) {
                errors.push(ValidationErrorCode.REVOCATION_STATUS_UNKNOWN);
                warnings.push(ValidationWarningCode.REVOCATION_STATUS_UNKNOWN);
                details.push({
                    stage: "REVOCATION_CHECK",
                    status: ValidationStatus.INDETERMINATE,
                    errorCode: ValidationErrorCode.REVOCATION_STATUS_UNKNOWN,
                    warningCode: ValidationWarningCode.REVOCATION_STATUS_UNKNOWN,
                    message: `Revocation check failed: ${formatError(err)}`,
                });
            }
        }

        return { chain, revocationInfo, details, errors, warnings };
    }

    getEvents(): ValidationEvent[] {
        return [...this.events];
    }

    clearEvents(): void {
        this.events = [];
    }
}

export function createSimpleTrustStore(
    certs: (Uint8Array | pkijs.Certificate)[]
): pkijs.Certificate[] {
    return certs.map((c) => {
        if (c instanceof pkijs.Certificate) {
            return c;
        }
        const asn1 = asn1js.fromBER(c.slice().buffer);
        return new pkijs.Certificate({ schema: asn1.result });
    });
}
