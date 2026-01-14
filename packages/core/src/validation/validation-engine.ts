import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import {
    IValidationEngine,
    ValidationOptions,
    RichValidationResult,
    PadesProfileType,
    PadesProfile,
    PADES_PROFILES,
    ProfileRequirement,
    ValidationStatus,
    ValidationEvent,
    ValidationErrorCode,
    ValidationWarningCode,
    CertificateChain,
    RevocationInfo,
    ValidationDetail,
    CertificateStatus,
} from "./contracts.js";
import { ChainBuilder, RevocationChecker, createSimpleTrustStore } from "./chain-validator.js";
import { extractTimestamps, verifyTimestamp as coreVerifyTimestamp } from "../pdf/extract.js";
import { bytesToHex } from "../utils.js";

export class ValidationEngine implements IValidationEngine {
    constructor(private defaultOptions?: ValidationOptions) {}

    async validate(
        timestampToken: Uint8Array,
        options?: ValidationOptions
    ): Promise<RichValidationResult> {
        const mergedOptions = { ...this.defaultOptions, ...options };
        const events: ValidationEvent[] = [];
        const errors: ValidationErrorCode[] = [];
        const warnings: ValidationWarningCode[] = [];
        const details: ValidationDetail[] = [];
        const revocationInfo: RevocationInfo[] = [];

        const emitEvent = (event: Omit<ValidationEvent, "timestamp">) => {
            const fullEvent: ValidationEvent = {
                ...event,
                timestamp: new Date(),
            };
            events.push(fullEvent);
            mergedOptions.eventCallback?.(fullEvent);
        };

        emitEvent({
            type: "info",
            category: "CHAIN_BUILDING",
            code: "STARTING",
            message: "Starting timestamp validation",
        });

        try {
            const asn1 = asn1js.fromBER(timestampToken.slice().buffer);
            if (asn1.offset === -1) {
                throw new Error("Failed to parse timestamp token ASN.1");
            }

            const contentInfo = new pkijs.ContentInfo({ schema: asn1.result });
            const signedData = new pkijs.SignedData({ schema: contentInfo.content });

            const certificates: pkijs.Certificate[] = [];
            if (signedData.certificates) {
                for (const cert of signedData.certificates) {
                    if (cert instanceof pkijs.Certificate) {
                        certificates.push(cert);
                    }
                }
            }

            if (certificates.length === 0) {
                errors.push(ValidationErrorCode.INCOMPLETE_CHAIN);
                details.push({
                    stage: "CHAIN_BUILDING",
                    status: ValidationStatus.INVALID,
                    errorCode: ValidationErrorCode.INCOMPLETE_CHAIN,
                    message: "No certificates found in timestamp token",
                });

                return this.createResult(
                    ValidationStatus.INVALID,
                    undefined,
                    revocationInfo,
                    details,
                    errors,
                    warnings,
                    events,
                    mergedOptions.profile
                );
            }

            const tsaCert = certificates[0];
            if (!tsaCert) {
                errors.push(ValidationErrorCode.INCOMPLETE_CHAIN);
                details.push({
                    stage: "CHAIN_BUILDING",
                    status: ValidationStatus.INVALID,
                    errorCode: ValidationErrorCode.INCOMPLETE_CHAIN,
                    message: "No TSA certificate found in timestamp token",
                });

                return this.createResult(
                    ValidationStatus.INVALID,
                    undefined,
                    revocationInfo,
                    details,
                    errors,
                    warnings,
                    events,
                    mergedOptions.profile
                );
            }
            emitEvent({
                type: "info",
                category: "CHAIN_BUILDING",
                code: "TSA_CERTIFICATE_FOUND",
                message: `TSA Certificate: ${tsaCert.subject.toString()}`,
            });

            const chainBuilder = new ChainBuilder();
            let certificateChain: CertificateChain | undefined;

            if (mergedOptions.chainBuilder) {
                certificateChain = await mergedOptions.chainBuilder.buildChain(tsaCert, {
                    maxDepth: mergedOptions.maxChainDepth,
                });
            } else {
                certificateChain = await chainBuilder.buildChain(tsaCert, {
                    maxDepth: mergedOptions.maxChainDepth,
                    enableAIAFetching: true,
                });
            }

            if (mergedOptions.trustStore && certificateChain.trustedRoot) {
                const trustAnchors = createSimpleTrustStore(
                    mergedOptions.trustStore.getTrustedCertificates()
                );

                const isTrusted = trustAnchors.some((tc) => {
                    const tcDer = tc.toSchema().toBER(false);
                    const rootDer = certificateChain.trustedRoot?.certificate
                        .toSchema()
                        .toBER(false);
                    if (!rootDer) {
                        return false;
                    }
                    return (
                        bytesToHex(new Uint8Array(tcDer)) === bytesToHex(new Uint8Array(rootDer))
                    );
                });

                if (!isTrusted) {
                    errors.push(ValidationErrorCode.TRUST_ANCHOR_MISSING);
                    warnings.push(ValidationWarningCode.NON_TLS_TRUST_ANCHOR);
                    details.push({
                        stage: "CHAIN_BUILDING",
                        status: ValidationStatus.INVALID,
                        errorCode: ValidationErrorCode.TRUST_ANCHOR_MISSING,
                        message: "TSA certificate chain does not lead to a trusted root",
                    });
                }
            }

            const revocationChecker = mergedOptions.revocationChecker ?? new RevocationChecker();
            if (mergedOptions.requireRevocationCheck !== false && certificateChain.complete) {
                try {
                    const revocations =
                        await revocationChecker.checkChainRevocation(certificateChain);
                    revocationInfo.push(...revocations);

                    const hasRevoked = revocations.some(
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
                    }
                } catch (e) {
                    errors.push(ValidationErrorCode.REVOCATION_STATUS_UNKNOWN);
                    warnings.push(ValidationWarningCode.REVOCATION_STATUS_UNKNOWN);
                    details.push({
                        stage: "REVOCATION_CHECK",
                        status: ValidationStatus.INDETERMINATE,
                        errorCode: ValidationErrorCode.REVOCATION_STATUS_UNKNOWN,
                        warningCode: ValidationWarningCode.REVOCATION_STATUS_UNKNOWN,
                        message: `Revocation check failed: ${e instanceof Error ? e.message : String(e)}`,
                    });
                }
            }

            const overallStatus = this.determineOverallStatus(errors, warnings);

            emitEvent({
                type: overallStatus === ValidationStatus.VALID ? "info" : "warning",
                category: "CHAIN_BUILDING",
                code: "COMPLETED",
                message: `Validation completed with status: ${overallStatus}`,
            });

            return this.createResult(
                overallStatus,
                certificateChain,
                revocationInfo,
                details,
                errors,
                warnings,
                events,
                mergedOptions.profile
            );
        } catch (e) {
            errors.push(ValidationErrorCode.UNKNOWN);
            emitEvent({
                type: "error",
                category: "CHAIN_BUILDING",
                code: "FAILED",
                message: `Validation failed: ${e instanceof Error ? e.message : String(e)}`,
            });

            return this.createResult(
                ValidationStatus.INVALID,
                undefined,
                revocationInfo,
                [
                    {
                        stage: "CHAIN_BUILDING",
                        status: ValidationStatus.INVALID,
                        errorCode: ValidationErrorCode.UNKNOWN,
                        message: e instanceof Error ? e.message : String(e),
                    },
                ],
                errors,
                warnings,
                events,
                mergedOptions.profile
            );
        }
    }

    async validatePdf(
        pdfBytes: Uint8Array,
        options?: ValidationOptions
    ): Promise<RichValidationResult> {
        const mergedOptions = { ...this.defaultOptions, ...options };

        try {
            const timestamps = await extractTimestamps(pdfBytes);

            if (timestamps.length === 0) {
                return {
                    overallStatus: ValidationStatus.INVALID,
                    isValid: false,
                    revocationInfo: [],
                    details: [
                        {
                            stage: "SIGNATURE_VERIFICATION",
                            status: ValidationStatus.INVALID,
                            errorCode: ValidationErrorCode.INVALID_SIGNATURE,
                            message: "No timestamp found in PDF",
                        },
                    ],
                    errors: [ValidationErrorCode.INVALID_SIGNATURE],
                    warnings: [ValidationWarningCode.NO_WARNING],
                    events: [],
                    validatedAt: new Date(),
                };
            }

            const timestampToVerify = timestamps[0];
            if (!timestampToVerify) {
                return {
                    overallStatus: ValidationStatus.INVALID,
                    isValid: false,
                    revocationInfo: [],
                    details: [
                        {
                            stage: "SIGNATURE_VERIFICATION",
                            status: ValidationStatus.INVALID,
                            errorCode: ValidationErrorCode.INVALID_SIGNATURE,
                            message: "No timestamp found in PDF",
                        },
                    ],
                    errors: [ValidationErrorCode.INVALID_SIGNATURE],
                    warnings: [ValidationWarningCode.NO_WARNING],
                    events: [],
                    validatedAt: new Date(),
                };
            }
            const extracted = await coreVerifyTimestamp(timestampToVerify, {
                strictESSValidation: mergedOptions.requireESSSigningCertificate,
            });

            // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
            if (extracted.token) {
                const result = await this.validate(extracted.token, mergedOptions);

                if (
                    mergedOptions.expectedTimestamp &&
                    result.overallStatus === ValidationStatus.VALID
                ) {
                    // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
                    if (extracted.info) {
                        const timeDiff = Math.abs(
                            mergedOptions.expectedTimestamp.getTime() -
                                extracted.info.genTime.getTime()
                        );
                        const tolerance = 5 * 60 * 1000;

                        if (timeDiff > tolerance) {
                            result.errors.push(ValidationErrorCode.TIMESTAMP_MISMATCH);
                            result.overallStatus = ValidationStatus.INVALID;
                            result.details.push({
                                stage: "TIMESTAMP_MATCH",
                                status: ValidationStatus.INVALID,
                                errorCode: ValidationErrorCode.TIMESTAMP_MISMATCH,
                                message: `Timestamp time does not match expected time (difference: ${String(Math.round(timeDiff / 1000))}s)`,
                            });
                        }
                    }
                }

                return result;
            }

            return {
                overallStatus: ValidationStatus.INVALID,
                isValid: false,
                revocationInfo: [],
                details: [
                    {
                        stage: "SIGNATURE_VERIFICATION",
                        status: ValidationStatus.INVALID,
                        errorCode: ValidationErrorCode.INVALID_SIGNATURE,
                        message: "No timestamp token in extracted timestamp",
                    },
                ],
                errors: [ValidationErrorCode.INVALID_SIGNATURE],
                warnings: [ValidationWarningCode.NO_WARNING],
                events: [],
                validatedAt: new Date(),
            };
        } catch (e) {
            return {
                overallStatus: ValidationStatus.INVALID,
                isValid: false,
                revocationInfo: [],
                details: [
                    {
                        stage: "SIGNATURE_VERIFICATION",
                        status: ValidationStatus.INVALID,
                        errorCode: ValidationErrorCode.INVALID_SIGNATURE,
                        message: e instanceof Error ? e.message : String(e),
                    },
                ],
                errors: [ValidationErrorCode.INVALID_SIGNATURE],
                warnings: [ValidationWarningCode.NO_WARNING],
                events: [],
                validatedAt: new Date(),
            };
        }
    }

    getProfile(profile: PadesProfileType): PadesProfile | undefined {
        return PADES_PROFILES[profile];
    }

    checkProfileCompliance(
        result: RichValidationResult,
        profile: PadesProfileType
    ): { compliant: boolean; failedRequirements: ProfileRequirement[] } {
        const profileDef: PadesProfile | undefined = PADES_PROFILES[profile];
        // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
        if (!profileDef) {
            return { compliant: false, failedRequirements: [] };
        }

        const failedRequirements: ProfileRequirement[] = [];

        for (const requirement of profileDef.requirements) {
            try {
                const passed = requirement.check(result);
                if (!passed) {
                    failedRequirements.push(requirement);
                }
            } catch {
                failedRequirements.push(requirement);
            }
        }

        return {
            compliant: failedRequirements.length === 0,
            failedRequirements,
        };
    }

    private determineOverallStatus(
        errors: ValidationErrorCode[],
        _warnings: ValidationWarningCode[]
    ): ValidationStatus {
        const criticalErrors = [
            ValidationErrorCode.EXPIRED_CERTIFICATE,
            ValidationErrorCode.REVOKED,
            ValidationErrorCode.INVALID_SIGNATURE,
            ValidationErrorCode.TRUST_ANCHOR_MISSING,
            ValidationErrorCode.ESS_CERT_ID_MISMATCH,
        ];

        if (errors.some((e) => criticalErrors.includes(e))) {
            return ValidationStatus.INVALID;
        }

        if (errors.length > 0) {
            return ValidationStatus.INDETERMINATE;
        }

        return ValidationStatus.VALID;
    }

    private createResult(
        overallStatus: ValidationStatus,
        certificateChain?: CertificateChain,
        revocationInfo?: RevocationInfo[],
        details?: ValidationDetail[],
        errors?: ValidationErrorCode[],
        warnings?: ValidationWarningCode[],
        events?: ValidationEvent[],
        profile?: PadesProfileType
    ): RichValidationResult {
        const profileConfig = profile ? PADES_PROFILES[profile] : undefined;

        return {
            overallStatus,
            isValid: overallStatus === ValidationStatus.VALID,
            certificateChain,
            revocationInfo: revocationInfo ?? [],
            details: details ?? [],
            errors: errors ?? [],
            warnings: warnings ?? [],
            events: events ?? [],
            validatedAt: new Date(),
            profile,
            strictnessLevel: profileConfig?.strictnessLevel,
        };
    }
}

export function createValidationEngine(options?: ValidationOptions): IValidationEngine {
    return new ValidationEngine(options);
}
