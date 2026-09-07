// verifiedby@0.1.0 ships declarations but omits them from its package exports.
declare module "verifiedby" {
    export type VerifyStatus =
        | "no-signature"
        | "unsupported"
        | "mismatch"
        | "unverified"
        | "signed-untimed"
        | "verified-untrusted-root"
        | "verified";

    export interface VerifyResult {
        status: VerifyStatus;
        documentMatches?: boolean;
        timestampCount?: number;
        genTimeTrusted?: boolean;
        authority?: string | null;
    }

    export function verify(pdfBytes: Uint8Array): Promise<VerifyResult>;
}
