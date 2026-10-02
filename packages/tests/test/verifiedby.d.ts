// verifiedby@0.1.0 ships declarations but omits them from its package exports.
// This shim mirrors src/verify-core.d.ts of the pinned engine (SHA-256
// 6ccfb6e6ee5568d1102226410341b15f5806f9927129de92debd304e4964feff,
// verifiedby f7c933e601a7febbc6a8f572ca30dc275c908905). The T00 browser
// gate asserts the installed engine hash before trusting any verdict.
// T15 extends the subset with the per-element surface the C04 closure
// asserts (anchored, time, imprint, computed) and the trustAnchors
// parameter; every added member matches the pinned declaration file.
declare module "verifiedby" {
    export type VerifyStatus =
        | "no-signature"
        | "unsupported"
        | "mismatch"
        | "unverified"
        | "signed-untimed"
        | "verified-untrusted-root"
        | "verified";

    export interface TimeInfo {
        value: Date | null;
        trusted: boolean;
        source: string;
    }

    export interface VerifyElement {
        kind: "doctimestamp" | "signature" | "unsupported" | "unreadable";
        subFilter: string | null;
        supported: boolean;
        byteRange: [number, number, number, number];
        trailingKind?: "none" | "signature-update" | "page-content" | "appended-data";
        documentMatches?: boolean | null;
        signatureValid?: boolean;
        attrsCommit?: boolean;
        chainValid?: boolean;
        anchored?: boolean;
        withinValidity?: boolean;
        authentic?: boolean;
        time?: TimeInfo;
        hashAlg?: string | null;
        imprint?: string | null;
        computed?: string | null;
        notes: string[];
    }

    export interface VerifyResult {
        status: VerifyStatus;
        elements: VerifyElement[];
        documentMatches?: boolean;
        timestampCount?: number;
        genTime?: Date | null;
        genTimeTrusted?: boolean;
        authority?: string | null;
        hashAlg?: string | null;
        byteRange?: [number, number, number, number];
        notes: string[];
    }

    export interface SignatureDictionary {
        byteRange: [number, number, number, number];
        signed: Uint8Array;
        token: Uint8Array;
        subFilter: string | null;
        dictType: string | null;
        coversWholeFile: boolean;
        trailingBytes: number;
        trailing: string;
    }

    export function verify(
        pdfBytes: Uint8Array,
        trustAnchors?: Uint8Array[]
    ): Promise<VerifyResult>;
    export function extractSignatures(bytes: Uint8Array): SignatureDictionary[];
}
