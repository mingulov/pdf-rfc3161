export { preparePdfForTimestamp, type PreparedPDF, type PrepareOptions } from "./prepare.js";

export { embedTimestampToken, extractBytesToHash } from "./embed.js";

export {
    extractLTVData,
    completeLTVData,
    addDSS,
    addVRIForSignature,
    // eslint-disable-next-line @typescript-eslint/no-deprecated -- legacy source API remains callable.
    addVRI,
    // eslint-disable-next-line @typescript-eslint/no-deprecated -- legacy source API remains callable.
    addVRIEnhanced,
    getDSSInfo,
    type LTVData,
    type CompletedLTVData,
    type AddVRIForSignatureOptions,
} from "./ltv.js";

export { extractTimestamps, verifyTimestamp, type ExtractedTimestamp } from "./extract.js";
