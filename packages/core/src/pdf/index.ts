export { preparePdfForTimestamp, type PreparedPDF, type PrepareOptions } from "./prepare.js";

export { embedTimestampToken, extractBytesToHash } from "./embed.js";

export {
    extractLTVData,
    completeLTVData,
    addDSS,
    addVRI,
    addVRIEnhanced,
    getDSSInfo,
    type LTVData,
    type CompletedLTVData,
} from "./ltv.js";

export { extractTimestamps, verifyTimestamp, type ExtractedTimestamp } from "./extract.js";
