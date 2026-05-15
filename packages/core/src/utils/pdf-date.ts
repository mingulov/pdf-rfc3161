/**
 * Parses a PDF date string (RFC 3833/ISO 32000-1 7.9.4) into a JS `Date`.
 *
 * Accepts the encoded form `D:YYYYMMDDHHmmSSOHH'mm'` (with or without the `D:`
 * prefix, and surrounding parentheses are stripped by callers before invoking
 * this). Returns `undefined` if the string cannot be parsed.
 */
export function parsePdfDate(raw: string): Date | undefined {
    const mStr = raw.replace(/^\(/, "").replace(/\)$/, "").replace("D:", "");
    try {
        const year = parseInt(mStr.substring(0, 4));
        const month = parseInt(mStr.substring(4, 6)) - 1;
        const day = parseInt(mStr.substring(6, 8));
        const hour = parseInt(mStr.substring(8, 10));
        const min = parseInt(mStr.substring(10, 12));
        const sec = parseInt(mStr.substring(12, 14));

        let iso = `${String(year)}-${String(month + 1).padStart(2, "0")}-${String(day).padStart(2, "0")}T${String(hour).padStart(2, "0")}:${String(min).padStart(2, "0")}:${String(sec).padStart(2, "0")}`;

        if (mStr.length > 14) {
            const rest = mStr.substring(14);
            if (rest === "Z") {
                iso += "Z";
            } else {
                // `+HH'mm'` -> `+HH:mm`
                const cleanOffset = rest.replace(/^([+-]\d{2})'(\d{2})'$/, "$1:$2");
                iso += cleanOffset;
            }
        } else {
            iso += "Z"; // Assume UTC if missing
        }

        const m = new Date(iso);
        return isNaN(m.getTime()) ? undefined : m;
    } catch {
        return undefined;
    }
}
