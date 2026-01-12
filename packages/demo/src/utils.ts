
/**
 * Triggers a browser download of a Blob object.
 */
export function downloadBlob(blob: Blob, name: string) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);
}

/**
 * Converts a Base64 string to a Uint8Array.
 */
export function base64ToUint8Array(base64: string) {
    const binary = window.atob(base64.trim());
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

/**
 * Generates a JavaScript fetch script for TSA/OCSP/CRL requests to be run in the browser console.
 */
export function generateFetchConsoleScript(url: string, bodyBytes?: Uint8Array, label: string = "Response", contentType: string = "application/timestamp-query") {
    const method = bodyBytes ? "POST" : "GET";
    const headers = contentType ? `headers: { "Content-Type": "${contentType}" }, ` : "";
    const bodyText = bodyBytes ? `body: new Uint8Array([${Array.from(bodyBytes).join(',')}]) ` : "";

    return `fetch("${url}", {
    method: "${method}",
    ${headers}${bodyText}
}).then(r => r.arrayBuffer()).then(b => {
    const b64 = btoa(String.fromCharCode(...new Uint8Array(b)));
    console.log("${label} Base64:");
    console.log(b64);
    try { 
        navigator.clipboard.writeText(b64); 
        console.log("Copied to clipboard!"); 
    } catch(e) {
        console.log("Copy manually above");
    }
})`;
}

/**
 * Minimal version for one-liner copy
 */
export function generateFetchConsoleScriptOneLiner(url: string, bodyBytes?: Uint8Array, contentType: string = "application/timestamp-query") {
    const method = bodyBytes ? "POST" : "GET";
    const headers = contentType ? `headers: { "Content-Type": "${contentType}" }, ` : "";
    const bodyText = bodyBytes ? `body: new Uint8Array([${Array.from(bodyBytes).join(',')}]) ` : "";

    return `fetch("${url}", { method: "${method}", ${headers}${bodyText} }).then(r => r.arrayBuffer()).then(b => { const b64 = btoa(String.fromCharCode(...new Uint8Array(b))); console.log(b64); try { navigator.clipboard.writeText(b64); } catch(e){console.log("Copy manually");} })`;
}
