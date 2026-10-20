export function flippedNonce(nonce: Uint8Array): Uint8Array {
    if (nonce.length === 0) return new Uint8Array([1]);
    const copy = new Uint8Array(nonce);
    const first = ((copy[0] ?? 0) ^ 1) & 0x7f;
    // 0x01 flips to zero; restoring 0x01 would reproduce the original
    // valid nonce. Use 0x02 so the negative fixture always differs.
    copy[0] = first === 0 ? 2 : first;
    return copy;
}
