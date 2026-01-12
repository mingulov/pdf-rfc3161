import * as pkijs from "pkijs";

const _webcrypto = await import("crypto").then((m) => m.webcrypto);

export const cryptoEngine = new pkijs.CryptoEngine({
    name: "test",
    crypto: _webcrypto as unknown as Crypto,
    subtle: _webcrypto.subtle as unknown as SubtleCrypto,
});

pkijs.setEngine("test", cryptoEngine);

export async function generateRSAKeyPair(): Promise<{
    publicKey: CryptoKey;
    privateKey: CryptoKey;
}> {
     
    return _webcrypto.subtle.generateKey(
        {
            name: "RSASSA-PKCS1-v1_5",
            modulusLength: 2048,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: { name: "SHA-256" },
        },
        true,
        ["sign", "verify"]
    ) as unknown as { publicKey: CryptoKey; privateKey: CryptoKey };
}

export async function importKeyForCertificate(key: CryptoKey): Promise<pkijs.PublicKeyInfo> {
    const pkijsKey = new pkijs.PublicKeyInfo();
    await pkijsKey.importKey(key);
    return pkijsKey;
}
