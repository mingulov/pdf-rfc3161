import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import { readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export const TSA_POLICY = "1.3.6.1.4.1.57264.1.1";

export interface LocalTsaConfiguration {
    rootCert: string;
    config: string;
}

function commandOutput(result: SpawnSyncReturns<string>): string {
    return [result.stdout, result.stderr]
        .filter((value): value is string => typeof value === "string" && value.length > 0)
        .join("\n");
}

function runOpenSsl(args: string[]): SpawnSyncReturns<string> {
    const result = spawnSync("openssl", args, {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
    });
    if (result.error) {
        const errno = result.error as NodeJS.ErrnoException;
        if (errno.code === "ENOENT") {
            throw new Error("OpenSSL is required for the local TSA fixture");
        }
        throw new Error(`openssl could not be started: ${result.error.message}`);
    }
    return result;
}

function assertOpenSslSuccess(args: string[]): SpawnSyncReturns<string> {
    const result = runOpenSsl(args);
    assert.equal(result.status, 0, commandOutput(result));
    return result;
}

function createOpenSslConfig(directory: string): string {
    const configPath = join(directory, "tsa.cnf");
    writeFileSync(
        configPath,
        `[req]
distinguished_name = root_dn
prompt = no
x509_extensions = root_extensions

[root_dn]
CN = Offline PAdES Test Root

[root_extensions]
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash

[tsa_extensions]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature,nonRepudiation
extendedKeyUsage = critical,timeStamping
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer

[tsa]
default_tsa = tsa_config

[tsa_config]
dir = ${directory}
serial = $dir/tsaserial
crypto_device = builtin
signer_cert = $dir/tsa.pem
certs = $dir/root.pem
signer_key = $dir/tsa.key
signer_digest = sha256
default_policy = ${TSA_POLICY}
other_policies = ${TSA_POLICY}
digests = sha256,sha384,sha512
accuracy = secs:1
ordering = yes
tsa_name = yes
ess_cert_id_chain = no
ess_cert_id_alg = sha256
`
    );
    return configPath;
}

export function createLocalTsa(directory: string): LocalTsaConfiguration {
    const rootKey = join(directory, "root.key");
    const rootCert = join(directory, "root.pem");
    const tsaKey = join(directory, "tsa.key");
    const tsaRequest = join(directory, "tsa.csr");
    const tsaCert = join(directory, "tsa.pem");
    const config = createOpenSslConfig(directory);

    writeFileSync(join(directory, "index.txt"), "");
    writeFileSync(join(directory, "tsaserial"), "01\n");

    assertOpenSslSuccess([
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        rootKey,
        "-out",
        rootCert,
        "-days",
        "2",
        "-sha256",
        "-config",
        config,
        "-extensions",
        "root_extensions",
    ]);
    assertOpenSslSuccess([
        "genpkey",
        "-algorithm",
        "RSA",
        "-pkeyopt",
        "rsa_keygen_bits:2048",
        "-out",
        tsaKey,
    ]);
    assertOpenSslSuccess([
        "req",
        "-new",
        "-key",
        tsaKey,
        "-out",
        tsaRequest,
        "-subj",
        "/CN=Offline PAdES Test TSA",
    ]);
    assertOpenSslSuccess([
        "x509",
        "-req",
        "-in",
        tsaRequest,
        "-CA",
        rootCert,
        "-CAkey",
        rootKey,
        "-CAcreateserial",
        "-out",
        tsaCert,
        "-days",
        "2",
        "-sha256",
        "-extfile",
        config,
        "-extensions",
        "tsa_extensions",
    ]);

    const certificateText = assertOpenSslSuccess(["x509", "-in", tsaCert, "-noout", "-text"])
        .stdout;
    const lines = certificateText.split("\n");
    const ekuHeader = lines.findIndex((line) =>
        line.includes("X509v3 Extended Key Usage: critical")
    );
    assert.ok(ekuHeader >= 0, "Local TSA certificate must have a critical EKU extension");
    const ekuValue = lines.slice(ekuHeader + 1).find((line) => line.trim().length > 0);
    assert.equal(ekuValue?.trim(), "Time Stamping", "Local TSA certificate EKU must be exclusive");

    return { rootCert, config };
}

export function createTimestampResponse(
    directory: string,
    config: string,
    request: Uint8Array
): Uint8Array {
    const suffix = randomUUID();
    const requestPath = join(directory, `request-${suffix}.tsq`);
    const responsePath = join(directory, `response-${suffix}.tsr`);
    writeFileSync(requestPath, request);
    try {
        assertOpenSslSuccess([
            "ts",
            "-reply",
            "-queryfile",
            requestPath,
            "-config",
            config,
            "-out",
            responsePath,
        ]);
        return new Uint8Array(readFileSync(responsePath));
    } finally {
        rmSync(requestPath, { force: true });
        rmSync(responsePath, { force: true });
    }
}
