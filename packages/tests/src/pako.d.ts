declare module "pako" {
    interface InflateInstance {
        err: number;
        msg: string;
        onData: (chunk: Uint8Array) => void;
        push(input: Uint8Array, mode: boolean): boolean;
    }

    const pako: {
        Inflate: new (options?: { chunkSize?: number }) => InflateInstance;
    };

    export default pako;
}
