"use strict";

const { webcrypto } = require("node:crypto");

const NONCE = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]);

webcrypto.getRandomValues = (target) => {
    for (let index = 0; index < target.length; index += 1) {
        target[index] = NONCE[index % NONCE.length];
    }
    return target;
};
