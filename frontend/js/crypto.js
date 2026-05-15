/**
 * Browser-side hash-based signature utilities.
 *
 * This prototype uses a WOTS-style SHA-256 signature bundle. WOTS is the
 * one-time signature family used inside XMSS/SPHINCS-style hash-based systems,
 * which lets the Flask server verify signatures with public material only.
 */

class QuantumCrypto {
    static WOTS_ALGORITHM = 'WOTS-SHA256';
    static WOTS_PUBLIC_TYPE = 'PQC-AUTH-PUBLIC';
    static WOTS_PRIVATE_TYPE = 'PQC-AUTH-PRIVATE';
    static WOTS_SIGNATURE_TYPE = 'PQC-AUTH-SIGNATURE';
    static WOTS_W = 16;
    static WOTS_CHAIN_STEPS = 15;
    static WOTS_SECRET_SIZE = 32;
    static WOTS_LEN1 = 64;
    static WOTS_LEN2 = 3;
    static WOTS_LEN = 67;
    static DEFAULT_SIGNATURE_SLOTS = 16;

    /**
     * Generate a browser-verifiable post-quantum key bundle.
     *
     * @returns {Promise<Object>} {publicKey, privateKey, algorithm, signatureSlots}
     */
    static async generateKeyPair(slotCount = this.DEFAULT_SIGNATURE_SLOTS) {
        if (!Number.isInteger(slotCount) || slotCount <= 0) {
            throw new Error('Signature slot count must be a positive integer');
        }

        const materialLength = slotCount * this.WOTS_LEN * this.WOTS_SECRET_SIZE;
        const privateMaterial = new Uint8Array(materialLength);
        const publicMaterial = new Uint8Array(materialLength);
        crypto.getRandomValues(privateMaterial);

        for (let offset = 0; offset < materialLength; offset += this.WOTS_SECRET_SIZE) {
            const secret = privateMaterial.slice(offset, offset + this.WOTS_SECRET_SIZE);
            const publicValue = await this._chain(secret, this.WOTS_CHAIN_STEPS);
            publicMaterial.set(publicValue, offset);
        }

        const publicKey = JSON.stringify({
            type: this.WOTS_PUBLIC_TYPE,
            algorithm: this.WOTS_ALGORITHM,
            slots: slotCount,
            key: this._bytesToBase64Url(publicMaterial)
        });

        const privateKey = JSON.stringify({
            type: this.WOTS_PRIVATE_TYPE,
            algorithm: this.WOTS_ALGORITHM,
            slots: slotCount,
            key: this._bytesToBase64Url(privateMaterial)
        });

        return {
            publicKey,
            privateKey,
            algorithm: this.WOTS_ALGORITHM,
            signatureSlots: slotCount
        };
    }

    /**
     * Sign username + nonce with a one-time key slot assigned by the server.
     *
     * @param {string} message - Message to sign
     * @param {string} privateKey - Private key bundle JSON
     * @param {number} keyIndex - One-time signature slot from /auth/nonce
     * @returns {Promise<string>} Signature envelope JSON
     */
    static async signMessage(message, privateKey, keyIndex = 0) {
        const parsedKey = this._parsePrivateKey(privateKey);

        if (keyIndex < 0 || keyIndex >= parsedKey.slots) {
            throw new Error('This private key does not contain the requested signature slot');
        }

        const digits = await this._messageDigits(message);
        const slotOffset = keyIndex * this.WOTS_LEN * this.WOTS_SECRET_SIZE;
        const signatureMaterial = new Uint8Array(this.WOTS_LEN * this.WOTS_SECRET_SIZE);

        for (let i = 0; i < digits.length; i++) {
            const privateOffset = slotOffset + (i * this.WOTS_SECRET_SIZE);
            const secret = parsedKey.keyMaterial.slice(privateOffset, privateOffset + this.WOTS_SECRET_SIZE);
            const signaturePiece = await this._chain(secret, digits[i]);
            signatureMaterial.set(signaturePiece, i * this.WOTS_SECRET_SIZE);
        }

        return JSON.stringify({
            type: this.WOTS_SIGNATURE_TYPE,
            algorithm: this.WOTS_ALGORITHM,
            slot: keyIndex,
            signature: this._bytesToBase64Url(signatureMaterial)
        });
    }

    /**
     * Client-side format verification for quick feedback.
     */
    static async verifySignature(message, signature, publicKey) {
        try {
            const parsedSignature = JSON.parse(signature);
            const parsedPublic = JSON.parse(publicKey);
            return parsedSignature.algorithm === this.WOTS_ALGORITHM &&
                parsedPublic.algorithm === this.WOTS_ALGORITHM &&
                typeof message === 'string';
        } catch (error) {
            console.error('Signature verification error:', error);
            return false;
        }
    }

    static exportKeyPair(publicKey, privateKey) {
        return {
            type: 'PQC-AUTH-KEYPAIR',
            publicKey,
            privateKey,
            algorithm: this.WOTS_ALGORITHM,
            generatedAt: new Date().toISOString()
        };
    }

    static importKeyPair(jsonData) {
        const data = typeof jsonData === 'string' ? JSON.parse(jsonData) : jsonData;

        if (data.type === 'PQC-AUTH-KEYPAIR') {
            this._parsePrivateKey(data.privateKey);
            return {
                publicKey: data.publicKey,
                privateKey: data.privateKey,
                algorithm: data.algorithm || this.WOTS_ALGORITHM
            };
        }

        if (data.type === this.WOTS_PRIVATE_TYPE) {
            this._parsePrivateKey(JSON.stringify(data));
            return {
                privateKey: JSON.stringify(data),
                algorithm: this.WOTS_ALGORITHM
            };
        }

        throw new Error('Invalid key pair format');
    }

    static getPrivateKeyInfo(privateKey) {
        const parsed = this._parsePrivateKey(privateKey);
        return {
            algorithm: parsed.algorithm,
            slots: parsed.slots
        };
    }

    static _parsePrivateKey(privateKey) {
        let payload;
        try {
            payload = typeof privateKey === 'string' ? JSON.parse(privateKey) : privateKey;
        } catch (error) {
            throw new Error('Private key must be a valid JSON key bundle');
        }

        if (payload.type !== this.WOTS_PRIVATE_TYPE || payload.algorithm !== this.WOTS_ALGORITHM) {
            throw new Error('Unsupported private key algorithm');
        }

        const slots = Number(payload.slots);
        if (!Number.isInteger(slots) || slots <= 0) {
            throw new Error('Invalid signature slot count in private key');
        }

        const keyMaterial = this._base64UrlToBytes(payload.key);
        const expectedLength = slots * this.WOTS_LEN * this.WOTS_SECRET_SIZE;
        if (keyMaterial.length !== expectedLength) {
            throw new Error('Private key material length does not match metadata');
        }

        return {
            algorithm: payload.algorithm,
            slots,
            keyMaterial
        };
    }

    static async _messageDigits(message) {
        const encoder = new TextEncoder();
        const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(message)));
        const digits = [];

        for (const byte of digest) {
            digits.push(byte >> 4);
            digits.push(byte & 0x0f);
        }

        const checksum = digits.reduce((total, digit) => total + (this.WOTS_CHAIN_STEPS - digit), 0);
        digits.push((checksum >> 8) & 0x0f);
        digits.push((checksum >> 4) & 0x0f);
        digits.push(checksum & 0x0f);

        return digits;
    }

    static async _chain(value, steps) {
        let node = value;
        for (let i = 0; i < steps; i++) {
            node = new Uint8Array(await crypto.subtle.digest('SHA-256', node));
        }
        return node;
    }

    static _bytesToBase64Url(bytes) {
        let binary = '';
        const chunkSize = 0x8000;

        for (let i = 0; i < bytes.length; i += chunkSize) {
            const chunk = bytes.subarray(i, i + chunkSize);
            binary += String.fromCharCode(...chunk);
        }

        return btoa(binary)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/g, '');
    }

    static _base64UrlToBytes(value) {
        if (typeof value !== 'string' || !value) {
            throw new Error('Missing base64url key material');
        }

        const base64 = value
            .replace(/-/g, '+')
            .replace(/_/g, '/')
            .padEnd(Math.ceil(value.length / 4) * 4, '=');
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);

        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }

        return bytes;
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = QuantumCrypto;
}
