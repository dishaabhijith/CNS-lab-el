import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';

export class QuantumCrypto {
  static ML_DSA_ALGORITHM = 'ML-DSA-65';
  static WOTS_ALGORITHM = 'WOTS-SHA256';
  static WOTS_PUBLIC_TYPE = 'PQC-AUTH-PUBLIC';
  static WOTS_PRIVATE_TYPE = 'PQC-AUTH-PRIVATE';
  static WOTS_SIGNATURE_TYPE = 'PQC-AUTH-SIGNATURE';
  static DEFAULT_ALGORITHM = this.ML_DSA_ALGORITHM;
  static WOTS_W = 16;
  static WOTS_CHAIN_STEPS = 15;
  static WOTS_SECRET_SIZE = 32;
  static WOTS_LEN1 = 64;
  static WOTS_LEN2 = 3;
  static WOTS_LEN = 67;
  static DEFAULT_SIGNATURE_SLOTS = 16;

  static async generateKeyPair(slotCount = this.DEFAULT_SIGNATURE_SLOTS, algorithm = this.DEFAULT_ALGORITHM) {
    if (algorithm === this.ML_DSA_ALGORITHM) {
      return this.generateMlDsaKeyPair();
    }
    return this.generateWotsKeyPair(slotCount);
  }

  static generateMlDsaKeyPair() {
    const keyPair = ml_dsa65.keygen();
    const publicKey = JSON.stringify({
      type: this.WOTS_PUBLIC_TYPE,
      algorithm: this.ML_DSA_ALGORITHM,
      key: this._bytesToBase64Url(keyPair.publicKey)
    });

    const privateKey = JSON.stringify({
      type: this.WOTS_PRIVATE_TYPE,
      algorithm: this.ML_DSA_ALGORITHM,
      key: this._bytesToBase64Url(keyPair.secretKey)
    });

    return {
      publicKey,
      privateKey,
      algorithm: this.ML_DSA_ALGORITHM,
      signatureSlots: null,
      publicKeyBytes: keyPair.publicKey.length,
      privateKeyBytes: keyPair.secretKey.length
    };
  }

  static async generateWotsKeyPair(slotCount = this.DEFAULT_SIGNATURE_SLOTS) {
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
      signatureSlots: slotCount,
      publicKeyBytes: publicMaterial.length,
      privateKeyBytes: privateMaterial.length
    };
  }

  static async signMessage(message, privateKey, keyIndex = 0) {
    const parsedKey = this._parsePrivateKey(privateKey);

    if (parsedKey.algorithm === this.ML_DSA_ALGORITHM) {
      const encoded = new TextEncoder().encode(message);
      const signature = ml_dsa65.sign(encoded, parsedKey.keyMaterial);
      return JSON.stringify({
        type: this.WOTS_SIGNATURE_TYPE,
        algorithm: this.ML_DSA_ALGORITHM,
        signature: this._bytesToBase64Url(signature)
      });
    }

    if (keyIndex < 0 || keyIndex >= parsedKey.slots) {
      throw new Error('This private key does not contain the requested signature slot');
    }

    const digits = await this._messageDigits(message);
    const slotOffset = keyIndex * this.WOTS_LEN * this.WOTS_SECRET_SIZE;
    const signatureMaterial = new Uint8Array(this.WOTS_LEN * this.WOTS_SECRET_SIZE);

    for (let i = 0; i < digits.length; i += 1) {
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

  static exportKeyPair(publicKey, privateKey) {
    return {
      type: 'PQC-AUTH-KEYPAIR',
      publicKey,
      privateKey,
      algorithm: this.getPrivateKeyInfo(privateKey).algorithm,
      generatedAt: new Date().toISOString()
    };
  }

  static importKeyPair(jsonData) {
    const data = typeof jsonData === 'string' ? JSON.parse(jsonData) : jsonData;

    if (data.type === 'PQC-AUTH-KEYPAIR') {
      const info = this._parsePrivateKey(data.privateKey);
      return {
        publicKey: data.publicKey,
        privateKey: data.privateKey,
        algorithm: data.algorithm || info.algorithm
      };
    }

    if (data.type === this.WOTS_PRIVATE_TYPE) {
      const info = this._parsePrivateKey(JSON.stringify(data));
      return {
        privateKey: JSON.stringify(data),
        algorithm: info.algorithm
      };
    }

    throw new Error('Invalid key pair format');
  }

  static getPrivateKeyInfo(privateKey) {
    const parsed = this._parsePrivateKey(privateKey);
    return {
      algorithm: parsed.algorithm,
      slots: parsed.slots,
      bytes: parsed.keyMaterial.length
    };
  }

  static getPublicKeyInfo(publicKey) {
    const payload = typeof publicKey === 'string' ? JSON.parse(publicKey) : publicKey;
    if (payload.type !== this.WOTS_PUBLIC_TYPE) {
      throw new Error('Unsupported public key algorithm');
    }

    if (payload.algorithm === this.ML_DSA_ALGORITHM) {
      const keyMaterial = this._base64UrlToBytes(payload.key);
      if (keyMaterial.length !== ml_dsa65.lengths.publicKey) {
        throw new Error('ML-DSA public key length does not match metadata');
      }
      return {
        algorithm: payload.algorithm,
        slots: null,
        bytes: keyMaterial.length
      };
    }

    if (payload.algorithm !== this.WOTS_ALGORITHM) {
      throw new Error('Unsupported public key algorithm');
    }

    const slots = Number(payload.slots);
    if (!Number.isInteger(slots) || slots <= 0) {
      throw new Error('Invalid public key slot count');
    }
    const keyMaterial = this._base64UrlToBytes(payload.key);
    return {
      algorithm: payload.algorithm,
      slots,
      bytes: keyMaterial.length
    };
  }

  static summarizeJson(value) {
    if (!value) return null;
    const payload = typeof value === 'string' ? JSON.parse(value) : value;
    return {
      type: payload.type,
      algorithm: payload.algorithm,
      slots: payload.slots ?? null,
      chars: JSON.stringify(payload).length
    };
  }

  static _parsePrivateKey(privateKey) {
    let payload;
    try {
      payload = typeof privateKey === 'string' ? JSON.parse(privateKey) : privateKey;
    } catch (error) {
      throw new Error('Private key must be a valid JSON key bundle');
    }

    if (payload.type !== this.WOTS_PRIVATE_TYPE) {
      throw new Error('Unsupported private key algorithm');
    }

    if (payload.algorithm === this.ML_DSA_ALGORITHM) {
      const keyMaterial = this._base64UrlToBytes(payload.key);
      if (keyMaterial.length !== ml_dsa65.lengths.secretKey) {
        throw new Error('ML-DSA private key length does not match metadata');
      }
      return {
        algorithm: payload.algorithm,
        slots: null,
        keyMaterial
      };
    }

    if (payload.algorithm !== this.WOTS_ALGORITHM) {
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
    for (let i = 0; i < steps; i += 1) {
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

    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }

    return bytes;
  }
}
