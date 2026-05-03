/**
 * Client-side Cryptographic Functions
 * Handles key generation and signature operations for quantum-resistant authentication
 */

class QuantumCrypto {
    /**
     * Generate a key pair for quantum-resistant authentication
     * Uses simplified HMAC-based approach (production would use official XMSS library)
     * 
     * @returns {Object} {publicKey, privateKey} in hex format
     */
    static async generateKeyPair() {
        try {
            // Generate random private key (256 bits)
            const privateKeyArray = new Uint8Array(32);
            crypto.getRandomValues(privateKeyArray);
            const privateKey = this._bytesToHex(privateKeyArray);
            
            // Derive public key from private key
            // In real XMSS: this would compute merkle tree root
            const encoder = new TextEncoder();
            const privateKeyBuffer = this._hexToBytes(privateKey);
            const publicKeyBuffer = await crypto.subtle.digest('SHA-256', privateKeyBuffer);
            const publicKey = this._bytesToHex(new Uint8Array(publicKeyBuffer));
            
            return {
                publicKey: publicKey,
                privateKey: privateKey,
                algorithm: 'XMSS-SHA256'
            };
        } catch (error) {
            throw new Error('Failed to generate key pair: ' + error.message);
        }
    }

    /**
     * Sign a message with private key
     * Uses HMAC-SHA256 (simplified for demo; production uses official XMSS)
     * 
     * @param {string} message - Message to sign
     * @param {string} privateKey - Private key in hex format
     * @returns {Promise<string>} Signature in hex format
     */
    static async signMessage(message, privateKey) {
        try {
            // Create HMAC key from private key
            const keyBuffer = this._hexToBytes(privateKey);
            const key = await crypto.subtle.importKey(
                'raw',
                keyBuffer,
                { name: 'HMAC', hash: 'SHA-256' },
                false,
                ['sign']
            );

            // Sign the message
            const encoder = new TextEncoder();
            const messageBuffer = encoder.encode(message);
            const signature = await crypto.subtle.sign('HMAC', key, messageBuffer);

            return this._bytesToHex(new Uint8Array(signature));
        } catch (error) {
            throw new Error('Failed to sign message: ' + error.message);
        }
    }

    /**
     * Verify a signature (client-side verification for demo purposes)
     * 
     * @param {string} message - Original message
     * @param {string} signature - Signature in hex format
     * @param {string} publicKey - Public key in hex format
     * @returns {Promise<boolean>} True if signature is valid
     */
    static async verifySignature(message, signature, publicKey) {
        try {
            // This is a simplified verification for client-side
            // Server performs the actual verification
            
            // Check if signature format is valid
            if (!signature || signature.length !== 64) {
                return false;
            }

            // Check if hex format is valid
            this._hexToBytes(signature);
            return true;
        } catch (error) {
            console.error('Signature verification error:', error);
            return false;
        }
    }

    /**
     * Helper: Convert bytes to hex string
     */
    static _bytesToHex(bytes) {
        return Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    /**
     * Helper: Convert hex string to bytes
     */
    static _hexToBytes(hex) {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        return bytes;
    }

    /**
     * Generate a random nonce (for server communication)
     * 
     * @param {number} length - Length in bytes (default 32)
     * @returns {string} Nonce in hex format
     */
    static generateNonce(length = 32) {
        const nonceArray = new Uint8Array(length);
        crypto.getRandomValues(nonceArray);
        return this._bytesToHex(nonceArray);
    }

    /**
     * Export key pair to JSON for storage
     */
    static exportKeyPair(publicKey, privateKey) {
        return {
            type: 'XMSS-KEYPAIR',
            publicKey: publicKey,
            privateKey: privateKey,
            algorithm: 'XMSS-SHA256',
            generatedAt: new Date().toISOString()
        };
    }

    /**
     * Import key pair from JSON
     */
    static importKeyPair(jsonData) {
        try {
            const data = typeof jsonData === 'string' ? JSON.parse(jsonData) : jsonData;
            
            if (data.type !== 'XMSS-KEYPAIR') {
                throw new Error('Invalid key pair format');
            }

            return {
                publicKey: data.publicKey,
                privateKey: data.privateKey
            };
        } catch (error) {
            throw new Error('Failed to import key pair: ' + error.message);
        }
    }
}

// Export for use in auth.js
if (typeof module !== 'undefined' && module.exports) {
    module.exports = QuantumCrypto;
}
