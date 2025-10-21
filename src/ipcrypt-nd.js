import { ipToBytes, bytesToIp, randomBytes } from './utils.js';
import { encrypt as encryptBlock, decrypt as decryptBlock } from './core/kiasu-bc.js';

/**
 * Encrypts an IP address using KIASU-BC with an optional tweak.
 * If no tweak is provided, a random 8-byte tweak is generated.
 * Returns a 24-byte array containing the tweak followed by the ciphertext.
 * 
 * @param {string} ip - IP address to encrypt
 * @param {Uint8Array} key - 16-byte key
 * @param {Uint8Array} [tweak] - Optional 8-byte tweak
 * @returns {Uint8Array} 24-byte array (8-byte tweak + 16-byte ciphertext)
 * @throws {Error} If inputs are invalid
 */
export function encrypt(ip, key, tweak) {
    // Validate inputs
    if (typeof ip !== 'string') {
        throw new Error('IP address must be a string');
    }
    if (!(key instanceof Uint8Array) || key.length !== 16) {
        throw new Error('Key must be a 16-byte Uint8Array');
    }

    // Generate random tweak if not provided
    if (!tweak) {
        tweak = randomBytes(8);
    } else if (!(tweak instanceof Uint8Array) || tweak.length !== 8) {
        throw new Error('Tweak must be an 8-byte Uint8Array');
    }

    // Convert IP to bytes and encrypt
    const plaintext = ipToBytes(ip);
    const ciphertext = encryptBlock(key, tweak, plaintext);

    // Combine tweak and ciphertext
    const result = new Uint8Array(24);
    result.set(tweak);
    result.set(ciphertext, 8);
    return result;
}

/**
 * Decrypts an IP address that was encrypted with KIASU-BC.
 * Input must be a 24-byte array containing the tweak followed by the ciphertext.
 * 
 * @param {Uint8Array} encryptedData - 24-byte array (8-byte tweak + 16-byte ciphertext)
 * @param {Uint8Array} key - 16-byte key
 * @returns {string} Decrypted IP address
 * @throws {Error} If inputs are invalid
 */
export function decrypt(encryptedData, key) {
    // Validate inputs
    if (!(encryptedData instanceof Uint8Array) || encryptedData.length !== 24) {
        throw new Error('Encrypted data must be a 24-byte Uint8Array');
    }
    if (!(key instanceof Uint8Array) || key.length !== 16) {
        throw new Error('Key must be a 16-byte Uint8Array');
    }

    // Extract tweak and ciphertext
    const tweak = encryptedData.slice(0, 8);
    const ciphertext = encryptedData.slice(8);

    // Decrypt and convert back to IP
    const plaintext = decryptBlock(key, tweak, ciphertext);
    return bytesToIp(plaintext);
} 