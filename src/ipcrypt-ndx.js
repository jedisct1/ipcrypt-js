import { subBytes, shiftRows, mixColumns, expandKey } from './core/aes.js';
import { ipToBytes, bytesToIp, randomBytes } from './utils.js';

/**
 * Encrypt a single block using AES-XTS mode (XEX Tweakable Block Cipher with Ciphertext Stealing).
 * AES-XTS uses two keys: K1 for the main encryption and K2 for tweak processing.
 * The tweak is first encrypted with K2, then the result is used in both pre- and post-whitening
 * of the main encryption with K1. This provides strong security for IP address encryption.
 * 
 * Process:
 * 1. Split the 32-byte key into K1 and K2 (16 bytes each)
 * 2. Encrypt the tweak with AES using K2
 * 3. XOR plaintext with encrypted tweak
 * 4. Encrypt the result with AES using K1
 * 5. XOR the result with encrypted tweak again
 * 
 * @param {Uint8Array} key - 32-byte key (K1||K2)
 * @param {Uint8Array} tweak - 16-byte tweak
 * @param {Uint8Array} plaintext - 16-byte plaintext
 * @returns {Uint8Array} 16-byte ciphertext
 * @throws {Error} If any input is invalid
 */
function encryptBlockXts(key, tweak, plaintext) {
    if (!(key instanceof Uint8Array) || key.length !== 32) {
        throw new Error('Key must be a 32-byte Uint8Array');
    }
    if (!(tweak instanceof Uint8Array) || tweak.length !== 16) {
        throw new Error('Tweak must be a 16-byte Uint8Array');
    }
    if (!(plaintext instanceof Uint8Array) || plaintext.length !== 16) {
        throw new Error('Plaintext must be a 16-byte Uint8Array');
    }

    // Split key into K1 and K2
    const k1 = key.slice(0, 16);
    const k2 = key.slice(16);

    // Generate round keys for both K1 and K2
    const roundKeys1 = expandKey(k1);
    const roundKeys2 = expandKey(k2);

    // Encrypt tweak with K2
    const encryptedTweak = new Uint8Array(16);
    encryptedTweak.set(tweak);

    // Initial round for tweak
    for (let i = 0; i < 16; i++) {
        encryptedTweak[i] ^= roundKeys2[i];
    }

    // Main rounds for tweak
    for (let round = 1; round < 10; round++) {
        subBytes(encryptedTweak);
        shiftRows(encryptedTweak);
        mixColumns(encryptedTweak);
        for (let i = 0; i < 16; i++) {
            encryptedTweak[i] ^= roundKeys2[round * 16 + i];
        }
    }

    // Final round for tweak
    subBytes(encryptedTweak);
    shiftRows(encryptedTweak);
    for (let i = 0; i < 16; i++) {
        encryptedTweak[i] ^= roundKeys2[160 + i];
    }

    // XOR plaintext with encrypted tweak
    const state = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
        state[i] = plaintext[i] ^ encryptedTweak[i];
    }

    // Initial round
    for (let i = 0; i < 16; i++) {
        state[i] ^= roundKeys1[i];
    }

    // Main rounds
    for (let round = 1; round < 10; round++) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        for (let i = 0; i < 16; i++) {
            state[i] ^= roundKeys1[round * 16 + i];
        }
    }

    // Final round
    subBytes(state);
    shiftRows(state);
    for (let i = 0; i < 16; i++) {
        state[i] ^= roundKeys1[160 + i];
    }

    // XOR with encrypted tweak again
    for (let i = 0; i < 16; i++) {
        state[i] ^= encryptedTweak[i];
    }

    return state;
}

/**
 * Decrypt a single block using AES-XTS mode.
 * The decryption process is the inverse of encryption:
 * 1. Split the 32-byte key into K1 and K2 (16 bytes each)
 * 2. Encrypt the tweak with AES using K2 (same as encryption)
 * 3. XOR ciphertext with encrypted tweak
 * 4. Decrypt the result with AES using K1
 * 5. XOR the result with encrypted tweak again
 * 
 * @param {Uint8Array} key - 32-byte key (K1||K2)
 * @param {Uint8Array} tweak - 16-byte tweak
 * @param {Uint8Array} ciphertext - 16-byte ciphertext
 * @returns {Uint8Array} 16-byte plaintext
 * @throws {Error} If any input is invalid
 */
function decryptBlockXts(key, tweak, ciphertext) {
    if (!(key instanceof Uint8Array) || key.length !== 32) {
        throw new Error('Key must be a 32-byte Uint8Array');
    }
    if (!(tweak instanceof Uint8Array) || tweak.length !== 16) {
        throw new Error('Tweak must be a 16-byte Uint8Array');
    }
    if (!(ciphertext instanceof Uint8Array) || ciphertext.length !== 16) {
        throw new Error('Ciphertext must be a 16-byte Uint8Array');
    }

    // Split key into K1 and K2
    const k1 = key.slice(0, 16);
    const k2 = key.slice(16);

    // Generate round keys for both K1 and K2
    const roundKeys1 = expandKey(k1);
    const roundKeys2 = expandKey(k2);

    // Encrypt tweak with K2
    const encryptedTweak = new Uint8Array(16);
    encryptedTweak.set(tweak);

    // Initial round for tweak
    for (let i = 0; i < 16; i++) {
        encryptedTweak[i] ^= roundKeys2[i];
    }

    // Main rounds for tweak
    for (let round = 1; round < 10; round++) {
        subBytes(encryptedTweak);
        shiftRows(encryptedTweak);
        mixColumns(encryptedTweak);
        for (let i = 0; i < 16; i++) {
            encryptedTweak[i] ^= roundKeys2[round * 16 + i];
        }
    }

    // Final round for tweak
    subBytes(encryptedTweak);
    shiftRows(encryptedTweak);
    for (let i = 0; i < 16; i++) {
        encryptedTweak[i] ^= roundKeys2[160 + i];
    }

    // XOR ciphertext with encrypted tweak
    const state = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
        state[i] = ciphertext[i] ^ encryptedTweak[i];
    }

    // Initial round
    for (let i = 0; i < 16; i++) {
        state[i] ^= roundKeys1[160 + i];
    }
    shiftRows(state, true);
    subBytes(state, true);

    // Main rounds
    for (let round = 9; round > 0; round--) {
        for (let i = 0; i < 16; i++) {
            state[i] ^= roundKeys1[round * 16 + i];
        }
        mixColumns(state, true);
        shiftRows(state, true);
        subBytes(state, true);
    }

    // Final round
    for (let i = 0; i < 16; i++) {
        state[i] ^= roundKeys1[i];
    }

    // XOR with encrypted tweak again
    for (let i = 0; i < 16; i++) {
        state[i] ^= encryptedTweak[i];
    }

    return state;
}

/**
 * Encrypt an IP address using AES-XTS mode.
 * This function provides non-deterministic encryption with strong security guarantees.
 * If no tweak is provided, a random one is generated, making the encryption non-deterministic.
 * The tweak is included in the output to allow for decryption.
 * 
 * @param {string} ip - IP address to encrypt
 * @param {Uint8Array} key - 32-byte key (K1||K2)
 * @param {Uint8Array} tweak - 16-byte tweak (optional)
 * @returns {Uint8Array} 32-byte output (tweak || ciphertext)
 * @throws {Error} If any input is invalid
 */
export function encrypt(ip, key, tweak = null) {
    if (!(key instanceof Uint8Array) || key.length !== 32) {
        throw new Error('Key must be a 32-byte Uint8Array');
    }

    // Generate random tweak if not provided
    if (!tweak) {
        tweak = randomBytes(16);
    } else if (!(tweak instanceof Uint8Array) || tweak.length !== 16) {
        throw new Error('Tweak must be a 16-byte Uint8Array');
    }

    const plaintext = ipToBytes(ip);
    const ciphertext = encryptBlockXts(key, tweak, plaintext);

    // Concatenate tweak and ciphertext
    const output = new Uint8Array(32);
    output.set(tweak);
    output.set(ciphertext, 16);
    return output;
}

/**
 * Decrypt an IP address using AES-XTS mode.
 * The input must include both the tweak and ciphertext used during encryption.
 * The first 16 bytes are the tweak, and the last 16 bytes are the ciphertext.
 * 
 * @param {Uint8Array} input - 32-byte input (tweak || ciphertext)
 * @param {Uint8Array} key - 32-byte key (K1||K2)
 * @returns {string} Decrypted IP address
 * @throws {Error} If any input is invalid
 */
export function decrypt(input, key) {
    if (!(input instanceof Uint8Array) || input.length !== 32) {
        throw new Error('Input must be a 32-byte Uint8Array');
    }
    if (!(key instanceof Uint8Array) || key.length !== 32) {
        throw new Error('Key must be a 32-byte Uint8Array');
    }

    const tweak = input.slice(0, 16);
    const ciphertext = input.slice(16);
    const plaintext = decryptBlockXts(key, tweak, ciphertext);
    return bytesToIp(plaintext);
} 