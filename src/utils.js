import crypto from 'crypto';

// Constants for IPv4 and IPv6 validation
const IPV4_REGEX = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV4_MAPPED_PREFIX = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]);
const IPV6_GROUPS = 8;
const BYTES_LENGTH = 16;

/**
 * Convert an IP address string to its 16-byte representation.
 * Handles both IPv4 and IPv6 addresses, with IPv4 being mapped to IPv6.
 * 
 * @param {string} ip - IP address string (IPv4 or IPv6)
 * @returns {Uint8Array} 16-byte representation
 * @throws {Error} If the IP address is invalid or malformed
 */
export function ipToBytes(ip) {
    if (typeof ip !== 'string') {
        throw new Error('IP address must be a string');
    }

    // Try parsing as IPv4 first
    if (IPV4_REGEX.test(ip)) {
        const parts = ip.split('.').map(x => parseInt(x, 10));
        if (parts.some(x => isNaN(x) || x < 0 || x > 255)) {
            throw new Error(`Invalid IPv4 address: ${ip}`);
        }

        const bytes = new Uint8Array(BYTES_LENGTH);
        bytes.set(IPV4_MAPPED_PREFIX);
        bytes.set(parts, 12);
        return bytes;
    }

    // Handle IPv6
    const cleanIp = ip.trim().replace(/^\[|\]$/g, '');

    // Validate :: usage
    if (cleanIp.includes(':::') || (cleanIp.match(/::/g) || []).length > 1) {
        throw new Error(`Invalid IPv6 address (invalid :: usage): ${ip}`);
    }

    // Split and handle :: compression
    const parts = cleanIp.split(':');
    const doubleColonIndex = cleanIp.indexOf('::');

    if (doubleColonIndex !== -1) {
        const beforeDouble = parts.slice(0, parts.indexOf(''));
        const afterDouble = parts.slice(parts.indexOf('') + 1);
        const missingGroups = IPV6_GROUPS - (beforeDouble.length + afterDouble.length);

        if (missingGroups <= 0) {
            throw new Error(`Invalid IPv6 address (too many groups): ${ip}`);
        }

        parts.splice(parts.indexOf(''), 1, ...Array(missingGroups).fill('0'));
    }

    if (parts.length !== IPV6_GROUPS) {
        throw new Error(`Invalid IPv6 address (wrong number of groups): ${ip}`);
    }

    const bytes = new Uint8Array(BYTES_LENGTH);
    for (let i = 0; i < IPV6_GROUPS; i++) {
        const value = parseInt(parts[i] || '0', 16);
        if (isNaN(value) || value < 0 || value > 0xffff) {
            throw new Error(`Invalid IPv6 group: ${parts[i]}`);
        }
        bytes[i * 2] = (value >> 8) & 0xff;
        bytes[i * 2 + 1] = value & 0xff;
    }
    return bytes;
}

/**
 * Convert a 16-byte representation back to an IP address string.
 * Automatically detects and handles IPv4-mapped addresses.
 * 
 * @param {Uint8Array|Buffer} bytes - 16-byte representation
 * @returns {string} IP address string (IPv4 or IPv6)
 * @throws {Error} If the input is invalid
 */
export function bytesToIp(bytes) {
    const input = Buffer.isBuffer(bytes) ? new Uint8Array(bytes) : bytes;

    if (!(input instanceof Uint8Array)) {
        throw new Error('Input must be a Uint8Array or Buffer');
    }

    if (input.length !== BYTES_LENGTH) {
        throw new Error('Input must be exactly 16 bytes');
    }

    // Check for IPv4-mapped address
    const isIPv4Mapped = input.slice(0, 12).every((byte, index) =>
        index < 10 ? byte === 0 : byte === 0xff
    );

    if (isIPv4Mapped) {
        return Array.from(input.slice(12))
            .map(b => b.toString(10))
            .join('.');
    }

    // Handle IPv6
    const parts = Array.from({ length: IPV6_GROUPS }, (_, i) => {
        const value = (input[i * 2] << 8) | input[i * 2 + 1];
        return value.toString(16);
    });

    // Find best zero compression opportunity
    const findLongestZeroRun = (parts) => {
        let longest = { start: -1, length: 0 };
        let current = { start: -1, length: 0 };

        parts.forEach((part, i) => {
            if (part === '0') {
                if (current.length === 0) current.start = i;
                current.length++;
            } else {
                if (current.length > longest.length) longest = { ...current };
                current = { start: -1, length: 0 };
            }
        });

        if (current.length > longest.length) longest = current;
        return longest;
    };

    const zeroRun = findLongestZeroRun(parts);

    if (zeroRun.length >= 2) {
        const before = parts.slice(0, zeroRun.start);
        const after = parts.slice(zeroRun.start + zeroRun.length);

        return before.join(':') + '::' + after.join(':');
    }

    return parts.join(':');
}

/**
 * Generate cryptographically secure random bytes.
 * Uses Web Crypto API (Node 15+) with fallback to crypto.randomFillSync (Node 14+).
 *
 * @param {number} length - Number of bytes to generate
 * @returns {Uint8Array} Random bytes
 */
export function randomBytes(length) {
    const bytes = new Uint8Array(length);

    // Feature detection: Use getRandomValues if available (Node 15+),
    // otherwise fall back to randomFillSync (Node 14+)
    if (crypto.getRandomValues) {
        crypto.getRandomValues(bytes);
    } else {
        // Node 14 compatibility: use randomFillSync instead
        crypto.randomFillSync(bytes);
    }

    return bytes;
}

/**
 * XOR two byte arrays of equal length.
 * 
 * @param {Uint8Array} a - First byte array
 * @param {Uint8Array} b - Second byte array
 * @returns {Uint8Array} XORed result
 * @throws {Error} If inputs are invalid or of different lengths
 */
export function xorBytes(a, b) {
    if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) {
        throw new Error('Inputs must be Uint8Arrays');
    }
    if (a.length !== b.length) {
        throw new Error('Byte arrays must have the same length');
    }
    return new Uint8Array(a.map((byte, i) => byte ^ b[i]));
}