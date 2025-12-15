/**
 * Rail Fence Cipher Brute Force Attack
 * 
 * This simplified version no longer tries to guess the "best" plaintext.
 * It simply decrypts the ciphertext with every possible rail count and
 * returns the list of all results in ascending rail order.
 */

/**
 * Performs brute force attack on ciphertext
 * @param {string} ciphertext - Encrypted message
 * @param {number} maxRails - Maximum number of rails to try (optional)
 * @returns {Promise<Array<{rails: number, plaintext: string}>>} All attempts
 */
async function bruteForceCipher(ciphertext, maxRails) {
    const limit = Math.min(
        Math.max(2, maxRails || ciphertext.length - 1),
        Math.max(2, ciphertext.length - 1)
    );
    
    const attempts = [];
    
    // Try all possible rail counts from 2..limit
    for (let rails = 2; rails <= limit; rails++) {
        const plaintext = railFenceDecrypt(ciphertext, rails);
        attempts.push({ rails, plaintext });
    }
    
    // Already generated in ascending rail order
    return attempts;
}