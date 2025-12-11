/**
 * Rail Fence Cipher Brute Force Attack
 * Uses local wordlist files for offline dictionary validation
 */

// Configuration: All wordlist files loaded for comprehensive dictionary coverage
const WORDLIST_URLS = [
    "assets/all_words.txt",
    "assets/words.txt",
    "assets/dwyl.txt",
    "assets/nouns.txt",
    "assets/verbs.txt",
    "assets/adjs.txt",
    "assets/advs.txt",
    "assets/adps.txt",
    "assets/conjs.txt",
    "assets/dets.txt",
    "assets/nums.txt",
    "assets/prons.txt",
    "assets/prts.txt"
];

// Common words get higher weight in scoring
const COMMON_WORD_WEIGHT = new Map([
    ["the", 6], ["and", 6], ["for", 5], ["are", 5], ["you", 5],
    ["this", 5], ["that", 5], ["with", 5], ["meet", 5], ["hello", 6],
    ["hi", 3], ["world", 5], ["is", 4], ["was", 4], ["have", 4]
]);

// Cache for loaded wordlists
let wordSetCache = null;
let wordSetPromise = null;

/**
 * Loads all wordlist files and combines them into a single Set
 * @returns {Promise<Set<string>>} Set of all words from all wordlists
 */
async function loadWordSets() {
    if (wordSetPromise) return wordSetPromise;
    
    wordSetPromise = (async () => {
        const combinedSet = new Set();
        
        for (const url of WORDLIST_URLS) {
            try {
                const response = await fetch(url);
                if (!response.ok) {
                    console.warn(`Failed to load wordlist: ${url}`);
                    continue;
                }
                
                const text = await response.text();
                const words = text
                    .split(/\r?\n/)
                    .map(w => w.trim().toLowerCase())
                    .filter(w => w.length >= 3);
                
                words.forEach(w => combinedSet.add(w));
            } catch (error) {
                console.warn(`Error loading wordlist ${url}:`, error);
            }
        }
        
        wordSetCache = combinedSet;
        console.log(`Loaded ${combinedSet.size} words from ${WORDLIST_URLS.length} wordlist(s)`);
        return combinedSet;
    })();
    
    return wordSetPromise;
}

/**
 * Checks if a word exists in the loaded wordlists
 * @param {string} word - Word to check (will be lowercased)
 * @returns {boolean} True if word exists in wordlists
 */
function isWordInDictionary(word) {
    if (!word || word.length < 3) return false;
    if (!wordSetCache) return false;
    return wordSetCache.has(word.toLowerCase());
}

/**
 * Extracts token words from text (space-separated)
 * @param {string} text - Input text
 * @returns {string[]} Array of words (length >= 3)
 */
function extractWords(text) {
    return text
        .toLowerCase()
        .replace(/[^a-z\s]/g, " ")
        .split(/\s+/)
        .filter(w => w.length >= 3);
}

/**
 * Extracts substrings from words to catch concatenated words
 * @param {string[]} words - Array of words
 * @param {number} maxCount - Maximum number of substrings to extract
 * @returns {string[]} Array of substrings (length 3-8)
 */
function extractSubstrings(words, maxCount = 15) {
    const substrings = [];
    
    for (const word of words) {
        const maxLen = Math.min(8, word.length);
        for (let len = maxLen; len >= 3; len--) {
            for (let i = 0; i <= word.length - len; i++) {
                substrings.push(word.slice(i, i + len));
                if (substrings.length >= maxCount) return substrings;
            }
        }
    }
    
    return substrings;
}

/**
 * Scores plaintext based on dictionary word matches
 * @param {string} text - Plaintext to score
 * @returns {Promise<number>} Score (higher = more likely correct)
 */
async function scorePlaintext(text) {
    if (!text || text.length === 0) return 0;
    
    // Ensure wordlists are loaded
    await loadWordSets();
    
    const words = extractWords(text);
    const substrings = extractSubstrings(words, 15);
    
    let totalHits = 0;
    let weightedScore = 0;
    let checked = 0;
    const maxChecks = 30;
    
    // Check full words first (stronger signal)
    for (const word of words) {
        if (checked >= maxChecks) break;
        
        if (isWordInDictionary(word)) {
            totalHits++;
            const weight = COMMON_WORD_WEIGHT.get(word) || 1;
            weightedScore += weight * Math.max(word.length, 3);
        }
        checked++;
    }
    
    // Check substrings to catch concatenated words
    for (const substr of substrings) {
        if (checked >= maxChecks) break;
        
        if (isWordInDictionary(substr)) {
            totalHits++;
            const weight = COMMON_WORD_WEIGHT.get(substr) || 1;
            weightedScore += weight * Math.max(substr.length, 3);
        }
        checked++;
    }
    
    // Calculate additional scoring factors
    const spacingCount = (text.match(/\s/g) || []).length;
    const coverageScore = checked > 0 ? (totalHits / checked) * 5 : 0;
    const spacingScore = spacingCount * 0.2;
    const zeroPenalty = totalHits === 0 ? -10 : 0;
    
    return weightedScore + coverageScore + spacingScore + zeroPenalty;
}

/**
 * Performs brute force attack on ciphertext
 * @param {string} ciphertext - Encrypted message
 * @param {number} maxRails - Maximum number of rails to try (optional)
 * @returns {Promise<{best: Object, attempts: Array}>} Results with best guess and all attempts
 */
async function bruteForceCipher(ciphertext, maxRails) {
    const limit = Math.min(
        Math.max(2, maxRails || ciphertext.length - 1),
        ciphertext.length - 1
    );
    
    const attempts = [];
    let best = null;
    
    // Try all possible rail counts
    for (let rails = 2; rails <= limit; rails++) {
        const plaintext = railFenceDecrypt(ciphertext, rails);
        const score = await scorePlaintext(plaintext);
        const result = { rails, plaintext, score };
        attempts.push(result);
        
        if (!best || score > best.score) {
            best = result;
        }
    }
    
    // Sort by score (descending)
    attempts.sort((a, b) => b.score - a.score);
    
    return { best, attempts };
}
