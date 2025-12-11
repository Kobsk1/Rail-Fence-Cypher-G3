const DICTIONARY_API = "https://api.dictionaryapi.dev/api/v2/entries/en/";

const dictionaryCache = new Map();
const COMMON_WORD_WEIGHT = new Map([
    ["the", 6],
    ["and", 6],
    ["for", 5],
    ["are", 5],
    ["you", 5],
    ["this", 5],
    ["that", 5],
    ["with", 5],
    ["meet", 5],
    ["hello", 6],
    ["hi", 3],
    ["world", 5],
]);

async function checkWordWithDictionary(word) {
    if (!word || word.length < 3) return false;
    if (dictionaryCache.has(word)) return dictionaryCache.get(word);

    try {
        const res = await fetch(DICTIONARY_API + encodeURIComponent(word));
        const ok = res.ok;
        dictionaryCache.set(word, ok);
        return ok;
    } catch (err) {
        dictionaryCache.set(word, false);
        return false;
    }
}

function collectTokenWords(text) {
    return text
        .toLowerCase()
        .replace(/[^a-z\s]/g, " ")
        .split(/\s+/)
        .filter((w) => w.length >= 3);
}

function collectSubstrings(words, cap = 15) {
    const result = [];
    for (const word of words) {
        const maxLen = Math.min(8, word.length);
        for (let len = maxLen; len >= 3; len--) {
            for (let i = 0; i <= word.length - len; i++) {
                result.push(word.slice(i, i + len));
                if (result.length >= cap) return result;
            }
        }
    }
    return result;
}

async function scorePlaintextWithDictionary(text) {
    const tokens = collectTokenWords(text);
    const substrings = collectSubstrings(tokens, 15);

    let hits = 0;
    let weightedHits = 0;
    let checked = 0;

    // Check full tokens first for stronger signal
    for (const word of tokens) {
        if (checked >= 15) break;
        if (await checkWordWithDictionary(word)) {
            hits += 1;
            weightedHits += (COMMON_WORD_WEIGHT.get(word) || 1) * Math.max(word.length, 3);
        }
        checked += 1;
    }

    // If few or no hits, try substrings to capture joined words
    for (const word of substrings) {
        if (checked >= 15) break;
        if (await checkWordWithDictionary(word)) {
            hits += 1;
            weightedHits += (COMMON_WORD_WEIGHT.get(word) || 1) * Math.max(word.length, 3);
        }
        checked += 1;
    }

    const spacingScore = (text.match(/\s/g) || []).length * 0.2;
    const coverageScore = checked ? hits / checked : 0;
    const zeroPenalty = hits === 0 ? -10 : 0;

    return weightedHits + coverageScore * 5 + spacingScore + zeroPenalty;
}

async function bruteForceCipher(ciphertext, maxRails) {
    const limit = Math.min(
        Math.max(2, maxRails || ciphertext.length - 1),
        Math.max(ciphertext.length - 1, 2)
    );

    const attempts = [];
    let best = null;

    for (let rails = 2; rails <= limit; rails++) {
        const plaintext = railFenceDecrypt(ciphertext, rails);
        const score = await scorePlaintextWithDictionary(plaintext);
        const result = { rails, plaintext, score };
        attempts.push(result);
        if (!best || score > best.score) {
            best = result;
        }
    }

    // sort descending by score to show the most promising first
    attempts.sort((a, b) => b.score - a.score);

    return { best, attempts };
}
