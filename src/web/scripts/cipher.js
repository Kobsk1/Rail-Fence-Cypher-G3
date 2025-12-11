function railFenceEncrypt(plaintext, rails) {
    if (rails <= 1 || rails >= plaintext.length) {
        return plaintext;
    }

    const fence = Array.from({ length: rails }, () => []);
    let rail = 0;
    let direction = 1;

    for (const ch of plaintext) {
        fence[rail].push(ch);
        if (rail === 0) direction = 1;
        else if (rail === rails - 1) direction = -1;
        rail += direction;
    }

    return fence.flat().join("");
}

function railFenceDecrypt(ciphertext, rails) {
    if (rails <= 1 || rails >= ciphertext.length) {
        return ciphertext;
    }

    // Track rail assignment for each character position
    const pattern = [];
    let rail = 0;
    let direction = 1;
    for (let i = 0; i < ciphertext.length; i++) {
        pattern.push(rail);
        if (rail === 0) direction = 1;
        else if (rail === rails - 1) direction = -1;
        rail += direction;
    }

    // Count how many chars belong to each rail
    const railCounts = Array(rails).fill(0);
    pattern.forEach((r) => railCounts[r]++);

    // Slice ciphertext into rail buckets
    const railsBuckets = [];
    let idx = 0;
    for (let r = 0; r < rails; r++) {
        railsBuckets[r] = ciphertext.slice(idx, idx + railCounts[r]).split("");
        idx += railCounts[r];
    }

    // Rebuild plaintext following the pattern
    const result = [];
    rail = 0;
    direction = 1;
    for (let i = 0; i < ciphertext.length; i++) {
        result.push(railsBuckets[rail].shift());
        if (rail === 0) direction = 1;
        else if (rail === rails - 1) direction = -1;
        rail += direction;
    }

    return result.join("");
}
