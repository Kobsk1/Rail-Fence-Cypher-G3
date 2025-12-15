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

    // Build pattern of rail indices for each position (mirror Java implementation)
    const pattern = new Array(ciphertext.length);
    let rail = 0;
    let direction = 1;
    for (let i = 0; i < ciphertext.length; i++) {
        pattern[i] = rail;
        if (rail === 0) direction = 1;
        else if (rail === rails - 1) direction = -1;
        rail += direction;
    }

    // Count characters per rail
    const railCounts = new Array(rails).fill(0);
    for (const r of pattern) {
        railCounts[r]++;
    }

    // Slice ciphertext into rail buckets
    const buckets = new Array(rails);
    let idx = 0;
    for (let r = 0; r < rails; r++) {
        buckets[r] = ciphertext.slice(idx, idx + railCounts[r]).split("");
        idx += railCounts[r];
    }

    // Reconstruct plaintext following the pattern
    const bucketPos = new Array(rails).fill(0);
    let result = "";
    rail = 0;
    direction = 1;
    for (let i = 0; i < ciphertext.length; i++) {
        result += buckets[rail][bucketPos[rail]++];
        if (rail === 0) direction = 1;
        else if (rail === rails - 1) direction = -1;
        rail += direction;
    }

    return result;
}