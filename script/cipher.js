function railFenceEncrypt(plaintext, rails, useNulls = false, nullChar = 'X') {
    if (rails <= 1) {
        return plaintext;
    }

    // Add nulls if needed (to make pattern symmetrical)
    let text = plaintext.toUpperCase();
    if (useNulls) {
        let q = 0;
        let d = 1;
        while (q < 1) {
            if (text.length <= d * rails - (d - 1)) {
                while (text.length < d * rails - (d - 1)) {
                    text += nullChar.toUpperCase();
                }
                q = 2;
            } else {
                d = d + 2;
            }
        }
    }

    // Build the rail pattern
    const fence = Array.from({ length: rails }, () => []);
    let rail = 0;
    let direction = 1;

    for (const ch of text) {
        fence[rail].push(ch);
        if (rail === 0) direction = 1;
        else if (rail === rails - 1) direction = -1;
        rail += direction;
    }

    // Join all rails together
    return fence.map(row => row.join('')).join('');
}

function railFenceDecrypt(ciphertext, rails) {
    if (rails <= 1 || rails >= ciphertext.length) {
        return ciphertext;
    }

    // Build pattern (same as encryption)
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

    // Split ciphertext into rails
    const buckets = new Array(rails);
    let idx = 0;
    for (let r = 0; r < rails; r++) {
        buckets[r] = ciphertext.slice(idx, idx + railCounts[r]).split('');
        idx += railCounts[r];
    }

    // Reconstruct plaintext
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