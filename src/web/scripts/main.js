function showMessage(targetId, message) {
    const el = document.getElementById(targetId);
    el.textContent = message || "";
}

function parseRails(inputId, textLength) {
    const value = Number(document.getElementById(inputId).value);
    if (!Number.isInteger(value) || value < 2 || value >= textLength) {
        throw new Error("Rails must be a whole number between 2 and message length.");
    }
    return value;
}

document.getElementById("encrypt-btn").addEventListener("click", () => {
    const text = document.getElementById("encrypt-input").value;
    try {
        const rails = parseRails("encrypt-rails", Math.max(text.length, 3));
        const output = railFenceEncrypt(text, rails);
        showMessage("encrypt-output", output);
    } catch (err) {
        showMessage("encrypt-output", err.message);
    }
});

document.getElementById("decrypt-btn").addEventListener("click", () => {
    const text = document.getElementById("decrypt-input").value;
    try {
        const rails = parseRails("decrypt-rails", Math.max(text.length, 3));
        const output = railFenceDecrypt(text, rails);
        showMessage("decrypt-output", output);
    } catch (err) {
        showMessage("decrypt-output", err.message);
    }
});

document.getElementById("bruteforce-btn").addEventListener("click", async () => {
    const text = document.getElementById("bruteforce-input").value;
    const railsValue = document.getElementById("bruteforce-max-rails").value;
    const outputEl = document.getElementById("bruteforce-output");

    if (!text.trim()) {
        showMessage("bruteforce-output", "Please enter ciphertext to test.");
        return;
    }

    outputEl.textContent = "Running brute force, this may take a few seconds...";

    const maxRails = railsValue ? Number(railsValue) : undefined;

    try {
        const { best, attempts } = await bruteForceCipher(text, maxRails);
        if (!best) {
            showMessage("bruteforce-output", "No results.");
            return;
        }

        const lines = [];
        lines.push(`Best guess (rails ${best.rails}):`);
        lines.push(best.plaintext);
        lines.push("");
        lines.push("All attempts (sorted):");
        attempts.forEach((a) => {
            lines.push(`rails ${a.rails}: ${a.plaintext}`);
        });

        outputEl.textContent = lines.join("\n");
    } catch (err) {
        showMessage("bruteforce-output", err.message || "Brute force failed.");
    }
});
