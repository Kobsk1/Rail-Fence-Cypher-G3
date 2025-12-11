/**
 * Main UI logic for Rail Fence Cipher application
 */

/**
 * Shows output in a styled output container
 * @param {string} outputId - ID of the output element
 * @param {string} content - Content to display (text or HTML)
 * @param {boolean} isError - Whether this is an error message
 */
function showOutput(outputId, content, isError = false) {
    const output = document.getElementById(outputId);
    const contentEl = output.querySelector('.output-content');
    
    if (typeof content === 'string' && content.includes('<')) {
        // HTML content
        contentEl.innerHTML = content;
    } else {
        // Plain text content
        contentEl.textContent = content;
    }
    
    output.classList.add('show');
    
    if (isError) {
        contentEl.style.color = '#e53e3e';
    } else {
        contentEl.style.color = '#2d3748';
    }
}

/**
 * Hides an output container
 * @param {string} outputId - ID of the output element
 */
function hideOutput(outputId) {
    document.getElementById(outputId).classList.remove('show');
}

/**
 * Validates and parses rails input
 * @param {string} inputId - ID of the input element
 * @param {number} textLength - Length of the text message
 * @returns {number} Validated rails value
 * @throws {Error} If rails value is invalid
 */
function parseRails(inputId, textLength) {
    const value = Number(document.getElementById(inputId).value);
    if (!Number.isInteger(value) || value < 2 || value >= textLength) {
        throw new Error("Rails must be between 2 and message length - 1");
    }
    return value;
}

// Tab Switching
document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        const targetTab = tab.dataset.tab;
        
        // Remove active class from all tabs and contents
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        
        // Add active class to clicked tab and corresponding content
        tab.classList.add('active');
        document.getElementById(targetTab + '-tab').classList.add('active');
        
        // Hide all outputs when switching tabs
        hideOutput('encrypt-output');
        hideOutput('decrypt-output');
        hideOutput('bruteforce-output');
    });
});

// Encrypt Button Handler
document.getElementById("encrypt-btn").addEventListener("click", () => {
    const text = document.getElementById("encrypt-input").value;
    
    if (!text.trim()) {
        showOutput("encrypt-output", "Please enter a message to encrypt", true);
        return;
    }
    
    try {
        const rails = parseRails("encrypt-rails", Math.max(text.length, 3));
        const output = railFenceEncrypt(text, rails);
        showOutput("encrypt-output", output);
    } catch (err) {
        showOutput("encrypt-output", err.message, true);
    }
});

// Decrypt Button Handler
document.getElementById("decrypt-btn").addEventListener("click", () => {
    const text = document.getElementById("decrypt-input").value;
    
    if (!text.trim()) {
        showOutput("decrypt-output", "Please enter ciphertext to decrypt", true);
        return;
    }
    
    try {
        const rails = parseRails("decrypt-rails", Math.max(text.length, 3));
        const output = railFenceDecrypt(text, rails);
        showOutput("decrypt-output", output);
    } catch (err) {
        showOutput("decrypt-output", err.message, true);
    }
});

// Brute Force Button Handler
document.getElementById("bruteforce-btn").addEventListener("click", async () => {
    const text = document.getElementById("bruteforce-input").value;
    const output = document.getElementById("bruteforce-output");
    const contentEl = output.querySelector('.output-content');
    const btn = document.getElementById("bruteforce-btn");

    if (!text.trim()) {
        showOutput("bruteforce-output", "Please enter ciphertext to crack", true);
        return;
    }

    // Show loading state
    btn.disabled = true;
    output.classList.add('show');
    contentEl.innerHTML = '<div class="loading"><div class="spinner"></div>Analyzing all possible keys...</div>';

    const railsValue = document.getElementById("bruteforce-max-rails").value;
    const maxRails = railsValue ? Number(railsValue) : undefined;

    try {
        const { best, attempts } = await bruteForceCipher(text, maxRails);
        
        if (!best || attempts.length === 0) {
            showOutput("bruteforce-output", "No results found", true);
            return;
        }
        
        // Build HTML for results display
        let html = '<div class="output-label">Analysis Results</div>';
        
        // Show top 10 results
        const topResults = attempts.slice(0, 10);
        topResults.forEach((attempt, idx) => {
            const isBest = idx === 0;
            html += `
                <div class="brute-result ${isBest ? 'best' : ''}">
                    <div class="result-header">
                        <span class="${isBest ? 'best-badge' : 'rails-badge'}">
                            ${isBest ? '✓ Best Match' : `${attempt.rails} Rails`}
                        </span>
                        <span class="score">Score: ${attempt.score.toFixed(1)}</span>
                    </div>
                    <div class="result-text">${escapeHtml(attempt.plaintext)}</div>
                </div>
            `;
        });
        
        if (attempts.length > 10) {
            html += `<div style="text-align: center; color: #718096; font-size: 14px; margin-top: 12px;">
                Showing top 10 of ${attempts.length} results
            </div>`;
        }
        
        contentEl.innerHTML = html;
    } catch (err) {
        contentEl.innerHTML = `<div style="color: #e53e3e;">${escapeHtml(err.message || 'Analysis failed')}</div>`;
    } finally {
        btn.disabled = false;
    }
});

/**
 * Escapes HTML to prevent XSS
 * @param {string} text - Text to escape
 * @returns {string} Escaped HTML
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
