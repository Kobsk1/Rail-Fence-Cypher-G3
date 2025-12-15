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
        // Plain text content - preserve spacing
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
    if (!Number.isInteger(value) || value < 2) {
        throw new Error("Rails must be at least 2");
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
        hideOutput('encrypt-visual-output');
    });
});

// Encrypt Button Handler
document.getElementById("encrypt-btn").addEventListener("click", () => {
    const rawText = document.getElementById("encrypt-input").value;
    const text = rawText.toUpperCase(); // Keep uppercase like the working site
    
    if (!text.trim()) {
        showOutput("encrypt-output", "Please enter a message to encrypt", true);
        hideOutput("encrypt-visual-output");
        return;
    }
    
    try {
        const rails = parseRails("encrypt-rails", text.length);
        const ciphertext = railFenceEncrypt(text, rails);
        showOutput("encrypt-output", ciphertext);

        // Build and show visual rail pattern for this encryption
        const visualHtml = buildRailVisualization(text, rails);
        showOutput("encrypt-visual-output", visualHtml);
    } catch (err) {
        showOutput("encrypt-output", err.message, true);
        hideOutput("encrypt-visual-output");
    }
});

/**
 * Builds an HTML table showing the rail fence pattern for a given plaintext
 * @param {string} text - Plaintext message
 * @param {number} rails - Number of rails
 * @returns {string} HTML table
 */
function buildRailVisualization(text, rails) {
    if (rails <= 1) {
        return "<div style=\"color:#718096; font-size:14px;\">Rail pattern is trivial when rails ≤ 1.</div>";
    }

    // Create empty grid [rails][text.length]
    const grid = Array.from({ length: rails }, () =>
        Array.from({ length: text.length }, () => "")
    );

    let rail = 0;
    let direction = 1;
    for (let i = 0; i < text.length; i++) {
        grid[rail][i] = text[i];
        if (rail === 0) direction = 1;
        else if (rail === rails - 1) direction = -1;
        rail += direction;
    }

    // Build HTML table
    let html = '<table class="rail-visual"><thead><tr><th>Rail</th>';
    for (let i = 0; i < text.length; i++) {
        html += `<th>${i + 1}</th>`;
    }
    html += '</tr></thead><tbody>';

    for (let r = 0; r < rails; r++) {
        html += `<tr><th>${r + 1}</th>`;
        for (let c = 0; c < text.length; c++) {
            const ch = grid[r][c];
            if (ch === "") {
                html += '<td class="empty">·</td>';
            } else {
                const safe = escapeHtml(ch);
                html += `<td>${safe}</td>`;
            }
        }
        html += '</tr>';
    }
    html += '</tbody></table>';
    return html;
}

// Decrypt Button Handler
document.getElementById("decrypt-btn").addEventListener("click", () => {
    const rawText = document.getElementById("decrypt-input").value;
    const text = rawText.toUpperCase();
    
    if (!text.trim()) {
        showOutput("decrypt-output", "Please enter ciphertext to decrypt", true);
        return;
    }
    
    try {
        const rails = parseRails("decrypt-rails", text.length);
        const plaintext = railFenceDecrypt(text, rails);
        showOutput("decrypt-output", plaintext);
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
        const attempts = await bruteForceCipher(text, maxRails);
        
        if (!attempts || attempts.length === 0) {
            showOutput("bruteforce-output", "No results found", true);
            return;
        }
        
        // Build HTML for results display
        let html = '<div class="output-label">Analysis Results</div>';
        
        // Show all results in ascending rail order
        attempts.forEach((attempt) => {
            html += `
                <div class="brute-result">
                    <div class="result-header">
                        <span class="rails-badge">${attempt.rails} Rails</span>
                    </div>
                    <div class="result-text">${escapeHtml(attempt.plaintext)}</div>
                </div>
            `;
        });
        
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