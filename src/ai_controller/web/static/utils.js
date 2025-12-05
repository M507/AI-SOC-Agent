// Utility functions for AI Controller

/**
 * Escape HTML to prevent XSS attacks.
 */
function escapeHtml(text) {
    if (text == null) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Format interval in seconds to human-readable string.
 */
function formatInterval(seconds) {
    if (seconds < 60) {
        return `${seconds}s`;
    } else if (seconds < 3600) {
        return `${Math.floor(seconds / 60)}m`;
    } else {
        return `${Math.floor(seconds / 3600)}h`;
    }
}

/**
 * Pretty-print the full result object for debug mode.
 */
function formatDebugResult(result) {
    try {
        return JSON.stringify(result, null, 2);
    } catch (e) {
        return String(result);
    }
}

/**
 * Normalize an ExecutionResult (from session entry or websocket) into a readable text string.
 * Supports both tool outputs and cursor-agent freeform prompts.
 * Returns null if stdout and stderr are both empty (to indicate an error condition).
 */
function extractResultText(result) {
    if (!result) {
        return '';
    }

    // Handle error case first
    if (result.error) {
        return `Error: ${result.error}`;
    }

    // Prefer explicit text field when present (cursor-agent freeform)
    if (result.output) {
        const out = result.output;

        // If output is a string, return it directly (unless empty)
        if (typeof out === 'string') {
            return out || null;
        }

        // ExecutionResult from backend uses { text, raw } for freeform prompts
        if (out.text !== undefined) {
            // Check if text is non-empty
            if (out.text) {
                return out.text;
            }
            // If text is empty, check if stdout/stderr are also empty
            if (out.raw && typeof out.raw === 'object') {
                const stdout = out.raw.stdout || '';
                const stderr = out.raw.stderr || '';
                // If both stdout and stderr are empty, return null to indicate error
                if (!stdout.trim() && !stderr.trim()) {
                    return null;
                }
            }
            // If text is empty but we don't have raw info, return null
            return null;
        }

        // Some tools may put text directly under raw.stdout or raw.text
        if (out.raw) {
            if (typeof out.raw === 'string') {
                return out.raw || null;
            }
            if (out.raw.stdout !== undefined) {
                const stdout = out.raw.stdout || '';
                const stderr = out.raw.stderr || '';
                // If both stdout and stderr are empty, return null to indicate error
                if (!stdout.trim() && !stderr.trim()) {
                    return null;
                }
                return stdout || stderr || null;
            }
            if (out.raw.text) {
                return out.raw.text;
            }
        }

        // If output is an object with a message or result field
        if (typeof out === 'object') {
            if (out.message) {
                return out.message;
            }
            if (out.result) {
                return typeof out.result === 'string' ? out.result : JSON.stringify(out.result, null, 2);
            }
            if (out.data) {
                return typeof out.data === 'string' ? out.data : JSON.stringify(out.data, null, 2);
            }
        }
    }

    // Fallback: stringify whole result object (excluding metadata)
    if (typeof result === 'object') {
        try {
            // Don't include internal fields in the output
            const { success, error, timestamp, ...outputData } = result;
            if (Object.keys(outputData).length > 0) {
                return JSON.stringify(outputData, null, 2);
            }
            return JSON.stringify(result, null, 2);
        } catch (e) {
            return String(result);
        }
    }

    return String(result);
}
