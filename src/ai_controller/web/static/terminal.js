// Terminal rendering and display logic

class TerminalRenderer {
    constructor(controller) {
        this.controller = controller;
        this.pendingEntries = new Map(); // entry_id -> pending line element
    }

    /**
     * Resolve the actual scroll container for a given terminal element.
     *
     * - For normal sessions, the scroll container is the `.terminal` itself.
     * - For autoruns, CSS makes the parent `.autorun-terminal-container` the
     *   scrollable element and the inner `.terminal` just grows with content.
     */
    _getScrollContainer(terminal) {
        if (!terminal) return null;

        const parent = terminal.parentElement;
        if (parent && parent.classList && parent.classList.contains('autorun-terminal-container')) {
            // Autorun view: user scrolls the container, not the inner terminal.
            return parent;
        }

        // Default: scroll on the terminal itself.
        return terminal;
    }

    /**
     * Check if text contains markdown syntax and render it if so.
     * Returns a DOM element containing either rendered markdown or plain text.
     */
    _renderMarkdown(text) {
        if (!text || typeof text !== 'string') {
            return null;
        }

        // Check if text contains markdown patterns
        const markdownPatterns = [
            /^#{1,6}\s+/m,           // Headers
            /\*\*.*?\*\*/,            // Bold
            /\*.*?\*/,                // Italic
            /`[^`]+`/,                // Inline code
            /```[\s\S]*?```/,         // Code blocks
            /^\s*[-*+]\s+/m,          // Lists
            /^\s*\d+\.\s+/m,          // Numbered lists
            /\[.*?\]\(.*?\)/,         // Links
            /^>\s+/m,                 // Blockquotes
            /^\|.*\|$/m,              // Tables
        ];

        const hasMarkdown = markdownPatterns.some(pattern => pattern.test(text));

        if (!hasMarkdown) {
            // No markdown detected, return plain text in pre element
            const pre = document.createElement('pre');
            pre.textContent = text;
            return pre;
        }

        // Render markdown
        try {
            // Configure marked options for better security and styling
            if (typeof marked !== 'undefined') {
                marked.setOptions({
                    breaks: true,        // Convert line breaks to <br>
                    gfm: true,          // GitHub Flavored Markdown
                    sanitize: false,    // We'll sanitize manually if needed
                });

                const html = marked.parse(text);
                const container = document.createElement('div');
                container.className = 'markdown-content';
                container.innerHTML = html;
                return container;
            } else {
                // Fallback if marked is not loaded
                const pre = document.createElement('pre');
                pre.textContent = text;
                return pre;
            }
        } catch (e) {
            console.error('[Terminal] Error rendering markdown:', e);
            // Fallback to plain text on error
            const pre = document.createElement('pre');
            pre.textContent = text;
            return pre;
        }
    }

    /**
     * Determine if the user is currently scrolled to (or very near) the bottom
     * of the terminal. We only auto-scroll when this is true so that users can
     * scroll back and read older events without being snapped back down.
     */
    _isPinnedToBottom(terminal, threshold = 40) {
        const container = this._getScrollContainer(terminal);
        if (!container) return true;

        const distanceFromBottom = container.scrollHeight - container.scrollTop - container.clientHeight;
        return distanceFromBottom <= threshold;
    }

    /**
     * Scroll to the bottom only if the terminal was previously pinned there.
     */
    _scrollToBottomIfPinned(terminal, wasPinned) {
        if (!terminal || !wasPinned) return;

        const container = this._getScrollContainer(terminal);
        if (!container) return;

        container.scrollTop = container.scrollHeight;
    }

    /**
     * Force scroll to bottom for autorun terminals.
     * Uses multiple strategies to ensure scrolling happens even if layout is still settling.
     *
     * IMPORTANT: Callers should gate this on _isPinnedToBottom() so we don't
     * snap the user back to the bottom if they've manually scrolled up.
     */
    _forceScrollToBottom(terminal) {
        if (!terminal) return;

        const container = this._getScrollContainer(terminal);
        if (!container) return;
        
        const scrollToBottom = () => {
            // Try to scroll last child into view first (most reliable)
            const lastChild = terminal.lastElementChild || container.lastElementChild;
            if (lastChild) {
                lastChild.scrollIntoView({ behavior: 'auto', block: 'end' });
            }
            // Also set scrollTop directly as fallback
            container.scrollTop = container.scrollHeight;
        };
        
        // Immediate scroll attempt
        scrollToBottom();
        
        // Scroll after layout calculation (double RAF)
        window.requestAnimationFrame(() => {
            window.requestAnimationFrame(() => {
                scrollToBottom();
            });
        });
        
        // Additional scroll attempts after delays to catch any late layout changes
        setTimeout(() => {
            scrollToBottom();
        }, 50);
        
        setTimeout(() => {
            scrollToBottom();
        }, 200);
    }

    /**
     * Render all entries for a session in the terminal.
     * Optionally takes a specific container ID (defaults to the main 'terminal').
     */
    render(session, containerId = 'terminal') {
        const terminal = document.getElementById(containerId);
        if (!terminal) {
            console.error('[Terminal] Terminal element not found:', containerId);
            return;
        }
        const wasPinned = this._isPinnedToBottom(terminal);
        const isAutorunTerminal = containerId === 'autorun-terminal';

        terminal.innerHTML = '';
        this.pendingEntries.clear();
        
        if (!session || !session.entries || session.entries.length === 0) {
            terminal.innerHTML = '<div class="terminal-line output">No commands executed yet.</div>';
            return;
        }
        
        session.entries.forEach(entry => {
            this.addEntry(entry, containerId, /*autoScroll*/ false);
        });

        // Scroll to bottom (deferred to ensure layout is updated) but only if
        // the user was already at (or very near) the bottom. This matches the
        // behavior of tools like Android Studio Logcat or chat UIs: as soon as
        // the user scrolls up, we stop auto-scrolling.
        if (wasPinned) {
            if (isAutorunTerminal) {
                // Autorun terminals use the more robust scrolling strategy,
                // but *only* when the user was pinned to the bottom.
                this._forceScrollToBottom(terminal);
            } else {
                // Regular terminals: simple deferred scroll when pinned.
                window.requestAnimationFrame(() => {
                    this._scrollToBottomIfPinned(terminal, true);
                });
            }
        }
    }

    /**
     * Add a single terminal entry (command + result).
     */
    addEntry(entry, containerId = 'terminal', autoScroll = true) {
        const terminal = document.getElementById(containerId);
        if (!terminal) return;

        const wasPinned = autoScroll ? this._isPinnedToBottom(terminal) : false;
        
        const isDebug = this.controller.uiDebugMode === true;
        
        // Timestamp
        const timestampLine = document.createElement('div');
        timestampLine.className = 'terminal-line timestamp';
        const timestamp = new Date(entry.timestamp);
        timestampLine.textContent = `[${timestamp.toLocaleTimeString()}]`;
        terminal.appendChild(timestampLine);
        
        // Command
        const commandLine = document.createElement('div');
        commandLine.className = 'terminal-line command';
        commandLine.textContent = `> ${entry.command}`;
        terminal.appendChild(commandLine);
        
        // Result
        if (entry.result) {
            const resultLine = document.createElement('div');
            const isError = entry.status === 'failed' || entry.status === 'stopped';
            resultLine.className = `terminal-line ${isError ? 'error' : 'output'}`;

            const text = isDebug
                ? formatDebugResult(entry.result)
                : extractResultText(entry.result);

            // If text is null (empty stdout/stderr) and debug is not enabled, show generic error
            if (text === null && !isDebug) {
                const pre = document.createElement('pre');
                pre.textContent = 'An error occurred (no output received)';
                resultLine.className = 'terminal-line error';
                resultLine.appendChild(pre);
            } else if (text) {
                // Render markdown if available, otherwise use plain text
                const content = this._renderMarkdown(text);
                if (content) {
                    resultLine.appendChild(content);
                } else {
                    const pre = document.createElement('pre');
                    pre.textContent = text;
                    resultLine.appendChild(pre);
                }
            } else {
                const pre = document.createElement('pre');
                pre.textContent = isError ? 'Error (no details returned)' : 'Command completed';
                resultLine.appendChild(pre);
            }
            
            terminal.appendChild(resultLine);
        } else if (entry.status === 'pending' || entry.status === 'running') {
            const pendingLine = document.createElement('div');
            pendingLine.className = 'terminal-line output';
            pendingLine.textContent = 'Executing...';
            pendingLine.dataset.entryId = entry.id;
            terminal.appendChild(pendingLine);
            this.pendingEntries.set(entry.id, pendingLine);
        }
        
        // Scroll to bottom (deferred to ensure layout is updated) but only if
        // the user was already at the bottom.
        if (autoScroll) {
            window.requestAnimationFrame(() => {
                this._scrollToBottomIfPinned(terminal, wasPinned);
            });
        }
    }

    /**
     * Add a command line to the terminal (before execution).
     */
    addCommand(command) {
        const terminal = document.getElementById('terminal');
        if (!terminal) return null;

        const wasPinned = this._isPinnedToBottom(terminal);
        
        const commandLine = document.createElement('div');
        commandLine.className = 'terminal-line command';
        commandLine.textContent = `> ${command}`;
        terminal.appendChild(commandLine);
        
        const pendingLine = document.createElement('div');
        pendingLine.className = 'terminal-line output';
        pendingLine.textContent = 'Executing...';
        pendingLine.id = `pending-${Date.now()}`;
        terminal.appendChild(pendingLine);
        
        this._scrollToBottomIfPinned(terminal, wasPinned);
        
        return pendingLine.id;
    }

    /**
     * Handle execution started message from WebSocket.
     */
    handleExecutionStarted(message) {
        // The command was already added by addCommand, so we just need to track it
        if (message.entry_id) {
            const terminal = document.getElementById('terminal');
            if (terminal) {
                const pendingLine = terminal.querySelector(`[data-entry-id="${message.entry_id}"]`) ||
                                   terminal.querySelector('.terminal-line.output:last-child');
                if (pendingLine && pendingLine.textContent === 'Executing...') {
                    this.pendingEntries.set(message.entry_id, pendingLine);
                }
            }
        }
    }

    /**
     * Handle execution completed message from WebSocket.
     */
    handleExecutionCompleted(message) {
        const terminal = document.getElementById('terminal');
        if (!terminal) return;

        const wasPinned = this._isPinnedToBottom(terminal);
        
        // Remove pending line
        const pendingLine = this.pendingEntries.get(message.entry_id);
        if (pendingLine && pendingLine.parentNode) {
            pendingLine.remove();
            this.pendingEntries.delete(message.entry_id);
        } else {
            // Fallback: remove last "Executing..." line
            const pendingLines = terminal.querySelectorAll('.terminal-line.output');
            for (let i = pendingLines.length - 1; i >= 0; i--) {
                if (pendingLines[i].textContent === 'Executing...') {
                    pendingLines[i].remove();
                    break;
                }
            }
        }
        
        // Show result
        if (message.result) {
            const resultLine = document.createElement('div');
            const isError = message.result.success === false;
            resultLine.className = `terminal-line ${isError ? 'error' : 'output'}`;

            const useDebug = this.controller.uiDebugMode === true;
            const text = useDebug
                ? formatDebugResult(message.result)
                : extractResultText(message.result);
            
            // If text is null (empty stdout/stderr) and debug is not enabled, show generic error
            if (text === null && !useDebug) {
                const pre = document.createElement('pre');
                pre.textContent = 'An error occurred (no output received)';
                resultLine.className = 'terminal-line error';
                resultLine.appendChild(pre);
            } else if (text) {
                // Render markdown if available, otherwise use plain text
                const content = this._renderMarkdown(text);
                if (content) {
                    resultLine.appendChild(content);
                } else {
                    const pre = document.createElement('pre');
                    pre.textContent = text;
                    resultLine.appendChild(pre);
                }
            } else {
                const pre = document.createElement('pre');
                pre.textContent = isError ? 'Error (no details returned)' : 'Command completed';
                resultLine.appendChild(pre);
            }
            
            terminal.appendChild(resultLine);
        }
        
        this._scrollToBottomIfPinned(terminal, wasPinned);
    }

    /**
     * Handle execution failed message from WebSocket.
     */
    handleExecutionFailed(message) {
        const terminal = document.getElementById('terminal');
        if (!terminal) return;

        const wasPinned = this._isPinnedToBottom(terminal);
        
        // Remove pending line
        const pendingLine = this.pendingEntries.get(message.entry_id);
        if (pendingLine && pendingLine.parentNode) {
            pendingLine.remove();
            this.pendingEntries.delete(message.entry_id);
        } else {
            // Fallback: remove last "Executing..." line
            const pendingLines = terminal.querySelectorAll('.terminal-line.output');
            for (let i = pendingLines.length - 1; i >= 0; i--) {
                if (pendingLines[i].textContent === 'Executing...') {
                    pendingLines[i].remove();
                    break;
                }
            }
        }
        
        // Show error
        const errorLine = document.createElement('div');
        errorLine.className = 'terminal-line error';
        errorLine.textContent = `Error: ${message.error || 'Unknown error'}`;
        terminal.appendChild(errorLine);
        
        this._scrollToBottomIfPinned(terminal, wasPinned);
    }

    /**
     * Handle execution stopped message from WebSocket.
     */
    handleExecutionStopped(message) {
        const terminal = document.getElementById('terminal');
        if (!terminal) return;

        const wasPinned = this._isPinnedToBottom(terminal);
        
        // Remove pending line
        const pendingLine = this.pendingEntries.get(message.entry_id);
        if (pendingLine && pendingLine.parentNode) {
            pendingLine.remove();
            this.pendingEntries.delete(message.entry_id);
        }
        
        // Show stopped message
        const stoppedLine = document.createElement('div');
        stoppedLine.className = 'terminal-line error';
        stoppedLine.textContent = 'Execution stopped by user';
        terminal.appendChild(stoppedLine);
        
        this._scrollToBottomIfPinned(terminal, wasPinned);
    }

    /**
     * Remove pending line and show error.
     */
    showError(pendingLineId, errorMessage) {
        const terminal = document.getElementById('terminal');
        if (!terminal) return;

        const wasPinned = this._isPinnedToBottom(terminal);
        
        const pending = document.getElementById(pendingLineId);
        if (pending && pending.parentNode) {
            pending.remove();
        }
        
        const errorLine = document.createElement('div');
        errorLine.className = 'terminal-line error';
        errorLine.textContent = `Error: ${errorMessage}`;
        terminal.appendChild(errorLine);
        this._scrollToBottomIfPinned(terminal, wasPinned);
    }
}
