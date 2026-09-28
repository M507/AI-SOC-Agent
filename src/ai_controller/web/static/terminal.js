// Terminal rendering and display logic

class TerminalRenderer {
    constructor(controller) {
        this.controller = controller;
        this.pendingEntries = new Map(); // entry_id -> pending line element
    }

    _thinkingTrace(result) {
        const output = result && result.output;
        const trace = output && output.trace;
        return Array.isArray(trace) ? trace : [];
    }

    _renderThinking(trace, live = false) {
        const root = document.createElement('div');
        root.className = 'thinking-trace';
        const label = document.createElement('div');
        label.className = 'thinking-label';
        label.textContent = 'Thinking';
        root.appendChild(label);
        trace.forEach((step, index) => {
            const block = document.createElement('div');
            block.className = 'thinking-step';
            const active = live && index === trace.length - 1;
            if (!step || step.kind === 'think') {
                if (active && step && step.live) {
                    block.classList.add('is-live');
                }
                const prose = document.createElement('div');
                prose.className = 'thinking-prose';
                prose.textContent = (step && step.text) || '';
                block.appendChild(prose);
            } else if (step.kind === 'status') {
                block.classList.add('thinking-status');
                if (active) {
                    block.classList.add('is-live');
                }
                block.textContent = step.text || '';
            } else if (step.kind === 'tool') {
                const running = step.phase === 'running';
                if (running) {
                    block.classList.add('is-live');
                }
                const name = document.createElement('div');
                name.className = 'thinking-tool-name';
                const verb = document.createElement('span');
                verb.textContent = running ? 'Running' : 'Tool';
                name.appendChild(verb);
                let detail = ` ${step.name || 'unknown'}`;
                if (running) {
                    detail += '…';
                }
                if (step.elapsed) {
                    detail += ` · ${step.elapsed}s`;
                }
                name.appendChild(document.createTextNode(detail));
                block.appendChild(name);
                const args = document.createElement('pre');
                args.className = 'thinking-block';
                try {
                    args.textContent = JSON.stringify(step.arguments || {}, null, 2);
                } catch (_unused) {
                    args.textContent = String(step.arguments || '');
                }
                block.appendChild(args);
                if (step.result) {
                    const result = document.createElement('pre');
                    result.className = 'thinking-block';
                    result.textContent = String(step.result);
                    block.appendChild(result);
                }
            }
            root.appendChild(block);
        });
        return root;
    }

    _fillResult(resultLine, result, isError, isDebug, live = false) {
        const partial = live || !!(result && result.output && result.output.partial);
        const showThinking = this.controller.uiThinkingMode === true || partial;
        const trace = showThinking ? this._thinkingTrace(result) : [];
        if (trace.length) {
            resultLine.appendChild(this._renderThinking(trace, partial));
        }

        const text = isDebug && !partial
            ? formatDebugResult(result)
            : extractResultText(result);

        if (partial && !text) {
            const narrating = trace.some((step) => step && (
                step.kind === 'status' || step.phase === 'running' || step.live
            ));
            if (!narrating) {
                const note = document.createElement('div');
                note.className = 'thinking-live';
                note.textContent = trace.length ? 'Working…' : 'Executing...';
                resultLine.appendChild(note);
            }
            return;
        }

        if (text === null && !isDebug) {
            const pre = document.createElement('pre');
            pre.textContent = isError
                ? 'An error occurred (no output received)'
                : 'The model returned an empty reply.';
            if (isError) {
                resultLine.className = 'terminal-line error';
            }
            resultLine.appendChild(pre);
            this._appendUsage(resultLine, result, partial);
            return;
        }
        if (text) {
            const content = this._renderMarkdown(text);
            if (content) {
                resultLine.appendChild(content);
            } else {
                const pre = document.createElement('pre');
                pre.textContent = text;
                resultLine.appendChild(pre);
            }
            this._appendUsage(resultLine, result, partial);
            return;
        }
        if (trace.length) {
            this._appendUsage(resultLine, result, partial);
            return;
        }
        const pre = document.createElement('pre');
        pre.textContent = isError ? 'Error (no details returned)' : 'Command completed';
        resultLine.appendChild(pre);
        this._appendUsage(resultLine, result, false);
    }

    _appendUsage(resultLine, result, live) {
        if (live) {
            return;
        }
        const note = formatUsageFooter(result);
        if (!note) {
            return;
        }
        const line = document.createElement('div');
        line.className = 'usage-footer';
        line.textContent = note;
        resultLine.appendChild(line);
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
        const inProgress = entry.status === 'pending' || entry.status === 'running'
            || (entry.result && entry.result.output && entry.result.output.partial);
        if (entry.result && !inProgress) {
            const resultLine = document.createElement('div');
            const isError = entry.status === 'failed' || entry.status === 'stopped';
            resultLine.className = `terminal-line ${isError ? 'error' : 'output'}`;

            this._fillResult(resultLine, entry.result, isError, isDebug);
            
            terminal.appendChild(resultLine);
        } else if (inProgress) {
            const pendingLine = document.createElement('div');
            pendingLine.className = 'terminal-line output';
            pendingLine.dataset.entryId = entry.id;
            if (entry.result) {
                this._fillResult(pendingLine, entry.result, false, false, true);
            } else {
                pendingLine.textContent = 'Executing...';
            }
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
     * Replace the in-progress line with the trace gathered so far.
     */
    handleExecutionProgress(message) {
        if (!message || !message.entry_id) {
            return;
        }
        ['terminal', 'autorun-terminal'].forEach((containerId) => {
            const terminal = document.getElementById(containerId);
            if (!terminal) {
                return;
            }
            const wasPinned = this._isPinnedToBottom(terminal);
            let line = terminal.querySelector(`[data-entry-id="${message.entry_id}"]`);
            if (!line) {
                const pending = [...terminal.querySelectorAll('.terminal-line.output')].reverse()
                    .find((node) => node.textContent === 'Executing...');
                if (!pending) {
                    return;
                }
                line = pending;
                line.dataset.entryId = message.entry_id;
            }
            line.className = 'terminal-line output';
            line.textContent = '';
            this._fillResult(line, message.result, false, false, true);
            this.pendingEntries.set(message.entry_id, line);
            this._scrollToBottomIfPinned(terminal, wasPinned);
        });
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

            this._fillResult(resultLine, message.result, isError, this.controller.uiDebugMode === true);
            
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
