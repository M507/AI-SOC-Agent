// WebSocket management for real-time session updates

class WebSocketManager {
    constructor(controller) {
        this.controller = controller;
        this.websockets = new Map();
        this.reconnectTimeouts = new Map();
    }

    /**
     * Connect WebSocket for a session.
     */
    connect(sessionId) {
        // Close existing WebSocket for this session if any
        if (this.websockets.has(sessionId)) {
            this.disconnect(sessionId);
        }

        // Clear any pending reconnect
        if (this.reconnectTimeouts.has(sessionId)) {
            clearTimeout(this.reconnectTimeouts.get(sessionId));
            this.reconnectTimeouts.delete(sessionId);
        }

        // Create new WebSocket connection
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/sessions/${sessionId}`;
        const ws = new WebSocket(wsUrl);

        ws.onopen = () => {
            console.log(`[WebSocket] Connected for session ${sessionId}`);
            // Send ping to keep connection alive
            this.startPing(sessionId);
        };

        ws.onmessage = (event) => {
            try {
                const message = JSON.parse(event.data);
                this.handleMessage(sessionId, message);
            } catch (error) {
                console.error('[WebSocket] Error parsing message:', error);
            }
        };

        ws.onerror = (error) => {
            console.error(`[WebSocket] Error for session ${sessionId}:`, error);
        };

        ws.onclose = () => {
            console.log(`[WebSocket] Closed for session ${sessionId}`);
            this.websockets.delete(sessionId);
            
            // Reconnect after a delay if session is still active
            if (this.controller.activeSessionId === sessionId) {
                const timeout = setTimeout(() => {
                    if (this.controller.activeSessionId === sessionId) {
                        console.log(`[WebSocket] Reconnecting for session ${sessionId}`);
                        this.connect(sessionId);
                    }
                }, 3000);
                this.reconnectTimeouts.set(sessionId, timeout);
            }
        };

        this.websockets.set(sessionId, ws);
    }

    /**
     * Start ping interval to keep connection alive.
     */
    startPing(sessionId) {
        const ws = this.websockets.get(sessionId);
        if (!ws || ws.readyState !== WebSocket.OPEN) {
            return;
        }

        const pingInterval = setInterval(() => {
            const ws = this.websockets.get(sessionId);
            if (ws && ws.readyState === WebSocket.OPEN) {
                try {
                    ws.send(JSON.stringify({ type: 'ping' }));
                } catch (error) {
                    console.error('[WebSocket] Error sending ping:', error);
                    clearInterval(pingInterval);
                }
            } else {
                clearInterval(pingInterval);
            }
        }, 30000); // Ping every 30 seconds

        // Store interval ID for cleanup
        ws._pingInterval = pingInterval;
    }

    /**
     * Handle incoming WebSocket messages.
     */
    handleMessage(sessionId, message) {
        switch (message.type) {
            case 'pong':
                // Pong response, do nothing
                break;
                
            case 'execution_started':
                // Command execution started - terminal will show pending state
                if (this.controller.terminal) {
                    this.controller.terminal.handleExecutionStarted(message);
                }
                break;
                
            case 'execution_completed': {
                // Command execution completed
                if (this.controller.terminal) {
                    this.controller.terminal.handleExecutionCompleted(message);
                }
                
                // Reload session to update status
                if (this.controller.loadSessionDetails) {
                    this.controller.loadSessionDetails(sessionId);
                }
                break;
            }
                
            case 'execution_failed': {
                // Command execution failed
                if (this.controller.terminal) {
                    this.controller.terminal.handleExecutionFailed(message);
                }
                
                // Reload session to update status
                if (this.controller.loadSessionDetails) {
                    this.controller.loadSessionDetails(sessionId);
                }
                break;
            }
                
            case 'execution_stopped': {
                // Execution was stopped by user
                if (this.controller.terminal) {
                    this.controller.terminal.handleExecutionStopped(message);
                }
                
                // Reload session to update status
                if (this.controller.loadSessionDetails) {
                    this.controller.loadSessionDetails(sessionId);
                }
                break;
            }
                
            default:
                console.log('[WebSocket] Unknown message type:', message.type);
        }
    }

    /**
     * Disconnect WebSocket for a session.
     */
    disconnect(sessionId) {
        if (this.websockets.has(sessionId)) {
            const ws = this.websockets.get(sessionId);
            
            // Clear ping interval
            if (ws._pingInterval) {
                clearInterval(ws._pingInterval);
            }
            
            ws.close();
            this.websockets.delete(sessionId);
        }
        
        // Clear reconnect timeout
        if (this.reconnectTimeouts.has(sessionId)) {
            clearTimeout(this.reconnectTimeouts.get(sessionId));
            this.reconnectTimeouts.delete(sessionId);
        }
    }

    /**
     * Close all WebSocket connections.
     */
    closeAll() {
        for (const [sessionId] of this.websockets.entries()) {
            this.disconnect(sessionId);
        }
    }
}
