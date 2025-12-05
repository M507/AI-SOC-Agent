// API client for AI Controller backend

class APIClient {
    /**
     * Load UI configuration (e.g., debug mode).
     */
    async loadConfig() {
        try {
            const response = await fetch('/api/config');
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            const data = await response.json();
            return data;
        } catch (error) {
            console.warn('Failed to load UI config:', error);
            return { success: false, ui_debug: false };
        }
    }

    /**
     * Update UI configuration.
     */
    async updateConfig(config) {
        try {
            const response = await fetch('/api/config', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(config)
            });
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            const data = await response.json();
            return data;
        } catch (error) {
            console.error('Error updating config:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Load all sessions.
     */
    async loadSessions(sessionType = null) {
        try {
            let url = '/api/sessions';
            if (sessionType) {
                url += `?session_type=${sessionType}`;
            }
            const response = await fetch(url);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            const data = await response.json();
            return data;
        } catch (error) {
            console.error('Error loading sessions:', error);
            return { success: false, sessions: [] };
        }
    }

    /**
     * Load all autoruns.
     */
    async loadAutoruns(enabledOnly = false) {
        try {
            const url = `/api/autoruns?enabled_only=${enabledOnly}`;
            const response = await fetch(url);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            const data = await response.json();
            return data;
        } catch (error) {
            console.error('Error loading autoruns:', error);
            return { success: false, autoruns: [] };
        }
    }

    /**
     * Get session details by ID.
     */
    async getSession(sessionId) {
        try {
            const response = await fetch(`/api/sessions/${sessionId}`);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            const data = await response.json();
            return data;
        } catch (error) {
            console.error('Error loading session details:', error);
            return { success: false };
        }
    }

    /**
     * Create a new session.
     */
    async createSession(name, sessionType = 'manual') {
        try {
            const response = await fetch('/api/sessions', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    name,
                    session_type: sessionType
                })
            });
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`HTTP ${response.status}: ${errorText}`);
            }
            const data = await response.json();
            return data;
        } catch (error) {
            console.error('Error creating session:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Execute a command in a session.
     */
    async executeCommand(sessionId, command) {
        try {
            const response = await fetch(`/api/sessions/${sessionId}/execute`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ command })
            });
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`HTTP ${response.status}: ${errorText}`);
            }
            const data = await response.json();
            return data;
        } catch (error) {
            console.error('Error executing command:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Stop a running session.
     */
    async stopSession(sessionId) {
        try {
            const response = await fetch(`/api/sessions/${sessionId}/stop`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`HTTP ${response.status}: ${errorText}`);
            }
            const data = await response.json();
            return data;
        } catch (error) {
            console.error('Error stopping session:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Delete a session.
     */
    async deleteSession(sessionId) {
        try {
            const response = await fetch(`/api/sessions/${sessionId}`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`HTTP ${response.status}: ${errorText}`);
            }
            
            const data = await response.json();
            return data;
        } catch (error) {
            console.error('Error deleting session:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Create a new autorun.
     */
    async createAutorun(name, command, intervalSeconds, conditionFunction) {
        try {
            const body = {
                name,
                command,
                interval_seconds: intervalSeconds
            };
            if (conditionFunction) {
                body.condition_function = conditionFunction;
            }
            const response = await fetch('/api/autoruns', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(body)
            });
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`HTTP ${response.status}: ${errorText}`);
            }
            const data = await response.json();
            return data;
        } catch (error) {
            console.error('Error creating autorun:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Get an autorun by ID.
     */
    async getAutorun(autorunId) {
        try {
            const response = await fetch(`/api/autoruns/${autorunId}`);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            const data = await response.json();
            return data;
        } catch (error) {
            console.error('Error loading autorun:', error);
            return { success: false };
        }
    }

    /**
     * Update an autorun.
     */
    async updateAutorun(autorunId, updates) {
        try {
            const response = await fetch(`/api/autoruns/${autorunId}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(updates)
            });
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`HTTP ${response.status}: ${errorText}`);
            }
            const data = await response.json();
            return data;
        } catch (error) {
            console.error('Error updating autorun:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Clear all entries from an autorun's backing session.
     */
    async clearAutorunSession(autorunId) {
        try {
            const response = await fetch(`/api/autoruns/${autorunId}/clear`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`HTTP ${response.status}: ${errorText}`);
            }
            const data = await response.json();
            return data;
        } catch (error) {
            console.error('Error clearing autorun session:', error);
            return { success: false, error: error.message };
        }
    }

    /**
     * Delete an autorun.
     */
    async deleteAutorun(autorunId) {
        try {
            const response = await fetch(`/api/autoruns/${autorunId}`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`HTTP ${response.status}: ${errorText}`);
            }
            const data = await response.json();
            return data;
        } catch (error) {
            console.error('Error deleting autorun:', error);
            return { success: false, error: error.message };
        }
    }
}
