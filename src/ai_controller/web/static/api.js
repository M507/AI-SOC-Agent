// API client for AI Controller backend

class APIClient {
    async _fetch(url, options = {}) {
        const response = await fetch(url, { credentials: 'same-origin', ...options });
        if (response.status === 401 && !String(url).includes('/api/auth/')) {
            window.location.href = '/login';
            throw new Error('Authentication required');
        }
        return response;
    }

    /**
     * Load UI configuration (e.g., debug mode).
     */
    async loadConfig() {
        try {
            const response = await this._fetch('/api/config');
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
            const response = await this._fetch('/api/config', {
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
            const response = await this._fetch(url);
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
            const response = await this._fetch(url);
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
            const response = await this._fetch(`/api/sessions/${sessionId}`);
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
    async createSession(name, sessionType = 'manual', clusterId = null) {
        try {
            const response = await this._fetch('/api/sessions', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    name,
                    session_type: sessionType,
                    cluster_id: clusterId || null,
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
            const response = await this._fetch(`/api/sessions/${sessionId}/execute`, {
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
            const response = await this._fetch(`/api/sessions/${sessionId}/stop`, {
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
            const response = await this._fetch(`/api/sessions/${sessionId}`, {
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
    async createAutorun(name, command, intervalSeconds, conditionFunction, clusterId = null) {
        try {
            const body = {
                name,
                command,
                interval_seconds: intervalSeconds
            };
            if (conditionFunction) {
                body.condition_function = conditionFunction;
            }
            if (clusterId) {
                body.cluster_id = clusterId;
            }
            const response = await this._fetch('/api/autoruns', {
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
            const response = await this._fetch(`/api/autoruns/${autorunId}`);
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
            const response = await this._fetch(`/api/autoruns/${autorunId}`, {
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
            const response = await this._fetch(`/api/autoruns/${autorunId}/clear`, {
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
            const response = await this._fetch(`/api/autoruns/${autorunId}`, {
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

    async request(url, options = {}) {
        const response = await this._fetch(url, options);
        if (!response.ok) {
            const errorText = await response.text();
            let message = `HTTP ${response.status}: ${errorText}`;
            try {
                const parsed = JSON.parse(errorText);
                if (parsed && parsed.detail) {
                    message = typeof parsed.detail === 'string'
                        ? parsed.detail
                        : JSON.stringify(parsed.detail);
                }
            } catch (_unused) {
                // Keep the raw status + body when the error is not JSON.
            }
            throw new Error(message);
        }
        return response.json();
    }

    async getLLMProviders() {
        try {
            return await this.request('/api/llm/providers');
        } catch (error) {
            console.error('Error loading LLM providers:', error);
            return { success: false, providers: [], error: error.message };
        }
    }

    async getLLMSettings() {
        try {
            return await this.request('/api/llm/settings');
        } catch (error) {
            console.error('Error loading LLM settings:', error);
            return { success: false, settings: {}, error: error.message };
        }
    }

    async saveLLMSettings(settings) {
        try {
            return await this.request('/api/llm/settings', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(settings),
            });
        } catch (error) {
            console.error('Error saving LLM settings:', error);
            return { success: false, error: error.message };
        }
    }

    async testLLMProvider(payload) {
        try {
            return await this.request('/api/llm/test', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload || {}),
            });
        } catch (error) {
            console.error('Error testing LLM provider:', error);
            return { success: false, ok: false, message: error.message };
        }
    }

    async listLLMModels(payload) {
        try {
            return await this.request('/api/llm/models', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload || {}),
            });
        } catch (error) {
            console.error('Error listing LLM models:', error);
            return { success: false, models: [], message: error.message };
        }
    }

    async testLLMModel(payload) {
        try {
            return await this.request('/api/llm/test-model', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload || {}),
            });
        } catch (error) {
            console.error('Error testing LLM model:', error);
            return { success: false, ok: false, message: error.message };
        }
    }

    async getMCPHealth() {
        try {
            return await this.request('/api/mcp/health');
        } catch (error) {
            return { success: false, running: false, status: 'unreachable', last_error: error.message };
        }
    }

    async getMCPSettings() {
        try {
            return await this.request('/api/mcp/settings');
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    async saveMCPSettings(settings) {
        try {
            return await this.request('/api/mcp/settings', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(settings),
            });
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    async mcpAction(action) {
        try {
            return await this.request(`/api/mcp/${action}`, { method: 'POST' });
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    async getElasticClusters() {
        try {
            return await this.request('/api/elastic/clusters');
        } catch (error) {
            return { success: false, clusters: [], error: error.message };
        }
    }

    async createElasticCluster(payload) {
        try {
            return await this.request('/api/elastic/clusters', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload || {}),
            });
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    async deleteElasticCluster(clusterId) {
        try {
            return await this.request(`/api/elastic/clusters/${encodeURIComponent(clusterId)}`, {
                method: 'DELETE',
            });
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    async setDefaultElasticCluster(clusterId) {
        try {
            return await this.request('/api/elastic/default', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ cluster_id: clusterId }),
            });
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    async testElasticCluster(payload) {
        try {
            return await this.request('/api/elastic/test', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload || {}),
            });
        } catch (error) {
            return { ok: false, success: false, error: error.message };
        }
    }

    async setDefaultSkillVector(skillVector) {
        try {
            return await this.request('/api/elastic/default-skills', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ skill_vector: skillVector }),
            });
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    async setClusterSkillVector(clusterId, skillVector) {
        try {
            return await this.request(`/api/elastic/clusters/${encodeURIComponent(clusterId)}/skills`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ skill_vector: skillVector }),
            });
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    async getIntegrations() {
        try {
            return await this.request('/api/integrations');
        } catch (error) {
            return { success: false, integrations: [], error: error.message };
        }
    }

    async testIntegration(integrationId) {
        try {
            return await this.request(`/api/integrations/${encodeURIComponent(integrationId)}/test`, {
                method: 'POST',
            });
        } catch (error) {
            return { success: false, ok: false, level: 'error', error: error.message, message: error.message };
        }
    }

    async getIntegrationSkills(integrationId) {
        try {
            return await this.request(`/api/integrations/${encodeURIComponent(integrationId)}/skills`);
        } catch (error) {
            return { success: false, skills: [], error: error.message };
        }
    }

    async testIntegrationSkills(integrationId, skills = null) {
        try {
            return await this.request(`/api/integrations/${encodeURIComponent(integrationId)}/skills/test`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ skills }),
            });
        } catch (error) {
            return { success: false, skills: [], error: error.message };
        }
    }
}
