// LLM settings and MCP health panel for SamiGPT

class SettingsManager {
    constructor(controller) {
        this.controller = controller;
        this.api = controller.api;
        this.providers = [];
        this.settings = {};
        this.modelCache = {};
        this.bind();
    }

    bind() {
        const providerSelect = document.getElementById('llm-provider');
        if (providerSelect) {
            providerSelect.addEventListener('change', () => this.renderProviderFields());
        }
        const saveBtn = document.getElementById('llm-save-btn');
        if (saveBtn) {
            saveBtn.addEventListener('click', () => this.save());
        }
        const testBtn = document.getElementById('llm-test-btn');
        if (testBtn) {
            testBtn.addEventListener('click', () => this.test());
        }
        const testModelBtn = document.getElementById('llm-test-model-btn');
        if (testModelBtn) {
            testModelBtn.addEventListener('click', () => this.testModel());
        }
        const fields = document.getElementById('llm-provider-fields');
        if (fields) {
            fields.addEventListener('click', (event) => {
                if (event.target.closest('[data-llm-refresh-models]')) {
                    this.refreshModels({ force: true });
                }
            });
            fields.addEventListener('change', (event) => {
                const key = event.target.getAttribute('data-llm-field');
                if (key === 'api_key' || key === 'base_url') {
                    delete this.modelCache[this.currentProvider()];
                }
            });
        }
    }

    async load() {
        const [providersResp, settingsResp] = await Promise.all([
            this.api.getLLMProviders(),
            this.api.getLLMSettings(),
        ]);
        this.providers = (providersResp && providersResp.providers) || [];
        this.settings = (settingsResp && settingsResp.settings) || { provider: 'cursor_agent' };
        this.renderProviderSelect();
        this.renderProviderFields();
        const prompt = document.getElementById('llm-system-prompt');
        if (prompt) prompt.value = this.settings.system_prompt || '';
        const iterations = document.getElementById('llm-max-iterations');
        if (iterations) iterations.value = this.settings.max_tool_iterations || 12;
    }

    renderProviderSelect() {
        const select = document.getElementById('llm-provider');
        if (!select) return;
        const current = this.settings.provider || 'cursor_agent';
        select.innerHTML = this.providers.map((p) => (
            `<option value="${this.escapeAttr(p.id)}" ${p.id === current ? 'selected' : ''}>${this.escapeHtml(p.name)}</option>`
        )).join('');
        if (!this.providers.length) {
            select.innerHTML = '<option value="cursor_agent">Cursor Agent</option>';
        }
    }

    currentProvider() {
        const select = document.getElementById('llm-provider');
        return (select && select.value) || this.settings.provider || 'cursor_agent';
    }

    currentSchema() {
        const id = this.currentProvider();
        const found = this.providers.find((p) => p.id === id);
        return (found && found.schema && found.schema.fields) || [];
    }

    hasModelField() {
        return this.currentSchema().some((field) => field.type === 'model');
    }

    renderProviderFields() {
        const container = document.getElementById('llm-provider-fields');
        if (!container) return;
        const providerId = this.currentProvider();
        const values = this.settings[providerId] || {};
        const fields = this.currentSchema();
        container.innerHTML = fields.map((field) => {
            const value = values[field.key] != null ? values[field.key] : '';
            if (field.type === 'model') {
                return `
                    <label for="llm-field-model">Model</label>
                    <div class="settings-inline-row">
                        <select
                            id="llm-field-model"
                            data-llm-field="model"
                            aria-label="Model"
                        >
                            <option value="" disabled selected>Loading models…</option>
                        </select>
                        <button
                            type="button"
                            class="btn btn-secondary"
                            data-llm-refresh-models
                            title="Reload the model list from this provider"
                        >Refresh</button>
                    </div>
                    <p class="settings-help">Choose a model from the provider catalog. Refresh after changing the API key or base URL.</p>
                `;
            }
            const inputType = field.type === 'password' ? 'password' : (field.type === 'number' ? 'number' : 'text');
            return `
                <label for="llm-field-${field.key}">${this.escapeHtml(field.label)}</label>
                <input
                    id="llm-field-${field.key}"
                    data-llm-field="${this.escapeAttr(field.key)}"
                    type="${inputType}"
                    value="${this.escapeAttr(value)}"
                    placeholder="${this.escapeAttr(field.placeholder || '')}"
                    autocomplete="off"
                >
            `;
        }).join('');

        const testModelBtn = document.getElementById('llm-test-model-btn');
        if (testModelBtn) {
            testModelBtn.style.display = this.hasModelField() ? '' : 'none';
        }

        if (this.hasModelField()) {
            const cached = this.modelCache[providerId];
            const selected = values.model || '';
            if (cached && cached.length) {
                this.fillModelSelect(cached, selected);
            } else {
                this.fillModelSelect(selected ? [{ id: selected, name: selected }] : [], selected);
                this.refreshModels({ quiet: true, force: true });
            }
        }
    }

    collectProviderSettings() {
        const settings = {};
        document.querySelectorAll('[data-llm-field]').forEach((input) => {
            settings[input.getAttribute('data-llm-field')] = input.value;
        });
        return settings;
    }

    collectPayload() {
        const provider = this.currentProvider();
        const payload = {
            provider,
            system_prompt: (document.getElementById('llm-system-prompt') || {}).value || '',
            max_tool_iterations: Number((document.getElementById('llm-max-iterations') || {}).value || 12),
        };
        payload[provider] = this.collectProviderSettings();
        return payload;
    }

    setStatus(message, isError) {
        const el = document.getElementById('llm-status');
        if (!el) return;
        el.textContent = message || '';
        el.classList.toggle('is-error', Boolean(isError));
    }

    setRefreshBusy(busy) {
        const btn = document.querySelector('[data-llm-refresh-models]');
        if (!btn) return;
        btn.disabled = Boolean(busy);
        btn.textContent = busy ? 'Refreshing…' : 'Refresh';
    }

    async save() {
        this.setStatus('Saving…');
        const data = await this.api.saveLLMSettings(this.collectPayload());
        if (data.success) {
            this.settings = data.settings || this.settings;
            this.setStatus('Saved.');
        } else {
            this.setStatus(data.error || 'Failed to save', true);
        }
    }

    async test() {
        this.setStatus('Testing provider…');
        const provider = this.currentProvider();
        const data = await this.api.testLLMProvider({
            provider,
            settings: this.collectProviderSettings(),
        });
        if (data.ok) {
            const models = (data.details && data.details.models) || [];
            if (models.length) {
                this.modelCache[provider] = this.normalizeModels(models);
                this.fillModelSelect(models, this.collectProviderSettings().model);
            }
            this.setStatus(data.message || 'Provider is reachable.');
        } else {
            this.setStatus(data.message || data.error || 'Provider check failed', true);
        }
    }

    async refreshModels({ quiet = false, force = true } = {}) {
        const provider = this.currentProvider();
        if (!force && this.modelCache[provider] && this.modelCache[provider].length) {
            this.fillModelSelect(this.modelCache[provider], this.collectProviderSettings().model);
            return;
        }
        this.setRefreshBusy(true);
        if (!quiet) {
            this.setStatus('Loading models from the provider…');
        }
        const current = this.collectProviderSettings().model;
        try {
            const data = await this.api.listLLMModels({
                provider,
                settings: this.collectProviderSettings(),
            });
            const models = (data && data.models) || [];
            if (!data.success) {
                this.fillModelSelect([], current);
                this.setStatus(data.message || data.error || 'Could not load models', true);
                return;
            }
            this.fillModelSelect(models, current);
            this.modelCache[provider] = this.normalizeModels(models);
            if (!models.length) {
                this.setStatus('No models returned. Check the base URL and API key.', true);
                return;
            }
            if (!quiet) {
                this.setStatus(`Loaded ${models.length} model${models.length === 1 ? '' : 's'}.`);
            }
        } finally {
            this.setRefreshBusy(false);
        }
    }

    normalizeModels(models) {
        const seen = new Set();
        const list = [];
        (models || []).forEach((item) => {
            let id = '';
            let name = '';
            if (typeof item === 'string') {
                id = item;
                name = item;
            } else if (item && typeof item === 'object') {
                id = String(item.id || item.name || '');
                name = String(item.name || item.id || '');
            }
            if (!id || seen.has(id)) return;
            seen.add(id);
            list.push({ id, name: name || id });
        });
        return list;
    }

    fillModelSelect(models, selected) {
        const select = document.getElementById('llm-field-model');
        if (!select || select.tagName !== 'SELECT') return;
        const list = this.normalizeModels(models);
        const selectedId = selected || '';
        if (selectedId && !list.some((model) => model.id === selectedId)) {
            list.unshift({ id: selectedId, name: selectedId });
        }
        if (!list.length) {
            select.innerHTML = '<option value="" disabled selected>No models loaded — click Refresh</option>';
            return;
        }
        const current = list.some((model) => model.id === selectedId) ? selectedId : list[0].id;
        select.innerHTML = list.map((model) => (
            `<option value="${this.escapeAttr(model.id)}" ${model.id === current ? 'selected' : ''}>${this.escapeHtml(model.name)}</option>`
        )).join('');
    }

    async testModel() {
        const settings = this.collectProviderSettings();
        if (!settings.model) {
            this.setStatus('Select a model first, or click Refresh to load the catalog.', true);
            return;
        }
        this.setStatus(`Testing ${settings.model}…`);
        const data = await this.api.testLLMModel({
            provider: this.currentProvider(),
            settings,
            model: settings.model,
        });
        if (data.ok) {
            this.setStatus(data.message || 'Model responded.');
        } else {
            this.setStatus(data.message || data.error || 'Model test failed', true);
        }
    }

    escapeAttr(value) {
        return String(value)
            .replace(/&/g, '&amp;')
            .replace(/"/g, '&quot;')
            .replace(/</g, '&lt;');
    }

    escapeHtml(value) {
        return String(value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;');
    }
}

class MCPPanel {
    constructor(controller) {
        this.controller = controller;
        this.api = controller.api;
        this.bind();
    }

    bind() {
        const map = {
            'mcp-refresh-btn': () => this.refresh(),
            'mcp-start-btn': () => this.action('start'),
            'mcp-stop-btn': () => this.action('stop'),
            'mcp-restart-btn': () => this.action('restart'),
            'mcp-save-btn': () => this.save(),
        };
        Object.keys(map).forEach((id) => {
            const el = document.getElementById(id);
            if (el) el.addEventListener('click', map[id]);
        });
    }

    async load() {
        const data = await this.api.getMCPSettings();
        if (data && data.settings) {
            this.fillForm(data.settings);
        }
        this.renderHealth(data && data.status ? data.status : await this.api.getMCPHealth());
    }

    fillForm(settings) {
        const enabled = document.getElementById('mcp-enabled');
        const autoStart = document.getElementById('mcp-auto-start');
        const host = document.getElementById('mcp-host');
        const port = document.getElementById('mcp-port');
        if (enabled) enabled.checked = settings.enabled !== false;
        if (autoStart) autoStart.checked = settings.auto_start !== false;
        if (host) host.value = settings.host || '127.0.0.1';
        if (port) port.value = settings.port || 8082;
    }

    collectSettings() {
        return {
            enabled: Boolean((document.getElementById('mcp-enabled') || {}).checked),
            auto_start: Boolean((document.getElementById('mcp-auto-start') || {}).checked),
            host: (document.getElementById('mcp-host') || {}).value || '127.0.0.1',
            port: Number((document.getElementById('mcp-port') || {}).value || 8082),
        };
    }

    async save() {
        const data = await this.api.saveMCPSettings(this.collectSettings());
        if (data.success) {
            this.fillForm(data.settings || this.collectSettings());
            this.renderHealth(data.status || {});
        }
    }

    async refresh() {
        const data = await this.api.getMCPHealth();
        this.renderHealth(data);
        return data;
    }

    async action(name) {
        const data = await this.api.mcpAction(name);
        this.renderHealth(data);
    }

    renderHealth(status) {
        if (!status) return;
        const running = Boolean(status.running);
        const state = status.status || (running ? 'healthy' : 'stopped');
        this.controller.updateMCPHealthIndicator(state, running);

        const badge = document.getElementById('mcp-status-badge');
        if (badge) {
            badge.textContent = running ? 'Running' : 'Stopped';
            badge.className = `status-badge ${running ? 'completed' : 'stopped'}`;
        }
        this.setText('mcp-health-status', state);
        this.setText('mcp-health-bind', status.host && status.port ? `${status.host}:${status.port}` : '—');
        this.setText('mcp-health-tools', status.tools_count != null ? String(status.tools_count) : '—');
        this.setText('mcp-health-started', status.started_at || '—');

        const errorEl = document.getElementById('mcp-last-error');
        if (errorEl) {
            errorEl.textContent = status.last_error || '';
            errorEl.classList.toggle('is-error', Boolean(status.last_error));
        }

        const pills = document.getElementById('mcp-integrations');
        if (pills) {
            const integrations = status.integrations || {};
            pills.innerHTML = Object.keys(integrations).map((key) => {
                const ok = Boolean(integrations[key]);
                return `<span class="integration-pill ${ok ? 'is-on' : 'is-off'}">${key}${ok ? '' : ' off'}</span>`;
            }).join('');
        }

        const snippet = document.getElementById('mcp-http-snippet');
        if (snippet && status.endpoints) {
            snippet.textContent = [
                `Health: ${status.endpoints.health}`,
                `Tools:  ${status.endpoints.tools}`,
                `RPC:    ${status.endpoints.rpc}`,
            ].join('\n');
        }
    }

    setText(id, value) {
        const el = document.getElementById(id);
        if (el) el.textContent = value;
    }
}
