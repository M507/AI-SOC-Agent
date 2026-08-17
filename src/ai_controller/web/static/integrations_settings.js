// Unified status and connectivity tests for configured integrations.

class IntegrationsSettingsManager {
    constructor(controller) {
        this.controller = controller;
        this.api = controller.api;
        this.integrations = [];
        this.results = new Map();
        this.bind();
    }

    bind() {
        const refresh = document.getElementById('integrations-refresh-btn');
        if (refresh) refresh.addEventListener('click', () => this.load());

        const grid = document.getElementById('integrations-grid');
        if (grid) {
            grid.addEventListener('click', (event) => {
                const button = event.target.closest('[data-integration-test]');
                if (button) this.test(button.dataset.integrationTest, button);
            });
        }
    }

    async load() {
        this.setPageState('loading', 'Checking configuration…');
        const data = await this.api.getIntegrations();
        if (!data || data.success === false) {
            this.integrations = [];
            this.render();
            this.setPageState('error', (data && (data.error || data.detail)) || 'Could not load integrations.');
            return;
        }
        this.integrations = data.integrations || [];
        this.render();
        this.updateSummary();
        this.setPageState('ready', '');
    }

    async test(id, button) {
        const integration = this.integrations.find((item) => item.id === id);
        if (!integration || !integration.configured) return;

        button.disabled = true;
        button.classList.add('is-loading');
        button.textContent = 'Testing…';
        this.results.set(id, { level: 'testing', message: 'Running connection test…' });
        this.renderResult(id);
        console.log(`[Integrations] Testing ${integration.name} (${id})`);

        const result = await this.api.testIntegration(id);
        const level = result.level || (result.ok || result.success ? 'success' : 'error');
        const message = result.message || result.error || result.detail || 'Connection test failed.';
        this.results.set(id, { level, message });
        console.log(`[Integrations] ${integration.name}: ${level} — ${message}`);

        button.disabled = false;
        button.classList.remove('is-loading');
        button.textContent = 'Test connection';
        this.renderResult(id);

        if (window.toast) {
            const toastFn = level === 'success' ? 'success' : (level === 'warning' ? 'info' : 'error');
            window.toast[toastFn](message, { key: `integration-${id}` });
        }
    }

    render() {
        const grid = document.getElementById('integrations-grid');
        if (!grid) return;
        grid.innerHTML = '';

        if (!this.integrations.length) {
            const empty = document.createElement('div');
            empty.className = 'integration-empty';
            empty.textContent = 'No integrations found.';
            grid.appendChild(empty);
            return;
        }

        this.integrations.forEach((integration) => {
            const card = document.createElement('article');
            card.className = 'integration-card';
            card.dataset.integrationId = integration.id;

            const header = document.createElement('div');
            header.className = 'integration-card-header';

            const identity = document.createElement('div');
            identity.className = 'integration-identity';
            const icon = document.createElement('span');
            icon.className = 'integration-icon';
            icon.setAttribute('aria-hidden', 'true');
            icon.textContent = this.iconFor(integration.category);
            const titles = document.createElement('div');
            const name = document.createElement('h3');
            name.textContent = integration.name;
            const category = document.createElement('p');
            category.className = 'integration-category';
            category.textContent = integration.category;
            titles.append(name, category);
            identity.append(icon, titles);

            const badge = document.createElement('span');
            badge.className = `integration-state ${integration.configured ? 'is-configured' : 'is-unconfigured'}`;
            badge.textContent = integration.configured ? 'Configured' : 'Not configured';
            header.append(identity, badge);

            const description = document.createElement('p');
            description.className = 'integration-description';
            description.textContent = integration.description;

            const detail = document.createElement('p');
            detail.className = 'integration-detail';
            detail.textContent = integration.detail;
            detail.title = integration.detail;

            const result = document.createElement('div');
            result.id = this.resultId(integration.id);
            result.className = 'integration-result';
            result.setAttribute('role', 'status');
            result.setAttribute('aria-live', 'polite');

            const actions = document.createElement('div');
            actions.className = 'integration-actions';
            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'btn btn-secondary btn-sm';
            button.dataset.integrationTest = integration.id;
            button.textContent = 'Test connection';
            button.disabled = !integration.configured || !integration.testable;
            if (button.disabled) {
                button.title = 'Complete this integration’s configuration before testing.';
            }
            actions.appendChild(button);

            card.append(header, description, detail, result, actions);
            grid.appendChild(card);
            this.renderResult(integration.id);
        });
    }

    renderResult(id) {
        const target = document.getElementById(this.resultId(id));
        if (!target) return;
        const result = this.results.get(id);
        if (!result) {
            target.className = 'integration-result';
            target.textContent = 'Not tested in this session';
            return;
        }
        target.className = `integration-result is-${result.level}`;
        target.textContent = result.message;
    }

    updateSummary() {
        const configured = this.integrations.filter((item) => item.configured).length;
        const total = this.integrations.length;
        const value = document.getElementById('integrations-summary-value');
        if (value) value.textContent = `${configured} of ${total} configured`;
    }

    setPageState(state, message) {
        const status = document.getElementById('integrations-page-status');
        if (!status) return;
        status.hidden = !message;
        status.className = `settings-status${state === 'error' ? ' is-error' : ''}`;
        status.textContent = message;
    }

    resultId(id) {
        return `integration-result-${String(id).replace(/[^a-zA-Z0-9_-]/g, '-')}`;
    }

    iconFor(category) {
        const icons = {
            'Case management': 'CM',
            'Elastic': 'EL',
            'SIEM': 'SI',
            'Endpoint security': 'ED',
            'Threat intelligence': 'TI',
            'Engineering': 'EN',
            'AI provider': 'AI',
            'Agent tools': 'MC',
        };
        return icons[category] || 'IN';
    }
}

window.IntegrationsSettingsManager = IntegrationsSettingsManager;
