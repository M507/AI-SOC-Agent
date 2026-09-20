// Unified status and connectivity tests for configured integrations.

class IntegrationsSettingsManager {
    constructor(controller) {
        this.controller = controller;
        this.api = controller.api;
        this.integrations = [];
        this.results = new Map();
        this.skillResults = new Map();
        this.skillInventories = new Map();
        this.bind();
    }

    bind() {
        const refresh = document.getElementById('integrations-refresh-btn');
        if (refresh) refresh.addEventListener('click', () => this.load());

        const grid = document.getElementById('integrations-grid');
        if (grid) {
            grid.addEventListener('click', (event) => {
                const connection = event.target.closest('[data-integration-test]');
                const suite = event.target.closest('[data-integration-skills-test]');
                const toggle = event.target.closest('[data-integration-skills-toggle]');
                const single = event.target.closest('[data-skill-test]');
                if (connection) this.test(connection.dataset.integrationTest, connection);
                if (suite) this.testSkills(suite.dataset.integrationSkillsTest, suite);
                if (toggle) this.toggleSkills(toggle.dataset.integrationSkillsToggle, toggle);
                if (single) this.testSkills(single.dataset.integrationId, single, [single.dataset.skillTest]);
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

    async toggleSkills(id, button) {
        const panel = document.getElementById(this.skillPanelId(id));
        if (!panel) return;
        const opening = panel.hidden;
        panel.hidden = !opening;
        button.setAttribute('aria-expanded', String(opening));
        button.textContent = opening ? 'Hide skills' : `Skills (${this.skillCount(id)})`;
        if (opening && !this.skillInventories.has(id)) {
            panel.innerHTML = '<p class="integration-skills-loading">Loading safe-test policy…</p>';
            const data = await this.api.getIntegrationSkills(id);
            if (data && data.success !== false) {
                this.skillInventories.set(id, data.skills || []);
            } else {
                panel.innerHTML = `<p class="integration-skill-error">${this.escapeText((data && (data.error || data.detail)) || 'Could not load skills.')}</p>`;
                return;
            }
        }
        if (opening) this.renderSkillPanel(id);
    }

    async testSkills(id, button, selected = null) {
        const integration = this.integrations.find((item) => item.id === id);
        if (!integration || !integration.configured || !integration.has_skill_tests) return;

        const panel = document.getElementById(this.skillPanelId(id));
        if (panel) panel.hidden = false;
        const toggle = Array.from(document.querySelectorAll('[data-integration-skills-toggle]'))
            .find((item) => item.dataset.integrationSkillsToggle === id);
        if (toggle) {
            toggle.setAttribute('aria-expanded', 'true');
            toggle.textContent = 'Hide skills';
        }

        button.disabled = true;
        const originalText = button.textContent;
        button.textContent = selected ? 'Testing…' : 'Testing skills…';
        button.classList.add('is-loading');
        console.log(`[Integrations] Testing ${selected ? selected[0] : 'all safe skills'} for ${id}`);

        if (!this.skillInventories.has(id)) {
            const inventory = await this.api.getIntegrationSkills(id);
            if (inventory && inventory.success !== false) {
                this.skillInventories.set(id, inventory.skills || []);
            }
        }
        if (!selected) {
            const pending = (this.skillInventories.get(id) || []).map((skill) => ({
                ...skill,
                status: skill.skip_reason ? 'skipped' : 'testing',
                message: skill.skip_reason || 'Waiting to run…',
            }));
            this.skillResults.set(id, pending);
            this.renderSkillPanel(id);
        }

        const data = await this.api.testIntegrationSkills(id, selected);
        if (data && Array.isArray(data.skills) && data.skills.length) {
            const existing = this.skillResults.get(id) || this.skillInventories.get(id) || [];
            const merged = new Map(existing.map((item) => [item.id, item]));
            data.skills.forEach((item) => merged.set(item.id, item));
            this.skillResults.set(id, Array.from(merged.values()));
            const counts = selected
                ? (data.counts || this.countSkillStatuses(data.skills))
                : this.countSkillStatuses(Array.from(merged.values()));
            const message = `${counts.passed || 0} passed · ${counts.failed || 0} failed · ${counts.skipped || 0} skipped`;
            this.results.set(id, {
                level: (counts.failed || 0) > 0 ? 'error' : 'success',
                message: `Skill tests: ${message}`,
            });
            if (window.toast) {
                const method = (counts.failed || 0) > 0 ? 'error' : 'success';
                window.toast[method](`${integration.name}: ${message}`, { key: `integration-skills-${id}` });
            }
        } else {
            const message = (data && (data.error || data.detail)) || 'Could not run skill tests.';
            this.results.set(id, { level: 'error', message });
            if (window.toast) window.toast.error(message, { key: `integration-skills-${id}` });
        }

        button.disabled = false;
        button.textContent = originalText;
        button.classList.remove('is-loading');
        this.renderResult(id);
        this.renderSkillPanel(id);
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

            if (integration.has_skill_tests) {
                const toggleSkills = document.createElement('button');
                toggleSkills.type = 'button';
                toggleSkills.className = 'btn btn-secondary btn-sm';
                toggleSkills.dataset.integrationSkillsToggle = integration.id;
                toggleSkills.textContent = `Skills (${integration.skill_count || 0})`;
                toggleSkills.setAttribute('aria-expanded', 'false');
                toggleSkills.setAttribute('aria-controls', this.skillPanelId(integration.id));
                toggleSkills.disabled = !integration.configured;

                const testSkills = document.createElement('button');
                testSkills.type = 'button';
                testSkills.className = 'btn btn-primary btn-sm';
                testSkills.dataset.integrationSkillsTest = integration.id;
                testSkills.textContent = 'Test safe skills';
                testSkills.disabled = !integration.configured;
                testSkills.title = 'Runs dummy calls, skips critical actions, and deletes temporary resources.';
                actions.append(toggleSkills, testSkills);
            }

            const skillsPanel = document.createElement('section');
            skillsPanel.id = this.skillPanelId(integration.id);
            skillsPanel.className = 'integration-skills-panel';
            skillsPanel.hidden = true;
            skillsPanel.setAttribute('aria-label', `${integration.name} skill tests`);

            card.append(header, description, detail, result, actions, skillsPanel);
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

    renderSkillPanel(id) {
        const panel = document.getElementById(this.skillPanelId(id));
        if (!panel || panel.hidden) return;
        const skills = this.skillResults.get(id) || this.skillInventories.get(id) || [];
        panel.innerHTML = '';
        if (!skills.length) {
            panel.innerHTML = '<p class="integration-skills-loading">No skills are available for safe testing.</p>';
            return;
        }

        const header = document.createElement('div');
        header.className = 'integration-skills-header';
        const title = document.createElement('h4');
        title.textContent = 'Skill smoke tests';
        const note = document.createElement('p');
        note.textContent = 'Critical actions are skipped. Temporary records are always cleaned up.';
        header.append(title, note);
        panel.appendChild(header);

        const list = document.createElement('div');
        list.className = 'integration-skill-list';
        skills.forEach((skill) => {
            const row = document.createElement('div');
            row.className = `integration-skill-row is-${skill.status || (skill.skip_reason ? 'skipped' : 'untested')}`;

            const status = document.createElement('span');
            status.className = 'integration-skill-status';
            status.textContent = this.skillStatusLabel(skill);

            const copy = document.createElement('div');
            copy.className = 'integration-skill-copy';
            const name = document.createElement('strong');
            name.textContent = skill.label || skill.id;
            const message = document.createElement('span');
            message.textContent = skill.message || skill.skip_reason || 'Not tested';
            copy.append(name, message);
            if (skill.cleanup && skill.cleanup.attempted) {
                const cleanup = document.createElement('span');
                cleanup.className = `integration-cleanup ${skill.cleanup.ok ? 'is-ok' : 'is-error'}`;
                cleanup.textContent = skill.cleanup.message || (skill.cleanup.ok ? 'Temporary resource deleted.' : 'Cleanup failed.');
                copy.appendChild(cleanup);
            }

            const test = document.createElement('button');
            test.type = 'button';
            test.className = 'btn btn-secondary btn-sm integration-skill-test';
            test.dataset.integrationId = id;
            test.dataset.skillTest = skill.id;
            test.textContent = 'Test';
            test.disabled = Boolean(skill.skip_reason) || skill.status === 'testing';
            if (skill.skip_reason) test.title = skill.skip_reason;

            row.append(status, copy, test);
            list.appendChild(row);
        });
        panel.appendChild(list);
    }

    skillStatusLabel(skill) {
        const labels = {
            passed: 'Passed',
            failed: 'Failed',
            skipped: 'Skipped',
            testing: 'Testing',
            untested: 'Ready',
        };
        return labels[skill.status] || (skill.skip_reason ? 'Skipped' : 'Ready');
    }

    countSkillStatuses(skills) {
        return skills.reduce((counts, skill) => {
            const status = skill.status || 'skipped';
            counts[status] = (counts[status] || 0) + 1;
            return counts;
        }, { passed: 0, failed: 0, skipped: 0 });
    }

    skillCount(id) {
        const integration = this.integrations.find((item) => item.id === id);
        return integration ? (integration.skill_count || 0) : 0;
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

    skillPanelId(id) {
        return `integration-skills-${String(id).replace(/[^a-zA-Z0-9_-]/g, '-')}`;
    }

    escapeText(value) {
        const span = document.createElement('span');
        span.textContent = String(value || '');
        return span.innerHTML;
    }

    iconFor(category) {
        const icons = {
            'Case management': 'CM',
            'Elastic': 'EL',
            'SIEM': 'SI',
            'Endpoint security': 'ED',
            'Threat intelligence': 'TI',
            'Asset inventory': 'NB',
            'Engineering': 'EN',
            'AI provider': 'AI',
            'Agent tools': 'MC',
        };
        return icons[category] || 'IN';
    }
}

window.IntegrationsSettingsManager = IntegrationsSettingsManager;
