// Elastic cluster settings, MCP skill vectors, and session/autorun cluster pickers

class ElasticClustersManager {
    constructor(controller) {
        this.controller = controller;
        this.api = controller.api;
        this.clusters = [];
        this.defaultClusterId = null;
        this.defaultSkillVector = '';
        this.catalog = { solutions: [], groups: [], default_skill_vector: '', help: '' };
        this.editorTarget = null;
        this.editorState = null;
        this.syncingEditor = false;
        this.bind();
    }

    bind() {
        const addBtn = document.getElementById('elastic-add-btn');
        if (addBtn) {
            addBtn.addEventListener('click', () => this.addCluster());
        }
        const testBtn = document.getElementById('elastic-test-btn');
        if (testBtn) {
            testBtn.addEventListener('click', () => this.testForm());
        }
        const authSelect = document.getElementById('elastic-auth-type');
        if (authSelect) {
            authSelect.addEventListener('change', () => this.syncAuthFields());
        }
        const list = document.getElementById('elastic-clusters-list');
        if (list) {
            list.addEventListener('click', (event) => this.onListClick(event));
        }
        const editDefault = document.getElementById('elastic-edit-default-skills');
        if (editDefault) {
            editDefault.addEventListener('click', () => this.openSkillEditor({ mode: 'default' }));
        }
        const closeSkills = document.getElementById('close-skill-vector-modal');
        if (closeSkills) {
            closeSkills.addEventListener('click', () => this.closeSkillEditor());
        }
        const cancelSkills = document.getElementById('cancel-skill-vector-btn');
        if (cancelSkills) {
            cancelSkills.addEventListener('click', () => this.closeSkillEditor());
        }
        const saveSkills = document.getElementById('save-skill-vector-btn');
        if (saveSkills) {
            saveSkills.addEventListener('click', () => this.saveSkillEditor());
        }
        const resetSkills = document.getElementById('skill-vector-reset-btn');
        if (resetSkills) {
            resetSkills.addEventListener('click', () => this.resetSkillEditor());
        }
        const vectorInput = document.getElementById('skill-vector-string');
        if (vectorInput) {
            vectorInput.addEventListener('input', () => this.onVectorStringInput());
        }
        const groups = document.getElementById('skill-vector-groups');
        if (groups) {
            groups.addEventListener('change', (event) => this.onSkillToggle(event));
            groups.addEventListener('click', (event) => this.onSkillGroupClick(event));
        }
        this.syncAuthFields();
    }

    async load() {
        const data = await this.api.getElasticClusters();
        if (!data || data.success === false) {
            this.clusters = [];
            this.defaultClusterId = null;
            this.render();
            return data;
        }
        this.clusters = data.clusters || [];
        this.defaultClusterId = data.default_cluster_id || (this.clusters[0] && this.clusters[0].id) || null;
        this.defaultSkillVector = data.default_skill_vector || (data.skill_catalog && data.skill_catalog.default_skill_vector) || '';
        if (data.skill_catalog) {
            this.catalog = data.skill_catalog;
        }
        this.render();
        this.fillAllSelects();
        return data;
    }

    render() {
        const defaultInput = document.getElementById('elastic-default-skill-vector');
        if (defaultInput) {
            defaultInput.value = this.defaultSkillVector || '';
        }
        const list = document.getElementById('elastic-clusters-list');
        if (!list) return;
        if (!this.clusters.length) {
            list.innerHTML = '<p class="settings-help">No Elastic clusters yet. Add one below so sessions can bind to a SIEM.</p>';
            return;
        }
        list.innerHTML = this.clusters.map((cluster) => {
            const isDefault = cluster.id === this.defaultClusterId;
            const auth = cluster.auth_type === 'basic' ? 'Username / password' : 'API key';
            const summary = `${cluster.solutions_on || 0}/${cluster.solutions_total || 0} solutions` +
                (cluster.skill_overrides ? ` · ${cluster.skill_overrides} skill override${cluster.skill_overrides === 1 ? '' : 's'}` : '');
            return `
                <article class="cluster-card${isDefault ? ' is-default' : ''}" data-cluster-id="${this.escapeAttr(cluster.id)}">
                    <div class="cluster-card-head">
                        <h4>${this.escapeHtml(cluster.name)}</h4>
                        ${isDefault ? '<span class="cluster-pill">Default</span>' : ''}
                    </div>
                    <p class="cluster-url">${this.escapeHtml(cluster.base_url)}</p>
                    <p class="settings-help">${auth}${cluster.has_credentials ? '' : ' — missing credentials'}</p>
                    <p class="cluster-vector" title="${this.escapeAttr(cluster.skill_vector || '')}">${this.escapeHtml(summary)}</p>
                    <div class="cluster-card-actions">
                        <button type="button" class="btn btn-secondary btn-sm" data-elastic-skills="${this.escapeAttr(cluster.id)}">MCP skills</button>
                        <button type="button" class="btn btn-secondary btn-sm" data-elastic-test="${this.escapeAttr(cluster.id)}">Test</button>
                        ${isDefault ? '' : `<button type="button" class="btn btn-secondary btn-sm" data-elastic-default="${this.escapeAttr(cluster.id)}">Set default</button>`}
                        <button type="button" class="btn btn-danger btn-sm" data-elastic-delete="${this.escapeAttr(cluster.id)}">Delete</button>
                    </div>
                </article>
            `;
        }).join('');
    }

    fillAllSelects() {
        ['session-cluster-select', 'autorun-cluster-select'].forEach((id) => {
            this.fillSelect(document.getElementById(id));
        });
    }

    fillSelect(select, selectedId) {
        if (!select) return;
        const current = selectedId || select.value || this.defaultClusterId || '';
        if (!this.clusters.length) {
            select.innerHTML = '<option value="">No Elastic clusters configured</option>';
            select.disabled = true;
            return;
        }
        select.disabled = false;
        select.innerHTML = this.clusters.map((cluster) => {
            const suffix = cluster.id === this.defaultClusterId ? ' (default)' : '';
            const selected = cluster.id === current ? ' selected' : '';
            return `<option value="${this.escapeAttr(cluster.id)}"${selected}>${this.escapeHtml(cluster.name)}${suffix}</option>`;
        }).join('');
        if (current && !this.clusters.some((cluster) => cluster.id === current)) {
            select.value = this.defaultClusterId || this.clusters[0].id;
        }
    }

    selectedClusterId(selectId) {
        const select = document.getElementById(selectId);
        return (select && select.value) || this.defaultClusterId || null;
    }

    clusterName(clusterId) {
        const cluster = this.clusters.find((item) => item.id === clusterId);
        return cluster ? cluster.name : '';
    }

    collectForm() {
        const authType = (document.getElementById('elastic-auth-type') || {}).value || 'api_key';
        const payload = {
            name: ((document.getElementById('elastic-name') || {}).value || '').trim(),
            base_url: ((document.getElementById('elastic-url') || {}).value || '').trim(),
            timeout_seconds: Number((document.getElementById('elastic-timeout') || {}).value || 30),
            verify_ssl: Boolean((document.getElementById('elastic-verify-ssl') || {}).checked),
        };
        if (authType === 'basic') {
            payload.username = ((document.getElementById('elastic-username') || {}).value || '').trim();
            payload.password = ((document.getElementById('elastic-password') || {}).value || '').trim();
        } else {
            payload.api_key = ((document.getElementById('elastic-api-key') || {}).value || '').trim();
        }
        return payload;
    }

    syncAuthFields() {
        const authType = (document.getElementById('elastic-auth-type') || {}).value || 'api_key';
        const keyRow = document.getElementById('elastic-api-key-row');
        const basicRow = document.getElementById('elastic-basic-row');
        if (keyRow) keyRow.hidden = authType !== 'api_key';
        if (basicRow) basicRow.hidden = authType !== 'basic';
    }

    applyClusterPayload(data) {
        this.clusters = data.clusters || this.clusters;
        this.defaultClusterId = data.default_cluster_id || this.defaultClusterId;
        if (data.default_skill_vector) {
            this.defaultSkillVector = data.default_skill_vector;
        }
        this.render();
        this.fillAllSelects();
    }

    async addCluster() {
        const payload = this.collectForm();
        if (!payload.base_url) {
            if (window.toast) window.toast.info('Enter the Elastic URL.', { key: 'elastic' });
            return;
        }
        if (window.toast) window.toast.info('Saving cluster…', { key: 'elastic', duration: 0 });
        const data = await this.api.createElasticCluster(payload);
        if (data.success) {
            this.applyClusterPayload(data);
            this.clearForm();
            if (window.toast) window.toast.success('Elastic cluster saved. It inherited the default MCP skill vector.', { key: 'elastic' });
        } else if (window.toast) {
            window.toast.error(data.error || data.detail || 'Could not save cluster', { key: 'elastic' });
        }
    }

    async testForm() {
        const payload = this.collectForm();
        if (!payload.base_url) {
            if (window.toast) window.toast.info('Enter the Elastic URL.', { key: 'elastic' });
            return;
        }
        if (window.toast) window.toast.info('Testing cluster…', { key: 'elastic', duration: 0 });
        const data = await this.api.testElasticCluster(payload);
        this.showProbeResult(data);
    }

    async onListClick(event) {
        const skillsId = event.target.closest && event.target.closest('[data-elastic-skills]');
        const testId = event.target.closest && event.target.closest('[data-elastic-test]');
        const defaultId = event.target.closest && event.target.closest('[data-elastic-default]');
        const deleteId = event.target.closest && event.target.closest('[data-elastic-delete]');
        if (skillsId) {
            this.openSkillEditor({ mode: 'cluster', clusterId: skillsId.getAttribute('data-elastic-skills') });
            return;
        }
        if (testId) {
            const id = testId.getAttribute('data-elastic-test');
            if (window.toast) window.toast.info('Testing cluster…', { key: 'elastic', duration: 0 });
            const data = await this.api.testElasticCluster({ id, base_url: this.urlFor(id) });
            this.showProbeResult(data);
            return;
        }
        if (defaultId) {
            const id = defaultId.getAttribute('data-elastic-default');
            const data = await this.api.setDefaultElasticCluster(id);
            if (data.success) {
                this.applyClusterPayload(data);
                if (window.toast) window.toast.success('Default cluster updated.', { key: 'elastic' });
            }
            return;
        }
        if (deleteId) {
            const id = deleteId.getAttribute('data-elastic-delete');
            if (!confirm('Delete this Elastic cluster? Sessions that used it will fall back to the default.')) {
                return;
            }
            const data = await this.api.deleteElasticCluster(id);
            if (data.success) {
                this.applyClusterPayload(data);
                if (window.toast) window.toast.success('Cluster deleted.', { key: 'elastic' });
            }
        }
    }

    urlFor(clusterId) {
        const cluster = this.clusters.find((item) => item.id === clusterId);
        return cluster ? cluster.base_url : '';
    }

    showProbeResult(data) {
        if (!window.toast) return;
        if (data && data.ok) {
            window.toast.success(data.message || 'Cluster is reachable.', { key: 'elastic' });
        } else {
            window.toast.error((data && (data.message || data.error)) || 'Cluster check failed', { key: 'elastic' });
        }
    }

    clearForm() {
        ['elastic-name', 'elastic-url', 'elastic-api-key', 'elastic-username', 'elastic-password'].forEach((id) => {
            const el = document.getElementById(id);
            if (el) el.value = '';
        });
    }

    openSkillEditor(target) {
        const cluster = target.mode === 'cluster'
            ? this.clusters.find((item) => item.id === target.clusterId)
            : null;
        const vector = target.mode === 'default'
            ? (this.defaultSkillVector || this.catalog.default_skill_vector || '')
            : (cluster && cluster.skill_vector) || this.defaultSkillVector || '';
        this.editorTarget = target;
        const title = document.getElementById('skill-vector-title');
        const help = document.getElementById('skill-vector-help');
        if (title) {
            title.textContent = target.mode === 'default'
                ? 'Default MCP skills'
                : `MCP skills — ${cluster ? cluster.name : 'cluster'}`;
        }
        if (help) {
            help.textContent = this.catalog.help ||
                'MSV is a CVSS-style string. Solution metrics are Y or N. SK:skill=N disables one tool.';
        }
        const parsed = this.parseVector(vector);
        if (!parsed.ok) {
            this.editorState = this.parseVector(this.catalog.default_skill_vector || '').state;
        } else {
            this.editorState = parsed.state;
        }
        this.renderSkillEditor();
        const modal = document.getElementById('skill-vector-modal');
        if (modal) modal.style.display = 'flex';
    }

    closeSkillEditor() {
        const modal = document.getElementById('skill-vector-modal');
        if (modal) modal.style.display = 'none';
        this.editorTarget = null;
        this.editorState = null;
    }

    resetSkillEditor() {
        this.editorState = this.parseVector(this.catalog.default_skill_vector || 'MSV:1').state;
        (this.catalog.solutions || []).forEach((solution) => {
            this.editorState.solutions[solution.id] = true;
        });
        this.editorState.skills = {};
        this.renderSkillEditor();
    }

    onVectorStringInput() {
        if (this.syncingEditor) return;
        const input = document.getElementById('skill-vector-string');
        const parsed = this.parseVector(input && input.value);
        this.setVectorError(parsed.ok ? '' : parsed.error);
        if (parsed.ok) {
            this.editorState = parsed.state;
            this.renderSkillGroups();
        }
    }

    onSkillToggle(event) {
        const target = event.target;
        if (!target || !this.editorState) return;
        const solutionId = target.getAttribute('data-solution');
        const skillId = target.getAttribute('data-skill');
        if (solutionId) {
            this.editorState.solutions[solutionId] = Boolean(target.checked);
            this.stripRedundantOverrides();
            this.renderSkillEditor();
            return;
        }
        if (skillId) {
            const group = this.groupForSkill(skillId);
            const parentOn = this.parentsOn(group);
            if (Boolean(target.checked) === parentOn) {
                delete this.editorState.skills[skillId];
            } else {
                this.editorState.skills[skillId] = Boolean(target.checked);
            }
            this.renderSkillEditor();
        }
    }

    onSkillGroupClick(event) {
        const toggle = event.target.closest && event.target.closest('[data-skill-expand]');
        if (!toggle) return;
        const groupEl = toggle.closest('.skill-group');
        if (!groupEl) return;
        groupEl.classList.toggle('is-open');
    }

    groupForSkill(skillId) {
        return (this.catalog.groups || []).find((group) =>
            (group.skills || []).some((skill) => skill.id === skillId)
        );
    }

    parentsOn(group) {
        if (!group) return true;
        return (group.solutions || []).some((id) => this.editorState.solutions[id]);
    }

    stripRedundantOverrides() {
        (this.catalog.groups || []).forEach((group) => {
            const parentOn = this.parentsOn(group);
            (group.skills || []).forEach((skill) => {
                if (!(skill.id in this.editorState.skills)) return;
                if (Boolean(this.editorState.skills[skill.id]) === parentOn) {
                    delete this.editorState.skills[skill.id];
                }
            });
        });
    }

    renderSkillEditor() {
        this.syncingEditor = true;
        const input = document.getElementById('skill-vector-string');
        if (input) input.value = this.encodeVector(this.editorState);
        this.syncingEditor = false;
        this.setVectorError('');
        this.renderSkillGroups();
    }

    renderSkillGroups() {
        const root = document.getElementById('skill-vector-groups');
        if (!root || !this.editorState) return;
        root.innerHTML = (this.catalog.groups || []).map((group) => {
            const parentOn = this.parentsOn(group);
            const solutionToggles = (group.solutions || []).map((id) => {
                const label = ((this.catalog.solutions || []).find((item) => item.id === id) || {}).label || id;
                const checked = this.editorState.solutions[id] ? ' checked' : '';
                return `<label class="settings-toggle skill-solution-toggle">
                    <input type="checkbox" data-solution="${this.escapeAttr(id)}"${checked}>
                    <span class="toggle-label">${this.escapeHtml(label)}</span>
                </label>`;
            }).join('');
            const skills = (group.skills || []).map((skill) => {
                const allowed = (skill.id in this.editorState.skills)
                    ? Boolean(this.editorState.skills[skill.id])
                    : parentOn;
                const override = skill.id in this.editorState.skills
                    ? (this.editorState.skills[skill.id] ? ' override-on' : ' override-off')
                    : '';
                return `<label class="skill-row${override}">
                    <input type="checkbox" data-skill="${this.escapeAttr(skill.id)}"${allowed ? ' checked' : ''}>
                    <span>${this.escapeHtml(skill.label || skill.id)}</span>
                </label>`;
            }).join('');
            return `<section class="skill-group${parentOn ? '' : ' is-disabled'}">
                <header class="skill-group-head">
                    <div>
                        <h4>${this.escapeHtml(group.name)}</h4>
                        <p class="settings-help">${this.escapeHtml(group.help || '')}</p>
                    </div>
                    <button type="button" class="btn btn-secondary btn-sm" data-skill-expand>Skills</button>
                </header>
                <div class="skill-solution-row">${solutionToggles}</div>
                <div class="skill-list">${skills}</div>
            </section>`;
        }).join('');
    }

    parseVector(raw) {
        const solutions = {};
        (this.catalog.solutions || []).forEach((item) => {
            solutions[item.id] = true;
        });
        const skills = {};
        const text = String(raw || '').trim();
        if (!text) {
            return { ok: true, state: { solutions, skills } };
        }
        const parts = text.split('/').map((item) => item.trim()).filter(Boolean);
        if (!parts.length || !/^(MSV|MCP):/i.test(parts[0])) {
            return { ok: false, error: 'Skill vector must start with MSV:1' };
        }
        const knownSolutions = new Set((this.catalog.solutions || []).map((item) => item.id));
        const knownSkills = new Set();
        (this.catalog.groups || []).forEach((group) => {
            (group.skills || []).forEach((skill) => knownSkills.add(skill.id));
        });
        for (let i = 1; i < parts.length; i += 1) {
            const part = parts[i];
            if (/^SK:/i.test(part)) {
                const body = part.slice(3);
                const items = body.split(',');
                for (let j = 0; j < items.length; j += 1) {
                    const item = items[j].trim();
                    if (!item) continue;
                    const eq = item.indexOf('=');
                    if (eq < 0) return { ok: false, error: `Invalid skill override '${item}'` };
                    const name = item.slice(0, eq).trim();
                    const flag = item.slice(eq + 1).trim().toUpperCase();
                    if (!knownSkills.has(name)) return { ok: false, error: `Unknown skill '${name}'` };
                    if (flag !== 'Y' && flag !== 'N') return { ok: false, error: `Skill '${name}' must be Y or N` };
                    skills[name] = flag === 'Y';
                }
                continue;
            }
            const colon = part.indexOf(':');
            if (colon < 0) return { ok: false, error: `Invalid vector metric '${part}'` };
            const key = part.slice(0, colon).trim().toUpperCase();
            const value = part.slice(colon + 1).trim().toUpperCase();
            if (key === 'CASE') {
                if (value !== 'Y' && value !== 'N') return { ok: false, error: 'CASE must be Y or N' };
                solutions.IRIS = value === 'Y';
                solutions.TH = value === 'Y';
                continue;
            }
            if (!knownSolutions.has(key)) return { ok: false, error: `Unknown solution '${key}'` };
            if (value !== 'Y' && value !== 'N') return { ok: false, error: `${key} must be Y or N` };
            solutions[key] = value === 'Y';
        }
        return { ok: true, state: { solutions, skills } };
    }

    encodeVector(state) {
        const parts = ['MSV:1'];
        (this.catalog.solutions || []).forEach((item) => {
            parts.push(`${item.id}:${state.solutions[item.id] ? 'Y' : 'N'}`);
        });
        const overrides = [];
        (this.catalog.groups || []).forEach((group) => {
            const parentOn = (group.solutions || []).some((id) => state.solutions[id]);
            (group.skills || []).forEach((skill) => {
                if (!(skill.id in state.skills)) return;
                if (Boolean(state.skills[skill.id]) === parentOn) return;
                overrides.push(`${skill.id}=${state.skills[skill.id] ? 'Y' : 'N'}`);
            });
        });
        overrides.sort();
        if (overrides.length) {
            parts.push(`SK:${overrides.join(',')}`);
        }
        return parts.join('/');
    }

    setVectorError(message) {
        const el = document.getElementById('skill-vector-error');
        if (!el) return;
        if (message) {
            el.hidden = false;
            el.textContent = message;
        } else {
            el.hidden = true;
            el.textContent = '';
        }
    }

    async saveSkillEditor() {
        const input = document.getElementById('skill-vector-string');
        const parsed = this.parseVector(input && input.value);
        if (!parsed.ok) {
            this.setVectorError(parsed.error);
            if (window.toast) window.toast.error(parsed.error, { key: 'elastic' });
            return;
        }
        const vector = this.encodeVector(parsed.state);
        if (window.toast) window.toast.info('Saving skill vector…', { key: 'elastic', duration: 0 });
        let data;
        if (this.editorTarget && this.editorTarget.mode === 'default') {
            data = await this.api.setDefaultSkillVector(vector);
        } else {
            data = await this.api.setClusterSkillVector(this.editorTarget.clusterId, vector);
        }
        const savingDefault = Boolean(this.editorTarget && this.editorTarget.mode === 'default');
        if (data && data.success) {
            this.applyClusterPayload(data);
            this.closeSkillEditor();
            if (window.toast) {
                window.toast.success(
                    savingDefault
                        ? 'Default MCP skill vector saved. New clusters will inherit it.'
                        : 'Cluster MCP skills saved.',
                    { key: 'elastic' }
                );
            }
        } else if (window.toast) {
            window.toast.error((data && (data.error || data.detail)) || 'Could not save skill vector', { key: 'elastic' });
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
