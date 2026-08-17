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
        this.log('info', 'Elastic clusters settings ready. Button actions will log here.');
    }

    log(level, message, extra) {
        const text = extra === undefined || extra === null
            ? String(message)
            : `${message} ${typeof extra === 'string' ? extra : JSON.stringify(extra)}`;
        const line = `[Elastic] ${text}`;
        if (level === 'error') {
            console.error(line);
        } else if (level === 'warn') {
            console.warn(line);
        } else {
            console.log(line);
        }
        const root = document.getElementById('elastic-activity-log');
        if (!root) return;
        const row = document.createElement('p');
        const cls = level === 'success' ? 'success' : (level === 'warn' ? 'warn' : (level === 'error' ? 'error' : 'info'));
        row.className = `elastic-log-line is-${cls}`;
        const stamp = new Date().toISOString().slice(11, 19);
        row.textContent = `${stamp} ${text}`;
        root.appendChild(row);
        while (root.childElementCount > 200) {
            root.removeChild(root.firstChild);
        }
        root.scrollTop = root.scrollHeight;
    }

    safeForm(payload) {
        if (!payload) return {};
        return {
            name: payload.name || '',
            url: payload.base_url || '',
            auth: payload.username ? 'basic' : (payload.api_key ? 'api_key' : 'none'),
            has_api_key: Boolean(payload.api_key),
            has_username: Boolean(payload.username),
            has_password: Boolean(payload.password),
            timeout_seconds: payload.timeout_seconds,
            verify_ssl: payload.verify_ssl,
            id: payload.id || null,
        };
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
            authSelect.addEventListener('change', () => {
                this.log('info', `Authentication type set to ${authSelect.value}`);
                this.syncAuthFields();
            });
        }
        const list = document.getElementById('elastic-clusters-list');
        if (list) {
            list.addEventListener('click', (event) => this.onListClick(event));
        }
        const editDefault = document.getElementById('elastic-edit-default-skills');
        if (editDefault) {
            editDefault.addEventListener('click', () => {
                this.log('info', 'Edit default skills clicked');
                this.openSkillEditor({ mode: 'default' });
            });
        }
        const closeSkills = document.getElementById('close-skill-vector-modal');
        if (closeSkills) {
            closeSkills.addEventListener('click', () => {
                this.log('info', 'MCP skills editor closed (X)');
                this.closeSkillEditor();
            });
        }
        const cancelSkills = document.getElementById('cancel-skill-vector-btn');
        if (cancelSkills) {
            cancelSkills.addEventListener('click', () => {
                this.log('info', 'MCP skills editor cancelled');
                this.closeSkillEditor();
            });
        }
        const saveSkills = document.getElementById('save-skill-vector-btn');
        if (saveSkills) {
            saveSkills.addEventListener('click', () => this.saveSkillEditor());
        }
        const resetSkills = document.getElementById('skill-vector-reset-btn');
        if (resetSkills) {
            resetSkills.addEventListener('click', () => {
                this.log('info', 'Reset MCP skills to all on');
                this.resetSkillEditor();
            });
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
        const clearLog = document.getElementById('elastic-clear-log-btn');
        if (clearLog) {
            clearLog.addEventListener('click', () => {
                const root = document.getElementById('elastic-activity-log');
                if (root) root.innerHTML = '';
                this.log('info', 'Cleared Elastic settings activity log.');
            });
        }
        this.syncAuthFields();
        this.log('info', 'Bound Elastic settings buttons: Test, Add, MCP skills, Set default, Delete, skill editor.');
    }

    async load() {
        this.log('info', 'Loading Elastic clusters…');
        const data = await this.api.getElasticClusters();
        if (!data || data.success === false) {
            this.clusters = [];
            this.defaultClusterId = null;
            this.log('error', 'Failed to load Elastic clusters', data && (data.error || data.detail));
            this.render();
            return data;
        }
        this.clusters = data.clusters || [];
        this.defaultClusterId = data.default_cluster_id || (this.clusters[0] && this.clusters[0].id) || null;
        this.defaultSkillVector = data.default_skill_vector || (data.skill_catalog && data.skill_catalog.default_skill_vector) || '';
        if (data.skill_catalog) {
            this.catalog = data.skill_catalog;
        }
        this.log('success', `Loaded ${this.clusters.length} cluster(s); default=${this.defaultClusterId || 'none'}`, {
            clusters: this.clusters.map((item) => ({ id: item.id, name: item.name, url: item.base_url, kind_guess: item.base_url })),
        });
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
            const flags = cluster.solution_flags || {};
            const pills = (this.catalog.solutions || []).filter((item) => flags[item.id]).map((item) => {
                return `<span class="integration-pill is-on">${this.escapeHtml(item.short || item.label)}</span>`;
            }).join('');
            return `
                <article class="cluster-card${isDefault ? ' is-default' : ''}" data-cluster-id="${this.escapeAttr(cluster.id)}">
                    <div class="cluster-card-head">
                        <h4>${this.escapeHtml(cluster.name)}</h4>
                        ${isDefault ? '<span class="cluster-pill">Default</span>' : ''}
                    </div>
                    <p class="cluster-url">${this.escapeHtml(cluster.base_url)}</p>
                    <p class="settings-help">${auth}${cluster.has_credentials ? '' : ' — missing credentials'}</p>
                    <div class="solution-pills">${pills || '<span class="settings-help">No MCP solutions enabled</span>'}</div>
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
        ['session-cluster-select', 'autorun-cluster-select', 'edit-autorun-cluster-select'].forEach((id) => {
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
        this.log('info', 'Add cluster clicked', this.safeForm(payload));
        if (!payload.base_url) {
            this.log('warn', 'Add cluster blocked: URL is required.');
            if (window.toast) window.toast.info('Enter the Elastic URL.', { key: 'elastic' });
            return;
        }
        if (window.toast) window.toast.info('Saving cluster…', { key: 'elastic', duration: 0 });
        const data = await this.api.createElasticCluster(payload);
        if (data.success) {
            this.applyClusterPayload(data);
            this.clearForm();
            this.log('success', `Cluster saved. count=${(data.clusters || []).length} default=${data.default_cluster_id}`);
            if (window.toast) window.toast.success('Elastic cluster saved. It inherited the default MCP skill vector.', { key: 'elastic' });
        } else {
            this.log('error', 'Add cluster failed', data.error || data.detail || data);
            if (window.toast) window.toast.error(data.error || data.detail || 'Could not save cluster', { key: 'elastic' });
        }
    }

    async testForm() {
        const payload = this.collectForm();
        this.log('info', 'Test connection clicked (add-cluster form)', this.safeForm(payload));
        if (!payload.base_url) {
            this.log('warn', 'Test connection blocked: URL is required.');
            if (window.toast) window.toast.info('Enter the Elastic URL.', { key: 'elastic' });
            return;
        }
        if (window.toast) window.toast.info('Testing cluster…', { key: 'elastic', duration: 0 });
        const data = await this.api.testElasticCluster(payload);
        this.showProbeResult(data, payload.base_url);
    }

    async onListClick(event) {
        const skillsId = event.target.closest && event.target.closest('[data-elastic-skills]');
        const testId = event.target.closest && event.target.closest('[data-elastic-test]');
        const defaultId = event.target.closest && event.target.closest('[data-elastic-default]');
        const deleteId = event.target.closest && event.target.closest('[data-elastic-delete]');
        if (skillsId) {
            const id = skillsId.getAttribute('data-elastic-skills');
            this.log('info', `MCP skills clicked for cluster ${id} (${this.clusterName(id)})`);
            this.openSkillEditor({ mode: 'cluster', clusterId: id });
            return;
        }
        if (testId) {
            const id = testId.getAttribute('data-elastic-test');
            const cluster = this.clusters.find((item) => item.id === id);
            const url = cluster ? cluster.base_url : this.urlFor(id);
            this.log('info', `Test connection clicked for cluster ${id} (${this.clusterName(id)}) url=${url} verify_ssl=${cluster ? cluster.verify_ssl : 'unknown'}`);
            if (window.toast) window.toast.info('Testing cluster…', { key: 'elastic', duration: 0 });
            const data = await this.api.testElasticCluster({
                id,
                base_url: url,
                verify_ssl: cluster ? cluster.verify_ssl : undefined,
                timeout_seconds: cluster ? cluster.timeout_seconds : undefined,
            });
            this.showProbeResult(data, url);
            return;
        }
        if (defaultId) {
            const id = defaultId.getAttribute('data-elastic-default');
            this.log('info', `Set default clicked for cluster ${id} (${this.clusterName(id)})`);
            const data = await this.api.setDefaultElasticCluster(id);
            if (data.success) {
                this.applyClusterPayload(data);
                this.log('success', `Default cluster is now ${data.default_cluster_id}`);
                if (window.toast) window.toast.success('Default cluster updated.', { key: 'elastic' });
            } else {
                this.log('error', 'Set default failed', data.error || data.detail || data);
            }
            return;
        }
        if (deleteId) {
            const id = deleteId.getAttribute('data-elastic-delete');
            this.log('info', `Delete clicked for cluster ${id} (${this.clusterName(id)})`);
            if (!confirm('Delete this Elastic cluster? Sessions that used it will fall back to the default.')) {
                this.log('warn', `Delete cancelled for cluster ${id}`);
                return;
            }
            const data = await this.api.deleteElasticCluster(id);
            if (data.success) {
                this.applyClusterPayload(data);
                this.log('success', `Deleted cluster ${id}. remaining=${(data.clusters || []).length} default=${data.default_cluster_id}`);
                if (window.toast) window.toast.success('Cluster deleted.', { key: 'elastic' });
            } else {
                this.log('error', `Delete failed for cluster ${id}`, data.error || data.detail || data);
            }
        }
    }

    urlFor(clusterId) {
        const cluster = this.clusters.find((item) => item.id === clusterId);
        return cluster ? cluster.base_url : '';
    }

    showProbeResult(data, url) {
        const summary = {
            url: url || (data && data.message) || '',
            ok: Boolean(data && data.ok),
            kind: data && data.kind,
            message: data && data.message,
            error: data && data.error,
            attempts: data && data.attempts,
            details: data && data.details,
        };
        if (data && data.ok) {
            this.log('success', `Test connection succeeded (${summary.kind || 'unknown'})`, summary);
            if (window.toast) window.toast.success(data.message || 'Cluster is reachable.', { key: 'elastic' });
        } else {
            this.log('error', 'Test connection failed', summary);
            if (window.toast) {
                window.toast.error((data && (data.message || data.error)) || 'Cluster check failed', { key: 'elastic' });
            }
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
        this.log('info', `Opened MCP skills editor (${target.mode}${cluster ? ` / ${cluster.name}` : ''})`);
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
            this.log('info', `Solution toggle ${solutionId}=${target.checked ? 'Y' : 'N'}`);
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
            this.log('info', `Skill toggle ${skillId}=${target.checked ? 'Y' : 'N'}`);
            this.renderSkillEditor();
        }
    }

    onSkillGroupClick(event) {
        const toggle = event.target.closest && event.target.closest('[data-skill-expand]');
        if (!toggle) return;
        const groupEl = toggle.closest('.skill-group');
        if (!groupEl) return;
        groupEl.classList.toggle('is-open');
        const open = groupEl.classList.contains('is-open');
        toggle.textContent = open ? 'Hide' : 'Show';
        this.log('info', `${open ? 'Expanded' : 'Collapsed'} ${groupEl.getAttribute('data-skill-group') || 'skill'} group`);
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
            const enabledCount = (group.skills || []).filter((skill) => {
                if (skill.id in this.editorState.skills) {
                    return Boolean(this.editorState.skills[skill.id]);
                }
                return parentOn;
            }).length;
            const total = (group.skills || []).length;
            const skills = (group.skills || []).map((skill) => {
                const allowed = (skill.id in this.editorState.skills)
                    ? Boolean(this.editorState.skills[skill.id])
                    : parentOn;
                const override = skill.id in this.editorState.skills
                    ? (this.editorState.skills[skill.id] ? ' override-on' : ' override-off')
                    : '';
                return `<label class="skill-row${override}">
                    <input type="checkbox" data-skill="${this.escapeAttr(skill.id)}"${allowed ? ' checked' : ''}>
                    <span class="skill-copy">
                        <span class="skill-name">${this.escapeHtml(skill.label || skill.id)}</span>
                        <code class="skill-id">${this.escapeHtml(skill.id)}</code>
                    </span>
                </label>`;
            }).join('');
            return `<section class="skill-group is-open${parentOn ? '' : ' is-disabled'}" data-skill-group="${this.escapeAttr(group.id)}">
                <header class="skill-group-head">
                    <div>
                        <h4>${this.escapeHtml(group.name)} <span class="skill-count">${enabledCount}/${total}</span></h4>
                        <p class="settings-help">${this.escapeHtml(group.help || '')}</p>
                    </div>
                    <button type="button" class="btn btn-secondary btn-sm" data-skill-expand>Hide</button>
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
            this.log('error', 'Save MCP skills blocked: invalid vector', parsed.error);
            if (window.toast) window.toast.error(parsed.error, { key: 'elastic' });
            return;
        }
        const vector = this.encodeVector(parsed.state);
        const savingDefault = Boolean(this.editorTarget && this.editorTarget.mode === 'default');
        this.log('info', `Save MCP skills clicked (${savingDefault ? 'default' : this.editorTarget && this.editorTarget.clusterId})`, { vector });
        if (window.toast) window.toast.info('Saving skill vector…', { key: 'elastic', duration: 0 });
        let data;
        if (savingDefault) {
            data = await this.api.setDefaultSkillVector(vector);
        } else {
            data = await this.api.setClusterSkillVector(this.editorTarget.clusterId, vector);
        }
        if (data && data.success) {
            this.applyClusterPayload(data);
            this.closeSkillEditor();
            this.log('success', savingDefault ? `Saved default skill vector ${vector}` : `Saved cluster skill vector ${vector}`);
            if (window.toast) {
                window.toast.success(
                    savingDefault
                        ? 'Default MCP skill vector saved. New clusters will inherit it.'
                        : 'Cluster MCP skills saved.',
                    { key: 'elastic' }
                );
            }
        } else {
            this.log('error', 'Save MCP skills failed', data && (data.error || data.detail || data));
            if (window.toast) {
                window.toast.error((data && (data.error || data.detail)) || 'Could not save skill vector', { key: 'elastic' });
            }
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
