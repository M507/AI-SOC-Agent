(function () {
    const form = document.getElementById('setup-form');
    const fieldsEl = document.getElementById('setup-fields');
    const noticesEl = document.getElementById('setup-notices');
    const titleEl = document.getElementById('setup-title');
    const whyEl = document.getElementById('setup-why');
    const progressEl = document.getElementById('setup-progress');
    const errorEl = document.getElementById('setup-error');
    const backBtn = document.getElementById('setup-back');
    const skipBtn = document.getElementById('setup-skip');
    const nextBtn = document.getElementById('setup-next');

    let schema = null;
    let index = 0;
    let showAdvanced = false;

    function step() {
        return schema.steps[index];
    }

    async function api(path, options) {
        const response = await fetch(path, Object.assign({
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
        }, options || {}));
        const data = await response.json().catch(function () { return {}; });
        return { response: response, data: data };
    }

    function matchesWhen(field) {
        if (!field.when) return true;
        const current = valuesFromForm();
        return Object.keys(field.when).every(function (key) {
            const expected = field.when[key];
            const actual = current[key];
            if (Array.isArray(expected)) return expected.indexOf(actual) !== -1;
            if (expected === true) return actual === true || actual === 'true' || actual === 'on';
            return String(actual) === String(expected);
        });
    }

    function valuesFromForm() {
        const values = {};
        fieldsEl.querySelectorAll('[data-field]').forEach(function (node) {
            const name = node.getAttribute('data-field');
            if (node.type === 'checkbox') values[name] = node.checked;
            else if (node.type === 'radio') {
                if (node.checked) values[name] = node.value;
            } else values[name] = node.value;
        });
        return values;
    }

    function renderProgress() {
        progressEl.innerHTML = '';
        schema.steps.forEach(function (item, itemIndex) {
            if (item.id === 'done') return;
            const li = document.createElement('li');
            li.textContent = item.title;
            if (itemIndex === index) li.className = 'is-current';
            else if (itemIndex < index) li.className = 'is-done';
            progressEl.appendChild(li);
        });
    }

    function renderNotices(current) {
        noticesEl.innerHTML = '';
        (current.notices || []).forEach(function (notice) {
            const p = document.createElement('p');
            p.className = 'setup-notice' + (notice.tone === 'beta' ? ' is-beta' : '');
            const text = notice.text || '';
            const repo = schema.tip_repo;
            if (repo && text.indexOf(repo) !== -1) {
                const parts = text.split(repo);
                p.appendChild(document.createTextNode(parts[0]));
                const link = document.createElement('a');
                link.href = repo;
                link.className = 'setup-link';
                link.target = '_blank';
                link.rel = 'noopener noreferrer';
                link.textContent = repo;
                p.appendChild(link);
                p.appendChild(document.createTextNode(parts.slice(1).join(repo)));
            } else {
                p.textContent = text;
            }
            noticesEl.appendChild(p);
        });
    }

    function addHelp(parent, text) {
        if (!text) return;
        const help = document.createElement('span');
        help.className = 'setup-help';
        help.textContent = text;
        parent.appendChild(help);
    }

    function renderFields(current) {
        fieldsEl.innerHTML = '';
        const advanced = (current.fields || []).filter(function (field) { return field.advanced && matchesWhen(field); });
        const normal = (current.fields || []).filter(function (field) { return !field.advanced; });
        normal.forEach(function (field) {
            if (matchesWhen(field)) fieldsEl.appendChild(renderField(field));
        });
        if (advanced.length) {
            const toggle = document.createElement('button');
            toggle.type = 'button';
            toggle.className = 'setup-advanced-toggle';
            toggle.textContent = showAdvanced ? 'Hide advanced' : 'Show advanced';
            toggle.addEventListener('click', function () {
                showAdvanced = !showAdvanced;
                render();
            });
            fieldsEl.appendChild(toggle);
            if (showAdvanced) {
                advanced.forEach(function (field) {
                    fieldsEl.appendChild(renderField(field));
                });
            }
        }
        if ((current.actions || []).indexOf('refresh_models') !== -1) {
            const refresh = document.createElement('button');
            refresh.type = 'button';
            refresh.className = 'setup-inline';
            refresh.id = 'setup-refresh-models';
            refresh.textContent = 'Refresh models';
            refresh.addEventListener('click', refreshModels);
            fieldsEl.appendChild(refresh);
        }
        if ((current.actions || []).indexOf('register_openwebui') !== -1) {
            const register = document.createElement('button');
            register.type = 'button';
            register.className = 'setup-inline';
            register.textContent = 'Register with Open WebUI';
            register.addEventListener('click', registerOpenWebUI);
            fieldsEl.appendChild(register);
        }
    }

    function renderField(field) {
        const wrap = document.createElement('div');
        wrap.className = 'setup-field';
        if (field.type === 'choice') {
            const legend = document.createElement('span');
            legend.textContent = field.label;
            wrap.appendChild(legend);
            (field.options || []).forEach(function (option) {
                if (option.requires_siem && !(schema.choices && schema.choices.siem === 'elastic')) return;
                if (option.advanced && !showAdvanced) return;
                const label = document.createElement('label');
                label.className = 'setup-choice';
                const input = document.createElement('input');
                input.type = 'radio';
                input.name = field.name;
                input.value = option.value;
                input.setAttribute('data-field', field.name);
                if (String(field.value || '') === option.value) input.checked = true;
                input.addEventListener('change', function () { renderFields(step()); });
                label.appendChild(input);
                label.appendChild(document.createTextNode(option.label));
                if (option.beta) {
                    const badge = document.createElement('span');
                    badge.className = 'setup-badge';
                    badge.textContent = 'Beta';
                    label.appendChild(badge);
                }
                if (option.help) {
                    const help = document.createElement('span');
                    help.className = 'setup-choice-help';
                    help.textContent = option.help;
                    label.appendChild(help);
                }
                wrap.appendChild(label);
            });
            return wrap;
        }
        if (field.type === 'checkbox') {
            const label = document.createElement('label');
            label.className = 'setup-check';
            const input = document.createElement('input');
            input.type = 'checkbox';
            input.setAttribute('data-field', field.name);
            input.checked = Boolean(field.value);
            input.addEventListener('change', function () { renderFields(step()); });
            label.appendChild(input);
            const text = document.createElement('span');
            text.textContent = field.label;
            if (field.beta) text.textContent += ' (beta)';
            label.appendChild(text);
            wrap.appendChild(label);
            addHelp(wrap, field.help);
            return wrap;
        }
        const label = document.createElement('label');
        label.setAttribute('for', 'field-' + field.name);
        label.textContent = field.label;
        if (field.beta) label.textContent += ' (beta)';
        wrap.appendChild(label);
        let input;
        if (field.type === 'model') {
            const row = document.createElement('div');
            row.className = 'setup-models';
            input = document.createElement('input');
            input.type = 'text';
            const select = document.createElement('select');
            select.setAttribute('aria-label', 'Available models');
            const blank = document.createElement('option');
            blank.value = '';
            blank.textContent = 'Available models';
            select.appendChild(blank);
            select.addEventListener('change', function () {
                if (select.value) input.value = select.value;
            });
            row.appendChild(input);
            row.appendChild(select);
            wrap.appendChild(row);
            input._modelSelect = select;
        } else {
            input = document.createElement('input');
            input.type = field.type === 'number' ? 'number' : (field.type === 'password' ? 'password' : 'text');
            wrap.appendChild(input);
        }
        input.id = 'field-' + field.name;
        input.setAttribute('data-field', field.name);
        if (field.value !== undefined && field.value !== null && field.type !== 'checkbox') input.value = field.value;
        if (field.placeholder) input.placeholder = field.placeholder;
        if (field.required) input.required = true;
        if (field.autocomplete) input.autocomplete = field.autocomplete;
        addHelp(wrap, field.help);
        return wrap;
    }

    function showError(message) {
        errorEl.hidden = !message;
        errorEl.textContent = message || '';
    }

    function render() {
        const current = step();
        titleEl.textContent = current.title;
        whyEl.textContent = current.why || '';
        backBtn.hidden = index === 0;
        skipBtn.hidden = !current.skippable || current.id === 'done';
        nextBtn.textContent = current.id === 'review' ? 'Finish' : (current.id === 'done' ? 'Open dashboard' : (current.id === 'edr' ? 'Continue' : 'Continue'));
        if (current.id === 'done') nextBtn.textContent = 'Open dashboard';
        renderProgress();
        renderNotices(current);
        renderFields(current);
        showError('');
    }

    async function refreshModels() {
        const values = valuesFromForm();
        showError('');
        const result = await api('/api/setup/llm/models', {
            method: 'POST',
            body: JSON.stringify({
                provider: values.provider || 'openwebui',
                settings: { api_key: values.api_key || '', base_url: values.base_url || '', model: values.model || '' },
            }),
        });
        if (!result.response.ok) {
            showError((result.data && result.data.detail) || 'Could not refresh models.');
            return;
        }
        const select = fieldsEl.querySelector('[aria-label="Available models"]');
        if (!select) return;
        const current = select.parentNode.querySelector('[data-field="model"]');
        select.innerHTML = '';
        const blank = document.createElement('option');
        blank.value = '';
        blank.textContent = (result.data.models || []).length + ' models';
        select.appendChild(blank);
        (result.data.models || []).forEach(function (id) {
            const option = document.createElement('option');
            option.value = id;
            option.textContent = id;
            select.appendChild(option);
        });
        if (current && current.value) select.value = current.value;
    }

    async function registerOpenWebUI() {
        const values = valuesFromForm();
        showError('');
        const result = await api('/api/setup/openwebui/connect', {
            method: 'POST',
            body: JSON.stringify({ public_url: values.public_url || '' }),
        });
        if (!result.response.ok) {
            showError((result.data && result.data.detail) || 'Open WebUI did not register the MCP listener.');
            return;
        }
        showError('');
        const note = document.createElement('p');
        note.className = 'setup-notice';
        note.textContent = 'Open WebUI is registered. Server id ' + (result.data.mcp_server_id || 'samigpt-mcp') + '.';
        noticesEl.appendChild(note);
    }

    async function submit(action) {
        const current = step();
        if (current.id === 'done') {
            window.location.href = '/';
            return;
        }
        showError('');
        nextBtn.disabled = true;
        const path = current.id === 'review' && action !== 'skip' ? '/api/setup/complete' : '/api/setup/steps/' + current.id;
        const result = await api(path, {
            method: 'POST',
            body: JSON.stringify({ action: action, values: action === 'skip' ? {} : valuesFromForm() }),
        });
        nextBtn.disabled = false;
        if (!result.response.ok || !result.data.success) {
            const errors = (result.data && result.data.errors) || {};
            const first = Object.keys(errors).map(function (key) { return errors[key]; })[0];
            showError(first || (result.data && result.data.detail) || 'Could not save this step.');
            return;
        }
        const nextId = result.data.next_step;
        const nextIndex = schema.steps.findIndex(function (item) { return item.id === nextId; });
        const refreshed = await api('/api/setup/schema');
        if (refreshed.response.ok) schema = refreshed.data;
        index = nextIndex >= 0 ? nextIndex : Math.min(index + 1, schema.steps.length - 1);
        showAdvanced = false;
        render();
    }

    form.addEventListener('submit', function (event) {
        event.preventDefault();
        submit('save');
    });
    skipBtn.addEventListener('click', function () { submit('skip'); });
    backBtn.addEventListener('click', function () {
        if (index > 0) {
            index -= 1;
            render();
        }
    });

    api('/api/setup/schema').then(function (result) {
        if (!result.response.ok) {
            showError('Setup could not be loaded.');
            return;
        }
        schema = result.data;
        const resume = schema.resume_step || 'welcome';
        const found = schema.steps.findIndex(function (item) { return item.id === resume; });
        index = found >= 0 ? found : 0;
        render();
    });
})();
