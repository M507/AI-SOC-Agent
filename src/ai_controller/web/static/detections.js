// Findings, Rules, and Review. Behavior and API: documentation/detection-as-code.md
class DetectionsManager {
    constructor(app) {
        this.app = app;
        this.page = 'findings';
        this.finding = null;
        this.rule = null;
        this.review = null;
        this.checked = new Set();
        this.busy = false;
        // Implement stays disabled while every exception card is unchecked.
        // setBusy must not clear that, or a finished request would enable a write with nothing selected.
        this.implementLocked = false;
        this.bind();
    }

    bind() {
        const refresh = document.getElementById('findings-refresh');
        if (refresh) refresh.addEventListener('click', () => this.loadFindings());
        const search = document.getElementById('findings-search');
        if (search) search.addEventListener('input', () => this.debounce('findingsTimer', () => this.loadFindings()));
        const rulesSearch = document.getElementById('rules-search');
        if (rulesSearch) rulesSearch.addEventListener('input', () => this.debounce('rulesTimer', () => this.loadRules()));
        const template = document.getElementById('findings-ask-template');
        if (template) {
            template.addEventListener('change', () => {
                const custom = document.getElementById('findings-ask-custom');
                if (custom) custom.hidden = template.value !== 'custom';
            });
        }
        const suggested = document.getElementById('findings-select-suggested');
        if (suggested) suggested.addEventListener('click', () => this.setSuggestedFields());
        const clear = document.getElementById('findings-clear');
        if (clear) clear.addEventListener('click', () => {
            this.checked = new Set();
            this.renderFields();
        });
        document.querySelectorAll('[data-detection-action]').forEach((button) => {
            button.addEventListener('click', () => this.onFindingAction(button.dataset.detectionAction));
        });
        document.querySelectorAll('[data-review-action]').forEach((button) => {
            button.addEventListener('click', () => this.onReviewAction(button.dataset.reviewAction));
        });
        const disable = document.getElementById('rules-disable');
        if (disable) disable.addEventListener('click', () => this.disableRule());
    }

    debounce(timerName, fn) {
        window.clearTimeout(this[timerName]);
        this[timerName] = window.setTimeout(fn, 250);
    }

    show(page) {
        this.page = page || 'findings';
        const titles = {
            findings: ['Findings', 'Open alerts from the lookback in Settings. Check the evidence you want to keep, then ask, except, or update workflow status.'],
            rules: ['Rules', 'Search the configured rules folder. Disable opens Review and does not write the file until Implement.'],
            review: ['Review', 'Keep the conditions you want. Unchecked conditions are omitted. Draft spends one model call. Implement writes the rule file.'],
        };
        const pair = titles[this.page] || titles.findings;
        const title = document.getElementById('detections-title');
        const caption = document.getElementById('detections-caption');
        if (title) title.textContent = pair[0];
        if (caption) caption.textContent = pair[1];
        document.querySelectorAll('[data-detections-page-content]').forEach((panel) => {
            panel.hidden = panel.dataset.detectionsPageContent !== this.page;
        });
        this.setStatus('');
        if (this.page === 'findings') this.loadFindings();
        if (this.page === 'rules') this.loadRules();
        if (this.page === 'review') this.loadReviews();
    }

    setStatus(message, isError) {
        const node = document.getElementById('detections-status');
        if (!node) return;
        node.hidden = !message;
        node.textContent = message || '';
        node.classList.toggle('is-error', Boolean(isError));
    }

    async request(url, options) {
        const response = await this.app.api._fetch(url, options || {});
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
            const detail = data.detail || data.error || response.statusText;
            throw new Error(typeof detail === 'string' ? detail : 'Request failed');
        }
        return data;
    }

    async loadFindings() {
        const query = (document.getElementById('findings-search') || {}).value || '';
        try {
            const data = await this.request('/api/detections/findings?q=' + encodeURIComponent(query));
            this.fillTemplates(data.templates || []);
            this.renderFindingList(data.findings || []);
        } catch (error) {
            this.setStatus(error.message, true);
        }
    }

    fillTemplates(templates) {
        const select = document.getElementById('findings-ask-template');
        if (!select || select.options.length) return;
        templates.forEach((item) => {
            const option = document.createElement('option');
            option.value = item.id;
            option.textContent = item.label;
            select.append(option);
        });
    }

    renderFindingList(findings) {
        const host = document.getElementById('findings-list');
        const count = document.getElementById('findings-count');
        host.replaceChildren();
        if (count) count.textContent = findings.length ? findings.length + ' open' : '';
        if (!findings.length) {
            host.append(this.emptyNote('No open findings in this lookback.'));
            return;
        }
        const selected = this.finding && this.finding.id;
        findings.forEach((item) => {
            host.append(this.listButton({
                id: item.id,
                title: item.rule_name || item.title || item.id,
                meta: [item.host_name, item.user_name, this.formatTime(item.created_at)].filter(Boolean),
                badge: item.severity,
                active: item.id === selected,
                onClick: () => this.openFinding(item.id),
            }));
        });
    }

    async openFinding(alertId) {
        this.setStatus('');
        const answer = document.getElementById('findings-answer');
        if (answer) {
            answer.hidden = true;
            answer.textContent = '';
        }
        try {
            const data = await this.request('/api/detections/findings/' + encodeURIComponent(alertId));
            this.finding = data.finding;
            this.checked = new Set(
                (data.finding.fields || []).filter((row) => row.suggested).map((row) => row.field + '=' + row.value)
            );
            this.renderFields();
            this.markActive('findings-list', this.finding.id);
        } catch (error) {
            this.setStatus(error.message, true);
        }
    }

    renderFields() {
        const finding = this.finding;
        const list = document.getElementById('findings-fields');
        const empty = document.getElementById('findings-empty');
        const actions = document.getElementById('findings-actions');
        const block = document.getElementById('findings-field-block');
        const summary = document.getElementById('findings-summary');
        empty.hidden = true;
        list.hidden = false;
        actions.hidden = false;
        if (block) block.hidden = false;
        if (summary) {
            summary.hidden = false;
            summary.replaceChildren();
            const heading = document.createElement('h3');
            heading.textContent = finding.rule_name || finding.title || finding.id;
            summary.append(heading);
            summary.append(this.metaLine([
                finding.severity,
                finding.host_name,
                finding.user_name,
                finding.status,
                this.formatTime(finding.created_at),
            ]));
        }
        list.replaceChildren();
        const fields = finding.fields || [];
        if (!fields.length) {
            list.append(this.emptyNote('This alert has no evidence fields to check.'));
        }
        fields.forEach((row) => {
            const key = row.field + '=' + row.value;
            const item = document.createElement('li');
            const label = document.createElement('label');
            const box = document.createElement('input');
            box.type = 'checkbox';
            box.checked = this.checked.has(key);
            box.setAttribute('aria-label', row.field + ' equals ' + row.value);
            box.addEventListener('change', () => {
                if (box.checked) this.checked.add(key);
                else this.checked.delete(key);
                this.updateSelectedCount();
            });
            const copy = document.createElement('span');
            const name = document.createElement('span');
            name.className = 'dac-field-name';
            name.textContent = row.field;
            const value = document.createElement('span');
            value.className = 'dac-field-value';
            value.textContent = ' = ' + row.value;
            copy.append(name, value);
            label.append(box, copy);
            if (row.suggested) {
                const mark = document.createElement('span');
                mark.className = 'dac-suggested';
                mark.textContent = 'Suggested';
                label.append(mark);
            }
            item.append(label);
            list.append(item);
        });
        this.updateSelectedCount();
    }

    updateSelectedCount() {
        const node = document.getElementById('findings-selected');
        if (!node || !this.finding) return;
        const total = (this.finding.fields || []).length;
        node.textContent = this.checked.size + ' of ' + total + ' checked. Every action uses the checked fields.';
    }

    setSuggestedFields() {
        if (!this.finding) return;
        this.checked = new Set(
            (this.finding.fields || []).filter((row) => row.suggested).map((row) => row.field + '=' + row.value)
        );
        this.renderFields();
    }

    selectedEntries() {
        const entries = [];
        (this.finding && this.finding.fields || []).forEach((row) => {
            if (this.checked.has(row.field + '=' + row.value)) entries.push({ field: row.field, value: row.value });
        });
        return entries;
    }

    async onFindingAction(action) {
        if (!this.finding || this.busy) return;
        const entries = this.selectedEntries();
        if (!entries.length) {
            this.setStatus('Check at least one evidence field.', true);
            return;
        }
        this.busy = true;
        this.setBusy(true);
        try {
            if (action === 'ask') {
                const promptId = document.getElementById('findings-ask-template').value;
                const custom = document.getElementById('findings-ask-custom').value;
                const data = await this.request('/api/detections/findings/' + encodeURIComponent(this.finding.id) + '/ask', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ prompt_id: promptId, custom_instruction: custom, entries: entries }),
                });
                const answer = document.getElementById('findings-answer');
                answer.hidden = false;
                answer.textContent = data.answer || '';
                return;
            }
            if (action === 'exception' || action === 'suggest') {
                const path = action === 'exception' ? 'exception' : 'suggest';
                const data = await this.request('/api/detections/findings/' + encodeURIComponent(this.finding.id) + '/' + path, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ entries: entries }),
                });
                this.app.activeDetectionsPage = 'review';
                this.app.setActiveSection('detections');
                this.openReview(data.review);
                this.setStatus('Opened a review. The rule file is unchanged.');
                return;
            }
            const note = document.getElementById('findings-note').value;
            const data = await this.request('/api/detections/findings/' + encodeURIComponent(this.finding.id) + '/status', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    status: action === 'close' ? 'closed' : 'acknowledged',
                    entries: entries,
                    note: note,
                    rule_id: this.finding.rule_id || '',
                }),
            });
            const label = action === 'close' ? 'Closed' : 'Acknowledged';
            const withNote = data.note ? 'with a note' : 'without a note';
            this.setStatus(label + ' ' + (data.updated || []).length + ' alert(s) ' + withNote + '.');
            this.loadFindings();
        } catch (error) {
            this.setStatus(error.message, true);
        } finally {
            this.busy = false;
            this.setBusy(false);
        }
    }

    async loadRules() {
        const query = (document.getElementById('rules-search') || {}).value || '';
        const host = document.getElementById('rules-list');
        const count = document.getElementById('rules-count');
        try {
            const data = await this.request('/api/detections/rules?q=' + encodeURIComponent(query) + '&limit=50');
            host.replaceChildren();
            if (!data.configured) {
                if (count) count.textContent = '';
                host.append(this.emptyNote('Rules folder is not configured. Set it under Settings, General.'));
                return;
            }
            const rules = data.rules || [];
            if (count) count.textContent = rules.length ? rules.length + (rules.length === 50 ? '+' : '') + ' rules' : 'No matches';
            if (!rules.length) {
                host.append(this.emptyNote('No rules match that search.'));
                return;
            }
            const selected = this.rule && this.rule.rule_id;
            rules.forEach((rule) => {
                host.append(this.listButton({
                    id: rule.rule_id,
                    title: rule.name || rule.rule_id,
                    meta: [rule.language, rule.enabled ? 'enabled' : 'disabled'].filter(Boolean),
                    badge: rule.severity,
                    active: rule.rule_id === selected,
                    onClick: () => this.openRule(rule.rule_id),
                }));
            });
        } catch (error) {
            this.setStatus(error.message, true);
        }
    }

    async openRule(ruleId) {
        try {
            const data = await this.request('/api/detections/rules/' + encodeURIComponent(ruleId));
            this.rule = data.rule;
            document.getElementById('rules-empty').hidden = true;
            const summary = document.getElementById('rules-summary');
            summary.hidden = false;
            summary.replaceChildren();
            const heading = document.createElement('h3');
            heading.textContent = data.rule.name || data.rule.rule_id;
            summary.append(heading);
            summary.append(this.metaLine([
                data.rule.severity,
                data.rule.language,
                data.rule.status,
                (data.rule.exception_count || 0) + ' exceptions',
            ]));
            if (data.rule.description) {
                const description = document.createElement('p');
                description.textContent = data.rule.description;
                summary.append(description);
            }
            const queryBlock = document.getElementById('rules-query-block');
            const exceptionsBlock = document.getElementById('rules-exceptions-block');
            queryBlock.hidden = false;
            exceptionsBlock.hidden = false;
            document.getElementById('rules-query').textContent = data.rule.query || 'This rule has no query text.';
            const items = data.rule.exception_items || [];
            document.getElementById('rules-exceptions').textContent = items.length
                ? JSON.stringify(items, null, 2)
                : 'No exceptions on this rule yet.';
            document.getElementById('rules-disable-bar').hidden = data.rule.status === 'disabled';
            this.markActive('rules-list', data.rule.rule_id);
        } catch (error) {
            this.setStatus(error.message, true);
        }
    }

    async disableRule() {
        if (!this.rule || this.busy) return;
        this.busy = true;
        this.setBusy(true);
        try {
            const data = await this.request('/api/detections/rules/' + encodeURIComponent(this.rule.rule_id) + '/disable', { method: 'POST' });
            this.app.activeDetectionsPage = 'review';
            this.app.setActiveSection('detections');
            this.openReview(data.review);
        } catch (error) {
            this.setStatus(error.message, true);
        } finally {
            this.busy = false;
            this.setBusy(false);
        }
    }

    async loadReviews() {
        const host = document.getElementById('review-list');
        const count = document.getElementById('review-count');
        try {
            const data = await this.request('/api/detections/reviews');
            host.replaceChildren();
            const reviews = (data.reviews || []).filter((item) => !item.archived);
            if (count) count.textContent = reviews.length ? reviews.length + ' open' : '';
            if (!reviews.length) {
                host.append(this.emptyNote('No open reviews. Create an exception from a finding, or disable a rule.'));
                return;
            }
            const selected = this.review && this.review.id;
            reviews.forEach((item) => {
                host.append(this.listButton({
                    id: item.id,
                    title: item.title,
                    meta: [item.kind === 'disable' ? 'Disable' : 'Exception'],
                    badge: item.stage,
                    badgeClass: 'dac-stage dac-stage-' + String(item.stage || ''),
                    active: item.id === selected,
                    onClick: () => this.openReview(item),
                }));
            });
        } catch (error) {
            this.setStatus(error.message, true);
        }
    }

    openReview(review) {
        this.review = review;
        const detail = document.getElementById('review-detail');
        const scroll = detail ? detail.scrollTop : 0;
        document.getElementById('review-empty').hidden = true;
        document.getElementById('review-body').hidden = false;
        const overview = document.getElementById('review-overview');
        overview.replaceChildren();
        const info = review.overview || {};
        const heading = document.createElement('h3');
        heading.textContent = info.name || review.rule_name || review.title || 'Review';
        const summary = document.createElement('div');
        summary.className = 'detections-summary';
        summary.append(heading);
        summary.append(this.metaLine([
            info.severity,
            info.language,
            info.status,
            review.kind === 'disable' ? 'Disable' : 'Exception',
            review.stage,
            typeof info.exception_count === 'number' ? info.exception_count + ' existing exceptions' : '',
        ]));
        if (info.file) {
            const file = document.createElement('p');
            file.className = 'detections-kicker';
            const full = String(info.file);
            file.textContent = full.split('/').pop() || full;
            file.title = full;
            summary.append(file);
        }
        overview.append(summary);
        if (review.rationale) {
            const rationale = document.createElement('p');
            rationale.className = 'detections-kicker';
            rationale.textContent = review.rationale;
            overview.append(rationale);
        }
        (review.warnings || []).forEach((warning) => overview.append(this.banner(warning, false)));
        if (review.error) overview.append(this.banner(review.error, true));

        const conditions = document.getElementById('review-conditions');
        const conditionsBlock = document.getElementById('review-conditions-block');
        conditions.replaceChildren();
        const cards = review.exceptions || [];
        if (conditionsBlock) conditionsBlock.hidden = review.kind === 'disable';
        if (!cards.length) {
            conditions.append(this.emptyNote(
                review.kind === 'disable'
                    ? 'Disabling a rule has no exception conditions. The change below is the whole file.'
                    : 'No conditions yet. Draft asks the model for some.'
            ));
        }
        cards.forEach((card, index) => {
            const label = document.createElement('label');
            const box = document.createElement('input');
            box.type = 'checkbox';
            box.className = 'suggestion-check';
            box.checked = card.selected !== false;
            box.addEventListener('change', () => this.toggleCondition(index, box.checked));
            const copy = document.createElement('span');
            copy.className = 'dac-condition-copy';
            const title = document.createElement('span');
            title.className = 'dac-condition-title';
            title.textContent = card.name || 'Exception';
            const confidence = document.createElement('span');
            confidence.className = this.severityClass(card.confidence || 'medium');
            confidence.textContent = card.confidence || 'medium';
            title.append(confidence);
            const entries = document.createElement('span');
            entries.className = 'dac-entry';
            entries.textContent = (card.entries || []).map((entry) => entry.field + ' = ' + entry.value).join(' AND ') || 'No fields';
            copy.append(title, entries);
            label.append(box, copy);
            conditions.append(label);
        });
        const selectedCount = cards.filter((card) => card.selected !== false).length;
        const selected = document.getElementById('review-selected');
        if (selected) {
            selected.textContent = cards.length
                ? selectedCount + ' of ' + cards.length + ' kept. Unchecked conditions are omitted.'
                : '';
        }

        const diff = document.getElementById('review-diff');
        diff.hidden = false;
        diff.replaceChildren();
        const diffText = String(review.diff || '').trim();
        if (!diffText) {
            const row = document.createElement('div');
            row.textContent = 'No file change yet.';
            diff.append(row);
        } else {
            diffText.split('\n').forEach((line) => {
                const row = document.createElement('div');
                if (line.startsWith('+') && !line.startsWith('+++')) row.className = 'dac-add';
                else if (line.startsWith('-') && !line.startsWith('---')) row.className = 'dac-del';
                row.textContent = line || ' ';
                diff.append(row);
            });
        }

        const open = !review.archived && (review.stage === 'proposed' || review.stage === 'drafted');
        document.getElementById('review-actions').hidden = !open;
        document.getElementById('review-feedback-label').hidden = review.stage !== 'drafted' || review.kind === 'disable';
        document.querySelector('[data-review-action="draft"]').hidden = review.stage !== 'proposed';
        document.querySelector('[data-review-action="revise"]').hidden = review.stage !== 'drafted' || review.kind === 'disable';
        const noneKept = review.kind !== 'disable' && cards.length > 0 && selectedCount === 0;
        this.implementLocked = noneKept;
        const implement = document.querySelector('[data-review-action="implement"]');
        if (implement) implement.disabled = noneKept || this.busy;
        const hint = document.getElementById('review-action-hint');
        if (hint) {
            if (review.stage === 'proposed') hint.textContent = 'Draft spends one model call. The file stays unchanged.';
            else if (review.kind === 'disable') hint.textContent = 'Implement renames the rule file to disabled. The alert stays open.';
            else if (noneKept) hint.textContent = 'Check the conditions to keep. The rule file is unchanged until you implement.';
            else hint.textContent = 'Implement writes only the checked conditions. The alert stays open.';
        }
        this.markActive('review-list', review.id);
        if (detail) detail.scrollTop = scroll;
    }

    async toggleCondition(index, selected) {
        if (!this.review || this.busy) return;
        const exceptions = (this.review.exceptions || []).map((card, cardIndex) => ({
            selected: cardIndex === index ? selected : card.selected !== false,
            allow_wildcard: Boolean(card.allow_wildcard),
        }));
        try {
            const data = await this.request('/api/detections/reviews/' + encodeURIComponent(this.review.id) + '/selection', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ exceptions: exceptions }),
            });
            this.openReview(data.review);
        } catch (error) {
            this.setStatus(error.message, true);
        }
    }

    async onReviewAction(action) {
        if (!this.review || this.busy) return;
        const id = encodeURIComponent(this.review.id);
        this.busy = true;
        this.setBusy(true);
        try {
            let data;
            if (action === 'revise') {
                const feedback = document.getElementById('review-feedback').value;
                data = await this.request('/api/detections/reviews/' + id + '/revise', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ feedback: feedback }),
                });
            } else {
                data = await this.request('/api/detections/reviews/' + id + '/' + action, { method: 'POST' });
            }
            this.openReview(data.review);
            this.setStatus(action === 'implement' ? 'Wrote the rule file. The alert is still open.' : '');
            if (action === 'reject' || action === 'implement') this.loadReviews();
        } catch (error) {
            this.setStatus(error.message, true);
        } finally {
            this.busy = false;
            this.setBusy(false);
        }
    }

    listButton(options) {
        const button = document.createElement('button');
        button.type = 'button';
        if (options.id != null) button.dataset.id = String(options.id);
        if (options.active) button.className = 'active';
        if (options.active) button.setAttribute('aria-current', 'true');
        const title = document.createElement('div');
        title.className = 'dac-card-title';
        title.textContent = options.title || 'Untitled';
        const meta = document.createElement('div');
        meta.className = 'dac-card-meta';
        if (options.badge) {
            const badge = document.createElement('span');
            badge.className = options.badgeClass || this.severityClass(options.badge);
            badge.textContent = options.badge;
            meta.append(badge);
        }
        (options.meta || []).forEach((part) => {
            const span = document.createElement('span');
            span.textContent = part;
            meta.append(span);
        });
        button.append(title, meta);
        button.addEventListener('click', options.onClick);
        return button;
    }

    markActive(listId, id) {
        const host = document.getElementById(listId);
        if (!host || id == null) return;
        const wanted = String(id);
        host.querySelectorAll('button[data-id]').forEach((button) => {
            const on = button.dataset.id === wanted;
            button.classList.toggle('active', on);
            if (on) button.setAttribute('aria-current', 'true');
            else button.removeAttribute('aria-current');
        });
    }

    emptyNote(text) {
        const note = document.createElement('p');
        note.className = 'detections-empty';
        note.textContent = text;
        return note;
    }

    metaLine(parts) {
        const line = document.createElement('p');
        line.className = 'dac-card-meta';
        parts.filter(Boolean).forEach((part) => {
            const span = document.createElement('span');
            span.textContent = part;
            line.append(span);
        });
        return line;
    }

    banner(text, isError) {
        const line = document.createElement('p');
        line.className = isError ? 'detections-error' : 'detections-warning';
        line.textContent = text;
        return line;
    }

    severityClass(value) {
        const key = String(value || '').toLowerCase();
        if (key === 'critical' || key === 'high' || key === 'medium' || key === 'low') return 'dac-sev dac-sev-' + key;
        return 'dac-sev';
    }

    formatTime(value) {
        if (!value) return '';
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) return String(value);
        return date.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    }

    setBusy(isBusy) {
        document.querySelectorAll('[data-detection-action], [data-review-action], #rules-disable, #findings-refresh').forEach((button) => {
            const locked = button.dataset.reviewAction === 'implement' && this.implementLocked;
            button.disabled = isBusy || locked;
            if (button.dataset.detectionAction === 'ask' || button.dataset.reviewAction === 'draft' || button.dataset.reviewAction === 'revise') {
                button.setAttribute('aria-busy', isBusy ? 'true' : 'false');
            }
        });
    }
}
