// Analyst approval-queue (Requests view)

class RequestsManager {
    constructor(controller) {
        this.controller = controller;
        this.requests = [];
        this.catalog = [];
        this.selectedId = null;
        this.selectedIds = new Set();
        this.filter = 'open';
        this.counts = { pending: 0, open: 0, archived: 0, all: 0 };
        this._bound = false;
        this._busy = false;
    }

    bind() {
        if (this._bound) {
            return;
        }
        this._bound = true;
        const pane = document.getElementById('requests-content');
        if (!pane) {
            return;
        }
        pane.addEventListener('click', (event) => {
            const filterBtn = event.target.closest('[data-request-filter]');
            if (filterBtn) {
                this.filter = filterBtn.dataset.requestFilter;
                this.selectedIds.clear();
                this.load();
                return;
            }
            const selectAll = event.target.closest('[data-request-select-all]');
            if (selectAll) {
                this.toggleSelectAll(selectAll.dataset.requestSelectAll === 'actionable');
                return;
            }
            const clearSel = event.target.closest('[data-request-clear-selection]');
            if (clearSel) {
                this.selectedIds.clear();
                this.render();
                return;
            }
            const checkbox = event.target.closest('[data-request-check]');
            if (checkbox) {
                event.stopPropagation();
                return;
            }
            const card = event.target.closest('.request-card');
            if (card) {
                this.selectedId = card.dataset.requestId;
                this.renderDetail();
                this.highlightCards();
            }
        });
        pane.addEventListener('change', (event) => {
            const checkbox = event.target.closest('[data-request-check]');
            if (!checkbox) {
                return;
            }
            event.stopPropagation();
            this.toggleChecked(checkbox.dataset.requestCheck, checkbox.checked);
        });
        pane.addEventListener('click', async (event) => {
            const actionBtn = event.target.closest('[data-request-action]');
            if (!actionBtn || actionBtn.disabled || this._busy) {
                return;
            }
            const action = actionBtn.dataset.requestAction;
            if (action === 'bulk-approve' || action === 'bulk-deny' || action === 'bulk-done') {
                const bulkAction = action === 'bulk-approve'
                    ? 'approve'
                    : action === 'bulk-deny'
                        ? 'deny'
                        : 'acknowledge';
                await this.handleBulk(bulkAction);
                return;
            }
            await this.handleAction(action);
        });
    }

    async load() {
        this.bind();
        const status = this.filter === 'all' ? 'all' : this.filter;
        const [list, catalog] = await Promise.all([
            this.controller.api.listRequests(status),
            this.catalog.length ? Promise.resolve({ actions: this.catalog }) : this.controller.api.getRequestCatalog(),
        ]);
        if (catalog && catalog.actions) {
            this.catalog = catalog.actions;
        }
        if (list && list.success) {
            this.requests = list.requests || [];
            this.counts = list.counts || this.counts;
        }
        const visible = new Set(this.requests.map((item) => item.id));
        this.selectedIds = new Set([...this.selectedIds].filter((id) => visible.has(id)));
        this.updateNavBadge();
        if (this.controller.activeSection === 'requests') {
            this.render();
        }
    }

    async refreshCounts() {
        const data = await this.controller.api.listRequests('open');
        if (data && data.success) {
            this.counts = data.counts || this.counts;
            this.updateNavBadge();
        }
    }

    updateNavBadge() {
        const badge = document.getElementById('nav-requests-count');
        if (!badge) {
            return;
        }
        const pending = Number(this.counts.open || this.counts.pending || 0);
        badge.textContent = String(pending);
        badge.hidden = pending <= 0;
        badge.classList.toggle('has-pending', pending > 0);
    }

    updateHeaderMeta() {
        const label = document.getElementById('requests-pending-label');
        if (!label) {
            return;
        }
        const open = Number(this.counts.open || this.counts.pending || 0);
        const archived = Number(this.counts.archived || 0);
        const selected = this.selectedIds.size;
        if (this.filter === 'archived') {
            label.textContent = selected ? `${selected} selected · ${archived} archived` : `${archived} archived`;
        } else if (this.filter === 'all') {
            label.textContent = selected
                ? `${selected} selected · ${open} open · ${archived} archived`
                : `${open} open · ${archived} archived`;
        } else {
            label.textContent = selected ? `${selected} selected · ${open} open` : `${open} open`;
        }
        const selectBtn = document.querySelector('#requests-content [data-request-select-all]');
        if (selectBtn) {
            selectBtn.hidden = this.filter === 'archived';
        }
    }

    specFor(actionType) {
        return this.catalog.find((item) => item.action_type === actionType) || null;
    }

    selected() {
        return this.requests.find((item) => item.id === this.selectedId) || this.requests[0] || null;
    }

    isInformational(item, spec) {
        return item.status === 'informational' || (spec && spec.execution === 'informational');
    }

    isActionable(item) {
        const spec = this.specFor(item.action_type);
        return item.status === 'pending' && !this.isInformational(item, spec);
    }

    canBulkApprove(item) {
        if (!this.isActionable(item)) {
            return false;
        }
        const spec = this.specFor(item.action_type);
        return !(spec && spec.asks_question);
    }

    canMarkDone(item) {
        return item.status === 'informational';
    }

    toggleChecked(id, checked) {
        if (checked) {
            this.selectedIds.add(id);
        } else {
            this.selectedIds.delete(id);
        }
        this.renderListChrome();
        this.highlightCards();
        this.updateHeaderMeta();
    }

    toggleSelectAll(actionableOnly) {
        const targets = this.requests.filter((item) => {
            if (actionableOnly) {
                return this.isActionable(item) || this.canMarkDone(item);
            }
            return true;
        });
        const ids = targets.map((item) => item.id);
        const allSelected = ids.length > 0 && ids.every((id) => this.selectedIds.has(id));
        if (allSelected) {
            ids.forEach((id) => this.selectedIds.delete(id));
        } else {
            ids.forEach((id) => this.selectedIds.add(id));
        }
        this.render();
    }

    render() {
        const list = document.getElementById('requests-list');
        if (!list) {
            return;
        }
        document.querySelectorAll('[data-request-filter]').forEach((btn) => {
            btn.classList.toggle('active', btn.dataset.requestFilter === this.filter);
        });
        this.renderListChrome();
        this.updateHeaderMeta();
        if (!this.requests.length) {
            const emptyCopy = this.filter === 'archived'
                ? 'No archived requests yet. Approved, denied, failed, and Done informational notes appear here.'
                : this.filter === 'all'
                    ? 'No requests yet. The agent files actions here when it wants your approval, or informational fine-tune / visibility notes.'
                    : 'No open requests. Archived approvals and reviewed notes are hidden — switch to Archived to see them.';
            list.innerHTML = `<div class="requests-empty">${emptyCopy}</div>`;
            this.selectedId = null;
            this.renderDetail();
            return;
        }
        if (this.selectedId && !this.requests.some((item) => item.id === this.selectedId)) {
            this.selectedId = this.requests[0].id;
        }
        if (!this.selectedId) {
            this.selectedId = this.requests[0].id;
        }
        list.innerHTML = this.requests.map((item) => this.cardHtml(item)).join('');
        this.renderDetail();
    }

    renderListChrome() {
        const bar = document.getElementById('requests-bulk-bar');
        if (!bar) {
            return;
        }
        const selected = [...this.selectedIds]
            .map((id) => this.requests.find((item) => item.id === id))
            .filter(Boolean);
        const approveCount = selected.filter((item) => this.canBulkApprove(item)).length;
        const denyCount = selected.filter((item) => this.isActionable(item)).length;
        const doneCount = selected.filter((item) => this.canMarkDone(item)).length;
        const hasSelection = selected.length > 0;
        bar.hidden = !hasSelection;
        if (!hasSelection) {
            return;
        }
        bar.innerHTML = `
            <div class="requests-bulk-summary">
                <strong>${selected.length}</strong> selected
                <span class="requests-bulk-hint">${approveCount} approvable · ${denyCount} deniable · ${doneCount} review notes</span>
            </div>
            <div class="requests-bulk-actions">
                <button type="button" class="btn btn-primary btn-sm" data-request-action="bulk-approve"
                    ${approveCount ? '' : 'disabled'} title="Approve selected closable / response actions">
                    Approve ${approveCount || ''}
                </button>
                <button type="button" class="btn btn-danger btn-sm" data-request-action="bulk-deny"
                    ${denyCount ? '' : 'disabled'} title="Deny selected pending actions">
                    Deny ${denyCount || ''}
                </button>
                <button type="button" class="btn btn-secondary btn-sm" data-request-action="bulk-done"
                    ${doneCount ? '' : 'disabled'} title="Mark informational notes as reviewed">
                    Done ${doneCount || ''}
                </button>
                <button type="button" class="btn btn-secondary btn-sm" data-request-clear-selection>Clear</button>
            </div>
        `;
    }

    highlightCards() {
        document.querySelectorAll('.request-card').forEach((card) => {
            const id = card.dataset.requestId;
            card.classList.toggle('active', id === this.selectedId);
            card.classList.toggle('is-checked', this.selectedIds.has(id));
            const checkbox = card.querySelector('[data-request-check]');
            if (checkbox) {
                checkbox.checked = this.selectedIds.has(id);
            }
        });
    }

    cardHtml(item) {
        const spec = this.specFor(item.action_type);
        const active = item.id === this.selectedId ? ' active' : '';
        const checked = this.selectedIds.has(item.id);
        const cluster = (item.cluster && item.cluster.name) || item.cluster_id || '';
        const title = item.title || (spec && spec.label) || item.action_type;
        const archived = Boolean(item.archived) || ['acknowledged', 'denied', 'executed', 'failed'].includes(item.status);
        return `
            <article class="request-card${active}${checked ? ' is-checked' : ''}${archived ? ' is-archived' : ''}" data-request-id="${escapeHtml(item.id)}">
                <label class="request-card-check" title="Select for bulk actions">
                    <input type="checkbox" data-request-check="${escapeHtml(item.id)}"
                        ${checked ? 'checked' : ''} aria-label="Select request">
                </label>
                <button type="button" class="request-card-body" data-request-id="${escapeHtml(item.id)}">
                    <div class="request-card-title">${escapeHtml(title)}</div>
                    <div class="request-card-meta">
                        <span class="action-badge">${escapeHtml((spec && spec.label) || item.action_type)}</span>
                        <span class="risk-badge risk-${escapeHtml(item.risk || 'medium')}">${escapeHtml(item.risk || 'medium')}</span>
                        <span class="status-badge ${escapeHtml(item.status)}">${escapeHtml(item.status)}</span>
                        ${archived ? '<span class="status-badge archived">archived</span>' : ''}
                        ${cluster ? `<span>${escapeHtml(cluster)}</span>` : ''}
                    </div>
                </button>
            </article>
        `;
    }

    decisionBarHtml(item, spec, pending, informational) {
        if (informational && item.status === 'informational') {
            return `
                <div class="request-decision-bar is-info">
                    <div class="request-decision-copy">
                        <span class="request-decision-label">Informational</span>
                        <span>No approval needed — review only, then mark Done.</span>
                    </div>
                    <div class="request-actions">
                        <button type="button" class="btn btn-primary" data-request-action="done">Done</button>
                    </div>
                    <textarea id="request-comment" class="command-input request-comment" rows="2"
                        placeholder="Optional note (kept on the audit trail)"></textarea>
                </div>
            `;
        }
        if (!pending) {
            return `
                <div class="request-decision-bar is-settled">
                    <div class="request-decision-copy">
                        <span class="request-decision-label">Status</span>
                        <span class="status-badge ${escapeHtml(item.status)}">${escapeHtml(item.status)}</span>
                    </div>
                </div>
            `;
        }
        const comment = `
            <textarea id="request-comment" class="command-input request-comment" rows="2"
                placeholder="Optional comment for the audit trail"></textarea>
        `;
        let buttons = '';
        if (spec && spec.asks_question) {
            buttons = `
                <button type="button" class="btn btn-primary" data-request-action="yes">Yes — run follow-up</button>
                <button type="button" class="btn btn-danger" data-request-action="no">No — run follow-up</button>
                <button type="button" class="btn btn-secondary" data-request-action="deny">Dismiss</button>
            `;
        } else {
            buttons = `
                <button type="button" class="btn btn-primary" data-request-action="approve">Approve and run</button>
                <button type="button" class="btn btn-danger" data-request-action="deny">Deny</button>
            `;
        }
        return `
            <div class="request-decision-bar">
                <div class="request-decision-copy">
                    <span class="request-decision-label">Decision</span>
                    <span>Review the details below, then approve or deny.</span>
                </div>
                <div class="request-actions">${buttons}</div>
                ${comment}
            </div>
        `;
    }

    renderDetail() {
        const root = document.getElementById('requests-detail');
        if (!root) {
            return;
        }
        const item = this.selected();
        if (!item) {
            root.innerHTML = '<div class="requests-detail-empty">Select a request to review it.</div>';
            return;
        }
        const spec = this.specFor(item.action_type);
        const informational = this.isInformational(item, spec);
        const pending = item.status === 'pending' && !informational;
        const payload = item.payload || {};
        const followUps = item.follow_ups || {};
        const followHtml = Object.keys(followUps).length
            ? `<div class="request-section-label">If you answer</div>
               <div class="request-followups">${Object.entries(followUps).map(([answer, plan]) => `
                    <div class="request-followup">
                        <strong>${escapeHtml(answer.toUpperCase())}: ${escapeHtml(plan.label || plan.action_type)}</strong>
                        ${escapeHtml(plan.summary || '')}
                    </div>`).join('')}
               </div>`
            : '';
        const questionHtml = item.question
            ? `<div class="request-section-label">Question</div><div class="request-question">${escapeHtml(item.question)}</div>`
            : '';
        const cluster = (item.cluster && item.cluster.name) || item.cluster_id || 'default cluster';
        const resultHtml = item.execution_result
            ? `<div class="request-section-label">Result</div><pre class="request-result">${escapeHtml(JSON.stringify(item.execution_result, null, 2))}</pre>`
            : '';
        const errorHtml = item.error
            ? `<p class="settings-status is-error">${escapeHtml(item.error)}</p>`
            : '';
        const banner = informational && item.status === 'informational'
            ? '<div class="request-info-banner">Informational only — nothing is executed. Mark <strong>Done</strong> when you have reviewed it.</div>'
            : '';
        root.innerHTML = `
            ${this.decisionBarHtml(item, spec, pending, informational)}
            <div class="request-detail-body">
                <div class="request-card-meta">
                    <span class="action-badge">${escapeHtml((spec && spec.label) || item.action_type)}</span>
                    <span class="risk-badge risk-${escapeHtml(item.risk || 'medium')}">${escapeHtml(item.risk || 'medium')}</span>
                    <span class="status-badge ${escapeHtml(item.status)}">${escapeHtml(item.status)}</span>
                    <span>${escapeHtml(cluster)}</span>
                </div>
                <h3 class="request-detail-title">${escapeHtml(item.title)}</h3>
                <div class="request-detail-summary">${escapeHtml(item.summary || '')}</div>
                ${banner}
                ${questionHtml}
                <div class="request-section-label">Why</div>
                <div class="request-detail-rationale">${escapeHtml(item.rationale || 'No extra investigation notes.')}</div>
                ${this.detailBodyHtml(item, spec, payload)}
                ${followHtml}
                ${errorHtml}
                ${resultHtml}
            </div>
        `;
        this.highlightCards();
    }

    detailBodyHtml(item, spec, payload) {
        if (this.isInformational(item, spec)) {
            return this.informationalBodyHtml(payload);
        }
        const skip = new Set([
            'alert', 'rule', 'coverage_check', 'rule_found', 'suggestion', 'description',
        ]);
        const payloadRows = Object.keys(payload).length
            ? Object.entries(payload)
                .filter(([key, value]) => !skip.has(key) && value != null && value !== '')
                .map(([key, value]) => {
                    const label = this.fieldLabel(spec, key);
                    return `<dt>${escapeHtml(label)}</dt><dd>${escapeHtml(this.formatValue(value))}</dd>`;
                }).join('')
            : '';
        return `
            ${this.alertHtml(payload.alert)}
            ${payloadRows ? `<div class="request-section-label">Action parameters</div><dl class="request-payload">${payloadRows}</dl>` : ''}
        `;
    }

    alertHtml(alert) {
        if (!alert || typeof alert !== 'object') {
            return '';
        }
        const entities = Array.isArray(alert.related_entities) ? alert.related_entities : [];
        const events = Array.isArray(alert.events) ? alert.events : [];
        const comments = Array.isArray(alert.comments) ? alert.comments : [];
        const meta = [
            alert.severity ? `severity ${alert.severity}` : '',
            alert.status ? `status ${alert.status}` : '',
            alert.verdict ? `verdict ${alert.verdict}` : '',
            alert.created_at ? `at ${alert.created_at}` : '',
        ].filter(Boolean);
        const entityHtml = entities.length
            ? `<div class="request-rule-meta">${entities.map((item) => `<span class="action-badge">${escapeHtml(String(item))}</span>`).join('')}</div>`
            : '';
        const eventHtml = events.length
            ? `<div class="request-section-label">Triggering events</div>
               <ul class="request-coverage-hits">${events.map((event) => {
                    if (!event || typeof event !== 'object') {
                        return `<li>${escapeHtml(String(event))}</li>`;
                    }
                    const bits = [event.timestamp, event.host, event.username, event.process_name, event.message]
                        .filter(Boolean).map(String);
                    return `<li>${escapeHtml(bits.join(' · '))}</li>`;
               }).join('')}</ul>`
            : '';
        const commentHtml = comments.length
            ? `<div class="request-section-label">Alert comments</div>
               <ul class="request-coverage-hits">${comments.map((comment) => {
                    if (!comment || typeof comment !== 'object') {
                        return `<li>${escapeHtml(String(comment))}</li>`;
                    }
                    return `<li><strong>${escapeHtml(String(comment.author || 'unknown'))}</strong>
                        ${comment.timestamp ? escapeHtml(String(comment.timestamp)) + ': ' : ''}
                        ${escapeHtml(String(comment.comment || ''))}</li>`;
               }).join('')}</ul>`
            : '';
        return `
            <div class="request-section-label">Alert context</div>
            <div class="request-rule">
                <div class="request-rule-name">${escapeHtml(alert.title || alert.id || 'Alert')}</div>
                <div class="request-rule-meta">
                    ${alert.id ? `<span>id ${escapeHtml(String(alert.id))}</span>` : ''}
                    ${meta.map((item) => `<span>${escapeHtml(item)}</span>`).join('')}
                </div>
                ${alert.description ? `<p class="request-detail-rationale">${escapeHtml(String(alert.description))}</p>` : ''}
                ${entityHtml}
            </div>
            ${eventHtml}
            ${commentHtml}
        `;
    }

    informationalBodyHtml(payload) {
        const suggestion = payload.suggestion || payload.description || '';
        const rule = payload.rule;
        const coverage = payload.coverage_check;
        const skip = new Set(['suggestion', 'rule', 'coverage_check', 'rule_found', 'description', 'alert']);
        const extras = Object.entries(payload).filter(([key, value]) => !skip.has(key) && value != null && value !== '');
        const extraRows = extras.length
            ? extras.map(([key, value]) => `<dt>${escapeHtml(key)}</dt><dd>${escapeHtml(this.formatValue(value))}</dd>`).join('')
            : '';
        return `
            ${suggestion ? `<div class="request-section-label">Suggestion</div><pre class="request-suggestion">${escapeHtml(suggestion)}</pre>` : ''}
            ${this.alertHtml(payload.alert)}
            ${this.ruleHtml(rule)}
            ${this.coverageHtml(coverage)}
            ${extraRows ? `<div class="request-section-label">Details</div><dl class="request-payload">${extraRows}</dl>` : ''}
        `;
    }

    ruleHtml(rule) {
        if (!rule || typeof rule !== 'object') {
            return '';
        }
        if (rule.found === false) {
            return `<div class="request-section-label">Home Lab rule</div><p class="request-detail-summary">${escapeHtml(rule.message || 'No matching rule found.')}</p>`;
        }
        const query = rule.query
            ? `<pre class="request-rule-query">${escapeHtml(String(rule.query))}</pre>`
            : '';
        const tags = Array.isArray(rule.tags) && rule.tags.length
            ? `<div class="request-rule-meta">${rule.tags.map((tag) => `<span class="action-badge">${escapeHtml(String(tag))}</span>`).join('')}</div>`
            : '';
        return `
            <div class="request-section-label">Home Lab rule</div>
            <div class="request-rule">
                <div class="request-rule-name">${escapeHtml(rule.name || 'Unnamed rule')}</div>
                <div class="request-rule-meta">
                    ${rule.rule_id ? `<span>id ${escapeHtml(String(rule.rule_id))}</span>` : ''}
                    ${rule.language ? `<span>${escapeHtml(String(rule.language))}</span>` : ''}
                    ${rule.enabled === false ? '<span>disabled</span>' : ''}
                </div>
                ${rule.description ? `<p class="request-detail-rationale">${escapeHtml(String(rule.description))}</p>` : ''}
                ${tags}
                ${query}
            </div>
        `;
    }

    coverageHtml(check) {
        if (!check || typeof check !== 'object') {
            return '';
        }
        const verdict = check.likely_gap
            ? 'Likely a real gap — no strong match in the Home Lab catalog.'
            : 'May already be covered by an existing Home Lab rule.';
        const hits = Array.isArray(check.matching_rules) ? check.matching_rules : [];
        const hitRows = hits.length
            ? `<ul class="request-coverage-hits">${hits.map((hit) => `
                <li><strong>${escapeHtml(hit.name || hit.rule_id || 'rule')}</strong>
                ${hit.score != null ? ` (score ${escapeHtml(String(hit.score))})` : ''}
                ${hit.query_excerpt ? `<pre class="request-rule-query">${escapeHtml(String(hit.query_excerpt))}</pre>` : ''}
                </li>`).join('')}</ul>`
            : '<p class="request-detail-summary">No catalog hits for this description.</p>';
        return `
            <div class="request-section-label">Coverage check</div>
            <p class="request-detail-summary">${escapeHtml(verdict)}</p>
            ${hitRows}
        `;
    }

    fieldLabel(spec, key) {
        const field = spec && spec.fields && spec.fields.find((item) => item.name === key);
        return (field && field.label) || key;
    }

    formatValue(value) {
        if (value == null || value === '') {
            return '—';
        }
        if (typeof value === 'object') {
            try {
                return JSON.stringify(value, null, 2);
            } catch (err) {
                return String(value);
            }
        }
        return String(value);
    }

    comment() {
        const el = document.getElementById('request-comment');
        return el ? el.value.trim() : '';
    }

    async handleAction(action) {
        const item = this.selected();
        if (!item) {
            return;
        }
        const comment = this.comment();
        this._busy = true;
        let result;
        try {
            if (action === 'approve') {
                result = await this.controller.api.approveRequest(item.id, comment);
            } else if (action === 'deny') {
                result = await this.controller.api.denyRequest(item.id, comment);
            } else if (action === 'done') {
                result = await this.controller.api.acknowledgeRequest(item.id, comment);
            } else if (action === 'yes' || action === 'no') {
                result = await this.controller.api.answerRequest(item.id, action, comment);
            } else {
                return;
            }
        } finally {
            this._busy = false;
        }
        if (!result || !result.success) {
            if (window.toast) {
                window.toast.error((result && (result.error || result.detail)) || 'Could not update request', { key: 'requests' });
            }
            return;
        }
        const updated = result.request;
        if (window.toast) {
            const status = updated && updated.status;
            if (status === 'executed') {
                window.toast.success('Request completed.', { key: 'requests' });
            } else if (status === 'acknowledged') {
                window.toast.success('Marked as done.', { key: 'requests' });
            } else if (status === 'awaiting_integration') {
                window.toast.info('Approved. Waiting on a connected API to finish this action.', { key: 'requests' });
            } else if (status === 'denied') {
                window.toast.info('Request denied.', { key: 'requests' });
            } else if (status === 'failed') {
                window.toast.error(updated.error || 'Request failed during execution.', { key: 'requests' });
            } else {
                window.toast.success('Request updated.', { key: 'requests' });
            }
        }
        this.selectedIds.delete(item.id);
        await this.load();
        this.selectedId = updated && updated.id ? updated.id : item.id;
        this.render();
    }

    async handleBulk(action) {
        const selected = [...this.selectedIds]
            .map((id) => this.requests.find((item) => item.id === id))
            .filter(Boolean);
        let ids;
        let label;
        if (action === 'approve') {
            ids = selected.filter((item) => this.canBulkApprove(item)).map((item) => item.id);
            label = 'approve';
        } else if (action === 'deny') {
            ids = selected.filter((item) => this.isActionable(item)).map((item) => item.id);
            label = 'deny';
        } else {
            ids = selected.filter((item) => this.canMarkDone(item)).map((item) => item.id);
            label = 'mark done';
        }
        if (!ids.length) {
            if (window.toast) {
                const emptyMsg = action === 'approve'
                    ? 'No selected items can be bulk-approved (identity questions need a yes/no).'
                    : action === 'deny'
                        ? 'No selected pending items to deny.'
                        : 'No selected informational notes to mark Done.';
                window.toast.info(emptyMsg, { key: 'requests' });
            }
            return;
        }
        const ok = window.confirm(
            action === 'acknowledge' || action === 'done'
                ? `Mark ${ids.length} informational note${ids.length === 1 ? '' : 's'} as Done?`
                : `${label.charAt(0).toUpperCase() + label.slice(1)} ${ids.length} request${ids.length === 1 ? '' : 's'}?`,
        );
        if (!ok) {
            return;
        }
        this._busy = true;
        let result;
        try {
            result = await this.controller.api.bulkRequests(action, ids, this.comment());
        } finally {
            this._busy = false;
        }
        if (!result || !result.success) {
            if (window.toast) {
                window.toast.error((result && (result.error || result.detail)) || 'Bulk action failed', { key: 'requests' });
            }
            return;
        }
        const succeeded = Number(result.succeeded || 0);
        const skipped = Number(result.skipped || 0);
        const failed = Number(result.failed || 0);
        if (window.toast) {
            const verb = action === 'acknowledge' ? 'marked done' : `${label}d`;
            const parts = [`${succeeded} ${verb}`];
            if (skipped) {
                parts.push(`${skipped} skipped`);
            }
            if (failed) {
                parts.push(`${failed} failed`);
            }
            if (failed) {
                window.toast.error(parts.join(' · '), { key: 'requests' });
            } else {
                window.toast.success(parts.join(' · '), { key: 'requests' });
            }
        }
        this.selectedIds.clear();
        await this.load();
    }
}
