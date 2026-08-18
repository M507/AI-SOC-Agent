// Analyst approval-queue (Requests view)

class RequestsManager {
    constructor(controller) {
        this.controller = controller;
        this.requests = [];
        this.catalog = [];
        this.selectedId = null;
        this.filter = 'pending';
        this.counts = { pending: 0, all: 0 };
        this._bound = false;
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
                this.load();
                return;
            }
            const card = event.target.closest('[data-request-id]');
            if (card && card.matches('.request-card')) {
                this.selectedId = card.dataset.requestId;
                this.renderDetail();
                this.highlightCards();
            }
        });
        pane.addEventListener('click', async (event) => {
            const actionBtn = event.target.closest('[data-request-action]');
            if (!actionBtn || actionBtn.disabled) {
                return;
            }
            await this.handleAction(actionBtn.dataset.requestAction);
        });
    }

    async load() {
        this.bind();
        const status = this.filter === 'pending' ? 'pending' : null;
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
        this.updateNavBadge();
        if (this.controller.activeSection === 'requests') {
            this.render();
        }
    }

    async refreshCounts() {
        const data = await this.controller.api.listRequests('pending');
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
        const pending = Number(this.counts.pending || 0);
        badge.textContent = String(pending);
        badge.hidden = pending <= 0;
        badge.classList.toggle('has-pending', pending > 0);
    }

    specFor(actionType) {
        return this.catalog.find((item) => item.action_type === actionType) || null;
    }

    selected() {
        return this.requests.find((item) => item.id === this.selectedId) || this.requests[0] || null;
    }

    render() {
        const list = document.getElementById('requests-list');
        if (!list) {
            return;
        }
        document.querySelectorAll('[data-request-filter]').forEach((btn) => {
            btn.classList.toggle('active', btn.dataset.requestFilter === this.filter);
        });
        if (!this.requests.length) {
            list.innerHTML = `<div class="requests-empty">No ${this.filter === 'pending' ? 'pending' : ''} requests. The agent files actions here when it wants your approval to close an alert, isolate a host, or ask “is this you?”.</div>`;
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

    highlightCards() {
        document.querySelectorAll('.request-card').forEach((card) => {
            card.classList.toggle('active', card.dataset.requestId === this.selectedId);
        });
    }

    cardHtml(item) {
        const spec = this.specFor(item.action_type);
        const active = item.id === this.selectedId ? ' active' : '';
        const cluster = (item.cluster && item.cluster.name) || item.cluster_id || '';
        return `
            <button type="button" class="request-card${active}" data-request-id="${escapeHtml(item.id)}">
                <div class="request-card-title">${escapeHtml(item.title || spec && spec.label || item.action_type)}</div>
                <div class="request-card-meta">
                    <span class="action-badge">${escapeHtml((spec && spec.label) || item.action_type)}</span>
                    <span class="risk-badge risk-${escapeHtml(item.risk || 'medium')}">${escapeHtml(item.risk || 'medium')}</span>
                    <span class="status-badge ${escapeHtml(item.status)}">${escapeHtml(item.status)}</span>
                    ${cluster ? `<span>${escapeHtml(cluster)}</span>` : ''}
                </div>
            </button>
        `;
    }

    renderDetail() {
        const root = document.getElementById('requests-detail');
        if (!root) {
            return;
        }
        const item = this.selected();
        if (!item) {
            root.innerHTML = '<div class="requests-detail-empty">Select a request to review the payload and approve or deny it.</div>';
            return;
        }
        const spec = this.specFor(item.action_type);
        const pending = item.status === 'pending';
        const payload = item.payload || {};
        const payloadRows = Object.keys(payload).length
            ? Object.entries(payload).map(([key, value]) => {
                const label = this.fieldLabel(spec, key);
                return `<dt>${escapeHtml(label)}</dt><dd>${escapeHtml(this.formatValue(value))}</dd>`;
            }).join('')
            : '<dt>None</dt><dd>No extra payload fields.</dd>';
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
        const commentHtml = pending
            ? `<textarea id="request-comment" class="command-input request-comment" placeholder="Optional comment for the audit trail"></textarea>`
            : '';
        let buttons = '';
        if (pending && spec && spec.asks_question) {
            buttons = `
                <button type="button" class="btn btn-primary" data-request-action="yes">Yes — run follow-up</button>
                <button type="button" class="btn btn-danger" data-request-action="no">No — run follow-up</button>
                <button type="button" class="btn btn-secondary" data-request-action="deny">Dismiss</button>
            `;
        } else if (pending) {
            buttons = `
                <button type="button" class="btn btn-primary" data-request-action="approve">Approve and run</button>
                <button type="button" class="btn btn-danger" data-request-action="deny">Deny</button>
            `;
        }
        root.innerHTML = `
            <div class="request-card-meta">
                <span class="action-badge">${escapeHtml((spec && spec.label) || item.action_type)}</span>
                <span class="risk-badge risk-${escapeHtml(item.risk || 'medium')}">${escapeHtml(item.risk || 'medium')}</span>
                <span class="status-badge ${escapeHtml(item.status)}">${escapeHtml(item.status)}</span>
                <span>${escapeHtml(cluster)}</span>
            </div>
            <h3 class="request-detail-title">${escapeHtml(item.title)}</h3>
            <div class="request-detail-summary">${escapeHtml(item.summary || '')}</div>
            ${questionHtml}
            <div class="request-section-label">Why</div>
            <div class="request-detail-rationale">${escapeHtml(item.rationale || 'No extra investigation notes.')}</div>
            <div class="request-section-label">Payload (used when you approve)</div>
            <dl class="request-payload">${payloadRows}</dl>
            ${followHtml}
            ${errorHtml}
            ${resultHtml}
            ${commentHtml}
            <div class="request-actions">${buttons}</div>
        `;
        this.highlightCards();
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
            return JSON.stringify(value);
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
        let result;
        if (action === 'approve') {
            result = await this.controller.api.approveRequest(item.id, comment);
        } else if (action === 'deny') {
            result = await this.controller.api.denyRequest(item.id, comment);
        } else if (action === 'yes' || action === 'no') {
            result = await this.controller.api.answerRequest(item.id, action, comment);
        } else {
            return;
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
        await this.load();
        this.selectedId = updated && updated.id ? updated.id : item.id;
        this.render();
    }
}
