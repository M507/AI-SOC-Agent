// Analyst approval-queue (Requests view)

const REQUEST_STATUS_LABELS = {
    pending: 'Needs approval',
    informational: 'Review note',
    acknowledged: 'Done',
    denied: 'Denied',
    executed: 'Done',
    failed: 'Failed',
    awaiting_integration: 'Waiting on integration',
};

const DETECTION_CATEGORIES = new Set(['detections', 'runbooks']);
const SOC_CATEGORIES = new Set(['siem', 'identity', 'edr', 'case', 'iam', 'email', 'network']);
const ENG_ACTION_TYPES = new Set(['fine_tune', 'visibility', 'runbook_gap']);
const REQUESTS_POLL_MS = 15000;

class RequestsManager {
    constructor(controller) {
        this.controller = controller;
        this.items = [];
        this.requests = [];
        this.catalog = [];
        this.selectedId = null;
        this.selectedIds = new Set();
        this.filter = 'open';
        this.queueTab = 'all';
        this.counts = { pending: 0, open: 0, archived: 0, all: 0, actionable: 0 };
        this.tabCounts = { open: 0, archived: 0, all: 0 };
        this.queueCounts = {};
        this.generation = 0;
        this.receipt = null;
        this._bound = false;
        this._inFlight = new Set();
        this._optimisticById = new Map();
        this._rollbackById = new Map();
        this._clickLockUntil = 0;
        this._savedDetailComment = '';
        this._savedBulkComment = '';
        this._skipDetailRebuild = false;
        this._loadSeq = 0;
        this._fullById = {};
        this._pollTimer = null;
        this._externalRefreshing = false;
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
                this.receipt = null;
                this.load();
                return;
            }
            const selectAll = event.target.closest('[data-request-select-all]');
            if (selectAll) {
                this.toggleSelectAll(selectAll.dataset.requestSelectAll === 'actionable');
                return;
            }
            const refreshBtn = event.target.closest('[data-request-refresh]');
            if (refreshBtn) {
                this.refreshFromTickets();
                return;
            }
            const clearSel = event.target.closest('[data-request-clear-selection]');
            if (clearSel) {
                this.selectedIds.clear();
                this.render();
                return;
            }
            const nextBtn = event.target.closest('[data-request-next]');
            if (nextBtn) {
                this.openNext(nextBtn.dataset.requestNext || null);
                return;
            }
            const childLink = event.target.closest('[data-request-open]');
            if (childLink) {
                this.selectCard(childLink.dataset.requestOpen);
                return;
            }
            const checkbox = event.target.closest('[data-request-check]');
            if (checkbox) {
                event.stopPropagation();
                return;
            }
            const card = event.target.closest('.request-card');
            if (card) {
                this.selectCard(card.dataset.requestId);
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
        pane.addEventListener('click', (event) => {
            const actionBtn = event.target.closest('[data-request-action]');
            if (!actionBtn || actionBtn.disabled) {
                return;
            }
            if (Date.now() < this._clickLockUntil) {
                return;
            }
            const action = actionBtn.dataset.requestAction;
            if (action === 'bulk-approve' || action === 'bulk-deny' || action === 'bulk-done' || action === 'bulk-ignore') {
                const bulkAction = action === 'bulk-approve'
                    ? 'approve'
                    : action === 'bulk-deny'
                        ? 'deny'
                        : action === 'bulk-ignore'
                            ? 'ignore'
                            : 'acknowledge';
                this.handleBulk(bulkAction);
                return;
            }
            this.handleAction(action);
        });
    }

    setQueueTab(queue) {
        const next = (queue || 'all').toLowerCase();
        if (this.queueTab === next) {
            this.syncQueueTabs();
            return;
        }
        this.queueTab = next;
        this.selectedIds.clear();
        this.receipt = null;
        this.syncQueueTabs();
        this.applyQueueFilter();
        this.render();
        if (this.selectedId) {
            this.ensureFull(this.selectedId).then((full) => {
                if (full && this.selectedId === full.id) {
                    this.renderDetail();
                }
            });
        }
    }

    syncQueueTabs() {
        document.querySelectorAll('#requests-tabs [data-request-queue]').forEach((tab) => {
            tab.classList.toggle('active', tab.dataset.requestQueue === this.queueTab);
        });
    }

    captureDrafts() {
        const detail = document.getElementById('request-comment');
        const bulk = document.getElementById('request-bulk-comment');
        const active = document.activeElement;
        this._savedDetailComment = detail ? detail.value : '';
        this._savedBulkComment = bulk ? bulk.value : '';
        this._skipDetailRebuild = Boolean(
            this.selectedId
            && (
                (active && (active.id === 'request-comment' || active.id === 'request-bulk-comment'))
                || this._savedDetailComment
            )
        );
    }

    restoreDrafts() {
        const bulk = document.getElementById('request-bulk-comment');
        if (bulk && this._savedBulkComment) {
            bulk.value = this._savedBulkComment;
        }
        if (this._skipDetailRebuild) {
            return;
        }
        const detail = document.getElementById('request-comment');
        if (detail && this._savedDetailComment) {
            detail.value = this._savedDetailComment;
        }
    }

    async refreshFromTickets() {
        await this.refreshExternal({ quiet: false });
    }

    async refreshExternal(options) {
        const quiet = Boolean(options && options.quiet);
        if (this._externalRefreshing) {
            return null;
        }
        this._externalRefreshing = true;
        const button = document.getElementById('requests-refresh-btn');
        if (button && !quiet) {
            button.disabled = true;
            button.textContent = 'Refreshing…';
        }
        if (!quiet && window.toast) {
            window.toast.info('Checking linked tickets…', { key: 'requests-sync', duration: 0 });
        }
        let result = null;
        try {
            result = await this.controller.api.syncRequests();
            await this.load();
        } finally {
            this._externalRefreshing = false;
            if (button) {
                button.disabled = false;
                button.textContent = 'Refresh';
            }
        }
        if (quiet) {
            return result;
        }
        const message = (result && result.message) || 'Could not sync linked tickets.';
        if (window.toast) {
            const closed = Number((result && result.closed) || 0);
            const errors = Number((result && result.errors) || 0);
            if (!result || !result.success) {
                window.toast.error(message, { key: 'requests-sync' });
            } else if (closed > 0) {
                window.toast.success(message, { key: 'requests-sync' });
            } else if (errors > 0) {
                window.toast.error(message, { key: 'requests-sync' });
            } else {
                window.toast.info(message, { key: 'requests-sync' });
            }
        }
        return result;
    }

    show(options) {
        const justOpened = Boolean(options && options.justOpened);
        this.startLocalPoll();
        const painted = this.load();
        if (justOpened) {
            painted.then(() => this.refreshExternal({ quiet: true }));
        }
    }

    hide() {
        this.stopLocalPoll();
    }

    startLocalPoll() {
        this.stopLocalPoll();
        this._pollTimer = setInterval(() => {
            this.pollSummary();
        }, REQUESTS_POLL_MS);
    }

    stopLocalPoll() {
        if (this._pollTimer) {
            clearInterval(this._pollTimer);
            this._pollTimer = null;
        }
    }

    async pollSummary() {
        if (this._externalRefreshing) {
            return;
        }
        const data = await this.controller.api.getRequestsSummary();
        if (!data || !data.success) {
            return;
        }
        this.counts = data.counts || this.counts;
        if (data.queue_counts) {
            this.queueCounts = data.queue_counts;
            this.tabCounts = data.queue_counts[this.queueTab] || this.tabCounts;
        }
        this.updateNavBadge();
        this.updateHeaderMeta();
        if (typeof data.generation === 'number' && data.generation !== this.generation) {
            await this.load();
        }
    }

    matchesQueue(item, queue) {
        const key = (queue || this.queueTab || 'all').toLowerCase();
        if (key === 'all' || key === '' || key === 'pending') {
            return true;
        }
        const category = item && item.category;
        if (key === 'soc') {
            return SOC_CATEGORIES.has(category);
        }
        if (key === 'detection' || key === 'detections' || key === 'detection_engineering') {
            return DETECTION_CATEGORIES.has(category);
        }
        if (key === 'engineering' || key === 'eng') {
            return Boolean(this.githubIssue(item));
        }
        return true;
    }

    applyQueueFilter() {
        this.requests = this.items.filter((item) => this.matchesQueue(item, this.queueTab));
        if (this.queueCounts && this.queueCounts[this.queueTab]) {
            this.tabCounts = this.queueCounts[this.queueTab];
        }
        const visible = new Set(this.requests.map((item) => item.id));
        this.selectedIds = new Set([...this.selectedIds].filter((id) => visible.has(id)));
    }

    async selectCard(id) {
        this.selectedId = id;
        this.receipt = null;
        this.highlightCards();
        await this.ensureFull(id);
        if (this.selectedId !== id) {
            return;
        }
        this.renderDetail();
    }

    async ensureFull(id) {
        if (!id) {
            return null;
        }
        const cached = this._fullById[id];
        if (cached && cached._generation === this.generation) {
            return cached;
        }
        const data = await this.controller.api.getRequest(id);
        if (!data || !data.success || !data.request) {
            return cached || null;
        }
        const full = { ...data.request, _full: true, _generation: this.generation };
        this._fullById[id] = full;
        const index = this.items.findIndex((item) => item.id === id);
        if (index >= 0) {
            this.items[index] = { ...this.items[index], ...full };
            this.applyQueueFilter();
        }
        return full;
    }

    async load() {
        this.bind();
        this.captureDrafts();
        const seq = ++this._loadSeq;
        const status = this.filter === 'all' ? 'all' : this.filter;
        const [list, catalog] = await Promise.all([
            this.controller.api.listRequests(status),
            this.catalog.length ? Promise.resolve({ actions: this.catalog }) : this.controller.api.getRequestCatalog(),
        ]);
        if (seq !== this._loadSeq) {
            return;
        }
        if (catalog && catalog.actions) {
            this.catalog = catalog.actions;
        }
        if (list && list.success) {
            this.items = this.applyOptimistic(list.requests || []);
            this.counts = list.counts || this.counts;
            this.queueCounts = list.queue_counts || this.queueCounts;
            this.tabCounts = (this.queueCounts && this.queueCounts[this.queueTab]) || list.tab_counts || this.tabCounts;
            if (typeof list.generation === 'number') {
                this.generation = list.generation;
            }
            const keepFull = {};
            this._inFlight.forEach((id) => {
                if (this._fullById[id]) {
                    keepFull[id] = this._fullById[id];
                }
            });
            this._fullById = keepFull;
        }
        this.applyQueueFilter();
        this.updateNavBadge();
        this.syncQueueTabs();
        if (this.controller.activeSection === 'requests') {
            this.render();
            if (this.selectedId) {
                await this.ensureFull(this.selectedId);
                if (seq !== this._loadSeq) {
                    return;
                }
                if (!this._skipDetailRebuild) {
                    this.renderDetail();
                }
            }
        }
    }

    async refreshCounts() {
        const data = await this.controller.api.getRequestsSummary();
        if (data && data.success) {
            this.counts = data.counts || this.counts;
            if (data.queue_counts) {
                this.queueCounts = data.queue_counts;
                this.tabCounts = data.queue_counts[this.queueTab] || this.tabCounts;
            }
            if (typeof data.generation === 'number') {
                this.generation = data.generation;
            }
            this.updateNavBadge();
        }
    }

    updateNavBadge() {
        const badge = document.getElementById('nav-requests-count');
        if (!badge) {
            return;
        }
        const pending = Number(this.counts.actionable || 0);
        badge.textContent = String(pending);
        badge.hidden = pending <= 0;
        badge.classList.toggle('has-pending', pending > 0);
    }

    updateHeaderMeta() {
        const label = document.getElementById('requests-pending-label');
        if (!label) {
            return;
        }
        const open = Number(this.tabCounts.open || 0);
        const archived = Number(this.tabCounts.archived || 0);
        const selected = this.selectedIds.size;
        const tabName = this.queueLabel();
        if (this.filter === 'archived') {
            label.textContent = selected
                ? `${selected} selected · ${archived} archived · ${tabName}`
                : `${archived} archived · ${tabName}`;
        } else if (this.filter === 'all') {
            label.textContent = selected
                ? `${selected} selected · ${open} open · ${archived} archived · ${tabName}`
                : `${open} open · ${archived} archived · ${tabName}`;
        } else {
            label.textContent = selected
                ? `${selected} selected · ${open} open · ${tabName}`
                : `${open} open · ${tabName}`;
        }
        const selectBtn = document.querySelector('#requests-content [data-request-select-all]');
        if (selectBtn) {
            selectBtn.hidden = this.filter === 'archived';
        }
        document.querySelectorAll('[data-request-filter]').forEach((btn) => {
            const key = btn.dataset.requestFilter;
            const count = Number((this.tabCounts && this.tabCounts[key]) || 0);
            const name = key === 'open' ? 'Open' : key === 'archived' ? 'Archived' : 'All';
            btn.textContent = `${name} (${count})`;
            btn.classList.toggle('active', key === this.filter);
        });
    }

    queueLabel() {
        if (this.queueTab === 'soc') {
            return 'SOC';
        }
        if (this.queueTab === 'engineering') {
            return 'Engineering';
        }
        if (this.queueTab === 'detection') {
            return 'Detection engineering';
        }
        return 'All';
    }

    specFor(actionType) {
        return this.catalog.find((item) => item.action_type === actionType) || null;
    }

    requestAlertIds(item) {
        const ids = new Set();
        if (item && item.alert_id) {
            ids.add(String(item.alert_id));
        }
        const payload = (item && item.payload) || {};
        [payload.alert_id, payload.alertId].forEach((value) => {
            if (value) {
                ids.add(String(value));
            }
        });
        const alert = payload.alert;
        if (alert && typeof alert === 'object') {
            [alert.id, alert.alert_id, alert.alertId].forEach((value) => {
                if (value) {
                    ids.add(String(value));
                }
            });
        }
        return ids;
    }

    associatedPendingNotes(item) {
        if (!item || (item.action_type !== 'close_alert' && item.action_type !== 'identity_verify')) {
            return [];
        }
        const wanted = this.requestAlertIds(item);
        if (!wanted.size) {
            return [];
        }
        return this.requests.filter((other) => {
            if (other.action_type !== 'add_alert_note' || other.status !== 'pending') {
                return false;
            }
            const noteIds = this.requestAlertIds(other);
            let overlap = false;
            wanted.forEach((id) => {
                if (noteIds.has(id)) {
                    overlap = true;
                }
            });
            if (!overlap) {
                return false;
            }
            return !item.cluster_id || !other.cluster_id || item.cluster_id === other.cluster_id;
        });
    }

    selected() {
        if (this.receipt && this.receipt.item && this.receipt.item.id === this.selectedId) {
            return this.receipt.item;
        }
        const base = this.requests.find((item) => item.id === this.selectedId) || this.requests[0] || null;
        if (!base) {
            return null;
        }
        return this._fullById[base.id] || base;
    }

    isInformational(item, spec) {
        return item.status === 'informational' || (spec && spec.execution === 'informational');
    }

    isActionable(item) {
        const spec = this.specFor(item.action_type);
        return item.status === 'pending' && !this.isInformational(item, spec);
    }

    isEngNote(item) {
        if (!item) {
            return false;
        }
        if (this.githubIssue(item)) {
            return true;
        }
        if (ENG_ACTION_TYPES.has(item.action_type)) {
            return true;
        }
        const spec = this.specFor(item.action_type);
        return Boolean(spec && DETECTION_CATEGORIES.has(spec.category));
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

    canIgnore(item) {
        if (!this.canMarkDone(item)) {
            return false;
        }
        if (this.queueTab === 'engineering' || this.queueTab === 'detection') {
            return true;
        }
        return this.isEngNote(item);
    }

    canCreateRunbook(item) {
        return Boolean(
            item
            && item.action_type === 'runbook_gap'
            && item.status === 'informational'
            && !item.archived
        );
    }

    githubIssue(item) {
        if (item && item.github_issue && item.github_issue.number != null) {
            return item.github_issue;
        }
        const payload = (item && item.payload) || {};
        const raw = payload.engineering || payload.github_issue;
        if (!raw || typeof raw !== 'object') {
            return null;
        }
        const issue = raw.issue && typeof raw.issue === 'object' ? raw.issue : raw;
        if (issue.number == null && raw.number == null) {
            return null;
        }
        return {
            number: issue.number || raw.number,
            url: issue.url || issue.html_url || raw.url,
            state: issue.state || raw.state,
            repository: raw.repository,
        };
    }

    statusLabel(item) {
        if (item && item.decision && item.decision.action === 'ignore') {
            return 'Ignored';
        }
        return REQUEST_STATUS_LABELS[item && item.status] || (item && item.status) || '';
    }

    statusClass(item) {
        if (item && item.decision && item.decision.action === 'ignore') {
            return 'ignored';
        }
        return item && item.status ? item.status : '';
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
        this.restoreDrafts();
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
        this.renderListChrome();
        this.updateHeaderMeta();
        if (!this.requests.length) {
            list.innerHTML = `<div class="requests-empty">${this.emptyCopy()}</div>`;
            this.selectedId = null;
            if (!this._skipDetailRebuild) {
                this.renderDetail();
            }
            this.restoreDrafts();
            return;
        }
        const receiptHoldsSelection = Boolean(
            this.receipt && this.receipt.item && this.receipt.item.id === this.selectedId
        );
        if (this.selectedId && !this.requests.some((item) => item.id === this.selectedId) && !receiptHoldsSelection) {
            this.selectedId = this.requests[0].id;
            this._skipDetailRebuild = false;
        }
        if (!this.selectedId) {
            this.selectedId = this.requests[0].id;
        }
        const awaiting = this.filter === 'open'
            ? this.requests.filter((item) => item.status === 'awaiting_integration')
            : [];
        const rest = this.filter === 'open'
            ? this.requests.filter((item) => item.status !== 'awaiting_integration')
            : this.requests;
        let html = rest.map((item) => this.cardHtml(item)).join('');
        if (awaiting.length && (this.queueTab === 'soc' || this.queueTab === 'all')) {
            html += `
                <div class="requests-muted-section">
                    <div class="requests-muted-copy">
                        Waiting on integration — approved earlier; connect the missing integration or leave archived when obsolete.
                    </div>
                    ${awaiting.map((item) => this.cardHtml(item)).join('')}
                </div>
            `;
        } else if (awaiting.length) {
            html += awaiting.map((item) => this.cardHtml(item)).join('');
        }
        list.innerHTML = html;
        if (!this._skipDetailRebuild) {
            this.renderDetail();
        } else {
            this.highlightCards();
        }
        this.restoreDrafts();
    }

    emptyCopy() {
        const tab = this.queueTab;
        if (this.filter === 'archived') {
            return 'No archived requests in this tab yet.';
        }
        if (tab === 'soc') {
            return this.filter === 'all'
                ? 'No SOC requests yet. Close, isolate, identity, and case work appear here.'
                : 'No open SOC approvals. Detection notes live under Detection engineering.';
        }
        if (tab === 'engineering') {
            return 'No GitHub-tracked engineering tickets in this view.';
        }
        if (tab === 'detection') {
            return 'No detection engineering notes in this view.';
        }
        if (this.filter === 'all') {
            return 'No requests yet. The agent files actions here when it wants your approval, or informational fine-tune / visibility notes.';
        }
        return 'No open requests. Archived approvals and reviewed notes are hidden — switch to Archived to see them.';
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
        const ignoreCount = selected.filter((item) => this.canIgnore(item)).length;
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
                <button type="button" class="btn btn-secondary btn-sm" data-request-action="bulk-ignore"
                    ${ignoreCount ? '' : 'disabled'} title="Ignore selected review notes and close linked GitHub issues">
                    Ignore ${ignoreCount || ''}
                </button>
                <button type="button" class="btn btn-secondary btn-sm" data-request-clear-selection>Clear</button>
            </div>
            <textarea id="request-bulk-comment" class="command-input request-comment" rows="2"
                placeholder="Optional comment for this bulk action"></textarea>
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

    githubChipHtml(item, asLink) {
        const issue = this.githubIssue(item);
        if (!issue) {
            return '';
        }
        const label = `#${issue.number}${issue.state ? ` ${issue.state}` : ''}`;
        if (asLink && issue.url) {
            return `<a class="github-issue-chip" href="${escapeHtml(String(issue.url))}" target="_blank" rel="noopener noreferrer">${escapeHtml(label)}</a>`;
        }
        return `<span class="github-issue-chip">${escapeHtml(label)}</span>`;
    }

    cardHtml(item) {
        const spec = this.specFor(item.action_type);
        const active = item.id === this.selectedId ? ' active' : '';
        const checked = this.selectedIds.has(item.id);
        const cluster = (item.cluster && item.cluster.name) || item.cluster_id || '';
        const title = item.title || (spec && spec.label) || item.action_type;
        const archived = Boolean(item.archived) || ['acknowledged', 'denied', 'executed', 'failed'].includes(item.status);
        const awaiting = item.status === 'awaiting_integration';
        return `
            <article class="request-card${active}${checked ? ' is-checked' : ''}${archived ? ' is-archived' : ''}${awaiting ? ' is-muted' : ''}" data-request-id="${escapeHtml(item.id)}">
                <label class="request-card-check" title="Select for bulk actions">
                    <input type="checkbox" data-request-check="${escapeHtml(item.id)}"
                        ${checked ? 'checked' : ''} aria-label="Select request">
                </label>
                <button type="button" class="request-card-body" data-request-id="${escapeHtml(item.id)}">
                    <div class="request-card-title">${escapeHtml(title)}</div>
                    <div class="request-card-meta">
                        <span class="action-badge">${escapeHtml((spec && spec.label) || item.action_type)}</span>
                        <span class="status-badge ${escapeHtml(this.statusClass(item))}">${escapeHtml(this.statusLabel(item))}</span>
                        ${this.githubChipHtml(item)}
                        ${archived ? '<span class="status-badge archived">Archived</span>' : ''}
                        ${cluster ? `<span>${escapeHtml(cluster)}</span>` : ''}
                    </div>
                </button>
            </article>
        `;
    }

    decisionBarHtml(item, spec, pending, informational) {
        if (this.receipt && this.receipt.id === item.id) {
            return this.receiptHtml();
        }
        if (informational && item.status === 'informational') {
            const ignoreBtn = this.canIgnore(item)
                ? '<button type="button" class="btn btn-secondary" data-request-action="ignore">Ignore</button>'
                : '';
            const createRunbookBtn = this.canCreateRunbook(item)
                ? '<button type="button" class="btn btn-primary" data-request-action="create-runbook">Create runbook</button>'
                : '';
            const doneLabel = createRunbookBtn
                ? 'Create runbook opens an Open WebUI session with the request + last alert, writes a new md under run_books/soc1/cases, then marks this Done. Ignore archives here and closes the GitHub issue when linked.'
                : (this.canIgnore(item)
                    ? 'Done keeps GitHub tracking open. Ignore archives here and closes the GitHub issue.'
                    : 'No approval needed — review only, then mark Done.');
            return `
                <div class="request-decision-bar is-info">
                    <div class="request-decision-copy">
                        <span class="request-decision-label">Review note</span>
                        <span>${doneLabel}</span>
                    </div>
                    <div class="request-actions">
                        ${createRunbookBtn}
                        <button type="button" class="btn ${createRunbookBtn ? 'btn-secondary' : 'btn-primary'}" data-request-action="done">Done</button>
                        ${ignoreBtn}
                    </div>
                    <textarea id="request-comment" class="command-input request-comment" rows="2"
                        placeholder="Optional note (kept on the audit trail)"></textarea>
                </div>
            `;
        }
        if (!pending) {
            return this.settledBarHtml(item);
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
                <button type="button" class="btn btn-primary" data-request-action="approve">Approve</button>
                <button type="button" class="btn btn-danger" data-request-action="deny">Deny</button>
            `;
        }
        const notes = this.associatedPendingNotes(item);
        const noteCopy = notes.length
            ? (item.action_type === 'identity_verify'
                ? `Yes will also approve ${notes.length} pending alert note${notes.length === 1 ? '' : 's'} for this alert.`
                : `Approve will also write ${notes.length} pending alert note${notes.length === 1 ? '' : 's'} for this alert.`)
            : 'Review the details below, then approve or deny.';
        return `
            <div class="request-decision-bar">
                <div class="request-decision-copy">
                    <span class="request-decision-label">Needs approval</span>
                    <span>${noteCopy}</span>
                </div>
                <div class="request-actions">${buttons}</div>
                ${comment}
            </div>
        `;
    }

    settledBarHtml(item) {
        const decision = item.decision || {};
        const action = decision.action === 'ignore'
            ? 'Ignored'
            : decision.action === 'acknowledge'
                ? 'Reviewed'
                : decision.action === 'approve'
                    ? 'Approved'
                    : decision.action === 'deny'
                        ? 'Denied'
                        : this.statusLabel(item);
        const actor = decision.actor ? ` by ${decision.actor}` : '';
        const comment = decision.comment ? ` — ${decision.comment}` : '';
        return `
            <div class="request-decision-bar is-settled">
                <div class="request-decision-copy">
                    <span class="request-decision-label">Decision</span>
                    <span class="status-badge ${escapeHtml(this.statusClass(item))}">${escapeHtml(this.statusLabel(item))}</span>
                    <span>${escapeHtml(`${action}${actor}${comment}`)}</span>
                </div>
            </div>
        `;
    }

    receiptHtml() {
        const receipt = this.receipt || {};
        const next = receipt.nextId
            ? `<button type="button" class="btn btn-primary" data-request-next="${escapeHtml(receipt.nextId)}">Next</button>`
            : '<button type="button" class="btn btn-secondary" data-request-next="">Next open</button>';
        const child = receipt.childId
            ? `<button type="button" class="btn btn-secondary" data-request-open="${escapeHtml(receipt.childId)}">Open follow-up</button>`
            : '';
        return `
            <div class="request-decision-bar is-receipt">
                <div class="request-decision-copy">
                    <span class="request-decision-label">Done</span>
                    <span>${escapeHtml(receipt.message || 'Request updated.')}</span>
                </div>
                <div class="request-actions">
                    ${next}
                    ${child}
                </div>
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
        const errorHtml = item.error
            ? `<p class="settings-status is-error">${escapeHtml(item.error)}</p>`
            : '';
        const awaitingHtml = item.status === 'awaiting_integration'
            ? '<div class="request-info-banner is-muted">Waiting on integration — approved earlier; connect the missing integration or leave archived when obsolete.</div>'
            : '';
        const banner = informational && item.status === 'informational'
            ? `<div class="request-info-banner">${this.canCreateRunbook(item)
                ? 'Runbook gap — <strong>Create runbook</strong> starts an Open WebUI session with this request and the last investigated alert to write a new file under <code>run_books/soc1/cases</code>, then marks Done.'
                : (this.canIgnore(item)
                ? 'Review note — <strong>Done</strong> archives here and leaves GitHub open. <strong>Ignore</strong> archives here and closes the GitHub issue.'
                : 'Informational only — nothing is executed. Mark <strong>Done</strong> when you have reviewed it.')}</div>`
            : awaitingHtml;
        const settled = !pending && !(informational && item.status === 'informational');
        const techJson = {
            id: item.id,
            action_type: item.action_type,
            status: item.status,
            decision: item.decision,
            execution_result: item.execution_result,
            payload,
            github_issue: item.github_issue,
            child_request_ids: item.child_request_ids,
            error: item.error,
        };
        const resultHtml = settled
            ? `<details class="request-tech-details"><summary>Technical details</summary>
               <pre class="request-result">${escapeHtml(JSON.stringify(techJson, null, 2))}</pre></details>`
            : (item.execution_result
                ? `<div class="request-section-label">Result</div><pre class="request-result">${escapeHtml(JSON.stringify(item.execution_result, null, 2))}</pre>`
                : '');
        root.innerHTML = `
            ${this.decisionBarHtml(item, spec, pending, informational)}
            <div class="request-detail-body">
                <div class="request-card-meta">
                    <span class="action-badge">${escapeHtml((spec && spec.label) || item.action_type)}</span>
                    <span class="status-badge ${escapeHtml(this.statusClass(item))}">${escapeHtml(this.statusLabel(item))}</span>
                    ${this.githubChipHtml(item, true)}
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
            'engineering', 'github_issue',
        ]);
        if (item.action_type === 'add_alert_note') {
            skip.add('note');
        }
        const payloadRows = Object.keys(payload).length
            ? Object.entries(payload)
                .filter(([key, value]) => !skip.has(key) && value != null && value !== '')
                .map(([key, value]) => {
                    const label = this.fieldLabel(spec, key);
                    return `<dt>${escapeHtml(label)}</dt><dd>${escapeHtml(this.formatValue(value))}</dd>`;
                }).join('')
            : '';
        const proposedNote = item.action_type === 'add_alert_note' && payload.note
            ? `<div class="request-section-label">Proposed note</div><div class="request-detail-summary">${escapeHtml(this.formatValue(payload.note))}</div>`
            : '';
        const associated = this.associatedPendingNotes(item);
        const associatedHtml = associated.length
            ? `<div class="request-section-label">Associated notes (approved with this close)</div>
               ${associated.map((note) => `<div class="request-detail-summary">${escapeHtml(this.formatValue(note.payload && note.payload.note))}</div>`).join('')}`
            : '';
        return `
            ${this.alertHtml(payload.alert)}
            ${proposedNote}
            ${associatedHtml}
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
            ? `<div class="request-rule-meta">${entities.map((entry) => `<span class="action-badge">${escapeHtml(String(entry))}</span>`).join('')}</div>`
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
                    ${meta.map((entry) => `<span>${escapeHtml(entry)}</span>`).join('')}
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
        const skip = new Set([
            'suggestion', 'rule', 'coverage_check', 'rule_found', 'description', 'alert',
            'engineering', 'github_issue',
        ]);
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

    comment(fromBulk) {
        const id = fromBulk ? 'request-bulk-comment' : 'request-comment';
        const el = document.getElementById(id);
        return el ? el.value.trim() : '';
    }

    nextOpenId(currentId) {
        const open = this.requests.filter((item) => (
            item.id !== currentId
            && !item.archived
            && ['pending', 'informational', 'awaiting_integration'].includes(item.status)
        ));
        return open.length ? open[0].id : null;
    }

    openNext(nextId) {
        this.receipt = null;
        if (nextId && this.requests.some((item) => item.id === nextId)) {
            this.selectedId = nextId;
            this.render();
            return;
        }
        const fallback = this.nextOpenId(this.selectedId);
        if (fallback) {
            this.selectedId = fallback;
        }
        this.render();
    }

    receiptMessage(action, updated) {
        if (action === 'ignore') {
            const github = updated && updated.execution_result && updated.execution_result.github;
            if (github && github.attempted && github.success === false) {
                return 'Ignored here. GitHub issue was not closed — the board may be out of sync.';
            }
            if (github && github.success) {
                return 'Ignored. Linked GitHub issue was closed.';
            }
            return 'Ignored and archived.';
        }
        const status = updated && updated.status;
        if (status === 'executed') {
            return 'Approved and completed.';
        }
        if (status === 'acknowledged') {
            const created = updated
                && updated.execution_result
                && updated.execution_result.create_runbook;
            if (created && created.target_path) {
                return `Create runbook started → ${created.target_path}.md. Marked Done.`;
            }
            return 'Marked as done and archived.';
        }
        if (status === 'awaiting_integration') {
            return 'Approved. Waiting on a connected API to finish this action.';
        }
        if (status === 'denied') {
            return 'Request denied.';
        }
        if (status === 'failed') {
            return (updated && updated.error) || 'Request failed during execution.';
        }
        return 'Request updated.';
    }

    showReceipt(item, updated, action) {
        const childIds = (updated && updated.child_request_ids) || [];
        this.receipt = {
            id: item.id,
            item: updated || item,
            message: this.receiptMessage(action, updated),
            nextId: this.nextOpenId(item.id),
            childId: childIds.length ? childIds[childIds.length - 1] : null,
        };
        this.selectedId = item.id;
    }

    workingMessage(action, count) {
        const many = Number(count || 1);
        const suffix = many > 1 ? ` ${many} requests` : '';
        if (action === 'approve') {
            return many > 1 ? `Approving${suffix}…` : 'Approving…';
        }
        if (action === 'deny') {
            return many > 1 ? `Denying${suffix}…` : 'Denying…';
        }
        if (action === 'ignore') {
            return many > 1 ? `Ignoring${suffix}…` : 'Ignoring…';
        }
        if (action === 'done' || action === 'acknowledge') {
            return many > 1 ? `Marking${suffix} done…` : 'Marking done…';
        }
        if (action === 'create-runbook') {
            return 'Starting runbook session…';
        }
        if (action === 'yes') {
            return 'Recording Yes…';
        }
        if (action === 'no') {
            return 'Recording No…';
        }
        return 'Updating request…';
    }

    optimisticStatus(action) {
        if (action === 'deny') {
            return 'denied';
        }
        if (action === 'done' || action === 'acknowledge' || action === 'ignore' || action === 'create-runbook') {
            return 'acknowledged';
        }
        return 'executed';
    }

    optimisticUpdatedItem(item, action) {
        return {
            ...item,
            status: this.optimisticStatus(action),
            archived: true,
            _optimistic: true,
        };
    }

    applyOptimistic(items) {
        if (!this._optimisticById.size) {
            return items;
        }
        const result = [];
        items.forEach((item) => {
            const overlay = this._optimisticById.get(item.id);
            if (overlay && this.filter === 'open' && overlay.archived) {
                return;
            }
            result.push(overlay || item);
        });
        return result;
    }

    replaceItem(id, next) {
        const index = this.items.findIndex((item) => item.id === id);
        if (index >= 0) {
            this.items[index] = next;
        } else {
            this.items.unshift(next);
        }
        if (this._fullById[id]) {
            this._fullById[id] = { ...next, _full: true, _generation: this.generation };
        }
    }

    nudgeCounts(delta, item) {
        const openDelta = delta;
        const archivedDelta = -delta;
        if (this.tabCounts) {
            this.tabCounts.open = Math.max(0, Number(this.tabCounts.open || 0) + openDelta);
            this.tabCounts.archived = Math.max(0, Number(this.tabCounts.archived || 0) + archivedDelta);
        }
        if (this.queueCounts && this.queueCounts[this.queueTab]) {
            this.queueCounts[this.queueTab].open = Math.max(
                0,
                Number(this.queueCounts[this.queueTab].open || 0) + openDelta,
            );
            this.queueCounts[this.queueTab].archived = Math.max(
                0,
                Number(this.queueCounts[this.queueTab].archived || 0) + archivedDelta,
            );
            this.tabCounts = this.queueCounts[this.queueTab];
        }
        if (this.counts) {
            this.counts.open = Math.max(0, Number(this.counts.open || 0) + openDelta);
            this.counts.pending = Math.max(0, Number(this.counts.pending || 0) + openDelta);
            if (this.isActionable(item)) {
                this.counts.actionable = Math.max(0, Number(this.counts.actionable || 0) + openDelta);
            }
        }
        this.updateNavBadge();
        this.updateHeaderMeta();
    }

    settleLocally(item, action) {
        const snapshot = { ...item };
        const settled = this.optimisticUpdatedItem(item, action);
        this._rollbackById.set(item.id, snapshot);
        this._optimisticById.set(item.id, settled);
        const nextId = this.nextOpenId(item.id);
        this.replaceItem(item.id, settled);
        this.selectedIds.delete(item.id);
        this.nudgeCounts(-1, snapshot);
        this.applyQueueFilter();
        this.receipt = null;
        this._skipDetailRebuild = false;
        this.selectedId = nextId;
        this._clickLockUntil = Date.now() + 400;
        this.render();
        if (nextId) {
            this.ensureFull(nextId);
        }
        return snapshot;
    }

    restoreLocal(id) {
        const snapshot = this._rollbackById.get(id);
        this._optimisticById.delete(id);
        this._rollbackById.delete(id);
        this._inFlight.delete(id);
        if (!snapshot) {
            this.load();
            return;
        }
        this.replaceItem(id, snapshot);
        this.nudgeCounts(1, snapshot);
        this.applyQueueFilter();
        this.render();
    }

    finishLocal(id) {
        this._optimisticById.delete(id);
        this._rollbackById.delete(id);
        this._inFlight.delete(id);
    }

    dispatchAction(action, id, comment) {
        const api = this.controller.api;
        if (action === 'approve') {
            return api.approveRequest(id, comment);
        }
        if (action === 'deny') {
            return api.denyRequest(id, comment);
        }
        if (action === 'done' || action === 'acknowledge') {
            return api.acknowledgeRequest(id, comment);
        }
        if (action === 'ignore') {
            return api.ignoreRequest(id, comment);
        }
        if (action === 'create-runbook') {
            return api.createRunbookFromRequest(id, comment);
        }
        if (action === 'yes' || action === 'no') {
            return api.answerRequest(id, action, comment);
        }
        return Promise.resolve({ success: false, error: 'Unknown action' });
    }

    async handleAction(action) {
        const item = this.selected();
        if (!item || this._inFlight.has(item.id)) {
            return;
        }
        this._inFlight.add(item.id);
        const comment = this.comment();
        const toastKey = `requests-${item.id}`;
        this.settleLocally(item, action);
        if (window.toast) {
            window.toast.info(this.workingMessage(action), { key: toastKey, duration: 0 });
        }
        const result = await this.dispatchAction(action, item.id, comment);
        if (!result || !result.success) {
            this.restoreLocal(item.id);
            if (window.toast) {
                window.toast.error(
                    (result && (result.error || result.detail)) || 'Could not update request',
                    { key: toastKey },
                );
            }
            return;
        }
        const updated = result.request;
        const github = updated && updated.execution_result && updated.execution_result.github;
        if (window.toast) {
            if (action === 'ignore' && github && github.attempted && github.success === false) {
                window.toast.error(github.error || 'Ignored locally, but GitHub close failed.', { key: toastKey });
            } else {
                window.toast.success(this.receiptMessage(action, updated), { key: toastKey });
            }
        }
        this.finishLocal(item.id);
        this.load();
        if (action === 'create-runbook' && result.session && result.session.id) {
            this.openCreateRunbookSession(result.session.id);
        }
    }

    async openCreateRunbookSession(sessionId) {
        try {
            if (this.controller.loadSessions) {
                await this.controller.loadSessions();
            }
            if (this.controller.setActiveSection) {
                this.controller.setActiveSection('sessions');
            }
            if (this.controller.sessionManager && this.controller.sessionManager.switchToSession) {
                await this.controller.sessionManager.switchToSession(sessionId);
            }
        } catch (err) {
            console.warn('[Requests] Could not switch to create-runbook session', err);
        }
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
        } else if (action === 'ignore') {
            ids = selected.filter((item) => this.canIgnore(item)).map((item) => item.id);
            label = 'ignore';
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
                        : action === 'ignore'
                            ? 'No selected review notes to ignore.'
                            : 'No selected informational notes to mark Done.';
                window.toast.info(emptyMsg, { key: 'requests' });
            }
            return;
        }
        const ok = window.confirm(
            action === 'ignore'
                ? `Ignore ${ids.length} review note${ids.length === 1 ? '' : 's'}? Linked GitHub issues will be closed.`
                : action === 'acknowledge' || action === 'done'
                    ? `Mark ${ids.length} informational note${ids.length === 1 ? '' : 's'} as Done?`
                    : `${label.charAt(0).toUpperCase() + label.slice(1)} ${ids.length} request${ids.length === 1 ? '' : 's'}?`,
        );
        if (!ok) {
            return;
        }
        const toastKey = 'requests-bulk';
        const originals = new Map(selected.map((item) => [item.id, item]));
        ids.forEach((id) => {
            const current = originals.get(id);
            if (!current || this._inFlight.has(id)) {
                return;
            }
            this._inFlight.add(id);
            this.settleLocally(current, action === 'acknowledge' ? 'done' : action);
        });
        if (window.toast) {
            window.toast.info(this.workingMessage(action, ids.length), { key: toastKey, duration: 0 });
        }
        const result = await this.controller.api.bulkRequests(action, ids, this.comment(true));
        if (!result || !result.success) {
            ids.forEach((id) => this.restoreLocal(id));
            if (window.toast) {
                window.toast.error((result && (result.error || result.detail)) || 'Bulk action failed', { key: toastKey });
            }
            return;
        }
        const succeeded = Number(result.succeeded || 0);
        const skipped = Number(result.skipped || 0);
        const failed = Number(result.failed || 0);
        const results = Array.isArray(result.results) ? result.results : [];
        results.forEach((entry) => {
            if (!entry || !entry.id) {
                return;
            }
            if (entry.success && !entry.skipped) {
                this.finishLocal(entry.id);
                return;
            }
            this.restoreLocal(entry.id);
        });
        ids.forEach((id) => {
            if (this._inFlight.has(id)) {
                this.finishLocal(id);
            }
        });
        if (window.toast) {
            const verb = action === 'acknowledge' ? 'marked done' : action === 'ignore' ? 'ignored' : `${label}d`;
            const parts = [`${succeeded} ${verb}`];
            if (skipped) {
                parts.push(`${skipped} skipped`);
            }
            if (failed) {
                parts.push(`${failed} failed`);
            }
            if (failed) {
                window.toast.error(parts.join(' · '), { key: toastKey });
            } else {
                window.toast.success(parts.join(' · '), { key: toastKey });
            }
        }
        this.selectedIds.clear();
        this._skipDetailRebuild = false;
        this.load();
    }
}
