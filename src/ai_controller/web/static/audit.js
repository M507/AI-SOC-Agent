class AuditManager {
    constructor(controller) {
        this.controller = controller;
        this.events = [];
        this.kind = 'all';
        this.truncated = false;
        this.limit = 200;
        this.bound = false;
    }

    bind() {
        if (this.bound) return;
        this.bound = true;
        const bar = document.getElementById('audit-segments');
        if (bar) {
            bar.addEventListener('click', (event) => {
                const button = event.target.closest('[data-audit-kind]');
                if (!button) return;
                this.kind = button.dataset.auditKind;
                this.render();
            });
        }
        const filter = document.getElementById('audit-filter');
        if (filter) filter.addEventListener('input', () => this.render());
    }

    async load() {
        this.bind();
        const body = document.getElementById('audit-body');
        if (body) body.setAttribute('aria-busy', 'true');
        this.setStatus('Loading audit…');
        const data = await this.controller.api.getAudit();
        if (body) body.setAttribute('aria-busy', 'false');
        if (!data || data.success === false) {
            this.fail((data && (data.error || data.detail)) || 'Could not load the audit.');
            return;
        }
        this.events = data.events || [];
        this.truncated = Boolean(data.truncated);
        this.limit = data.limit || 200;
        this.clearStatus();
        this.render();
    }

    render() {
        const caption = document.getElementById('audit-caption');
        if (caption) {
            const cap = this.truncated ? ` Showing the latest ${this.limit}.` : '';
            caption.textContent = `Sign-ins, chats, and decisions. Sign-in history starts with this console.${cap}`;
        }
        const counts = { all: this.events.length, signin: 0, chat: 0, action: 0 };
        this.events.forEach((item) => {
            if (counts[item.kind] != null) counts[item.kind] += 1;
        });
        const bar = document.getElementById('audit-segments');
        if (bar) {
            const segments = [
                ['all', 'All'],
                ['signin', 'Sign-ins'],
                ['chat', 'Chats'],
                ['action', 'Actions'],
            ];
            bar.replaceChildren();
            segments.forEach(([id, label]) => {
                const button = document.createElement('button');
                button.type = 'button';
                button.className = id === this.kind ? 'btn btn-primary btn-sm' : 'btn btn-secondary btn-sm';
                button.dataset.auditKind = id;
                button.setAttribute('aria-pressed', id === this.kind ? 'true' : 'false');
                button.textContent = `${label} ${counts[id]}`;
                bar.append(button);
            });
        }
        const host = document.getElementById('audit-table');
        if (!host) return;
        const query = ((document.getElementById('audit-filter') || {}).value || '').trim().toLowerCase();
        const rows = this.events.filter((item) => {
            if (this.kind !== 'all' && item.kind !== this.kind) return false;
            if (!query) return true;
            const haystack = [item.who, item.summary, item.ip, item.session_name, item.title].join(' ').toLowerCase();
            return haystack.includes(query);
        });
        host.replaceChildren();
        if (!this.events.length) {
            host.append(this.note('No sign-ins, chats, or decisions are recorded yet.'));
            return;
        }
        if (!rows.length) {
            host.append(this.note('Nothing matches this filter.'));
            return;
        }
        const wrap = document.createElement('div');
        wrap.className = 'page-table-wrap';
        const table = document.createElement('table');
        table.className = 'page-table';
        const head = document.createElement('thead');
        const headRow = document.createElement('tr');
        ['Time', 'Kind', 'Who', 'What'].forEach((label) => {
            const cell = document.createElement('th');
            cell.scope = 'col';
            cell.textContent = label;
            headRow.append(cell);
        });
        head.append(headRow);
        const body = document.createElement('tbody');
        rows.forEach((item) => body.append(this.row(item)));
        table.append(head, body);
        wrap.append(table);
        host.append(wrap);
    }

    row(item) {
        const line = document.createElement('tr');
        const target = item.kind === 'chat' ? item.session_id : item.kind === 'action' ? item.request_id : '';
        if (target) {
            line.className = 'page-row-link';
            line.tabIndex = 0;
            line.setAttribute('role', 'link');
            const label = item.kind === 'chat' ? `Open session ${item.session_name || ''}`.trim() : `Open request ${item.title || ''}`.trim();
            line.setAttribute('aria-label', label);
            const open = () => this.open(item);
            line.addEventListener('click', open);
            line.addEventListener('keydown', (event) => {
                if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault();
                    open();
                }
            });
        }
        const when = document.createElement('td');
        when.className = 'num';
        const time = document.createElement('time');
        time.className = 'page-time';
        time.dateTime = item.at || '';
        time.textContent = formatPageWhen(item.at);
        when.append(time);
        const kind = document.createElement('td');
        kind.textContent = item.kind === 'signin' ? 'Sign-in' : item.kind === 'chat' ? 'Chat' : 'Action';
        const who = document.createElement('td');
        who.textContent = item.who || '—';
        const what = document.createElement('td');
        what.className = 'page-wrap';
        if (item.outcome === 'failed') {
            const failed = document.createElement('span');
            failed.className = 'audit-failed';
            failed.textContent = 'Failed';
            what.append(failed, document.createTextNode(item.summary.replace(/^Failed/, '') || ''));
        } else {
            what.textContent = item.summary || '—';
            what.title = item.summary || '';
        }
        line.append(when, kind, who, what);
        return line;
    }

    open(item) {
        if (item.kind === 'chat' && item.session_id && this.controller.sessionManager) {
            this.controller.sessionManager.switchToSession(item.session_id);
            return;
        }
        if (item.kind === 'action' && item.request_id && this.controller.overviewManager) {
            this.controller.overviewManager.openRequest(item.request_id);
        }
    }

    note(text) {
        const paragraph = document.createElement('p');
        paragraph.className = 'page-note';
        paragraph.textContent = text;
        return paragraph;
    }

    setStatus(text) {
        const status = document.getElementById('audit-status');
        if (!status) return;
        status.hidden = false;
        status.classList.remove('is-error');
        status.textContent = text;
    }

    clearStatus() {
        const status = document.getElementById('audit-status');
        if (!status) return;
        status.textContent = '';
        status.hidden = true;
        status.classList.remove('is-error');
    }

    fail(message) {
        const status = document.getElementById('audit-status');
        if (!status) return;
        status.hidden = false;
        status.classList.add('is-error');
        status.textContent = message;
    }
}
