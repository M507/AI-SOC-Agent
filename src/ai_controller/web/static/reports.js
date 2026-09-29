class ReportsManager {
    constructor(controller) {
        this.controller = controller;
        this.reports = [];
        this.selected = null;
        this.bound = false;
    }

    bind() {
        if (this.bound) return;
        this.bound = true;
        const search = document.getElementById('reports-search');
        if (search) search.addEventListener('input', () => this.showList());
    }

    query() {
        const search = document.getElementById('reports-search');
        return ((search && search.value) || '').trim().toLowerCase();
    }

    visibleReports() {
        const query = this.query();
        if (!query) return this.reports;
        return this.reports.filter((item) => {
            const haystack = [item.session_name, item.command].join(' ').toLowerCase();
            return haystack.includes(query);
        });
    }

    async load() {
        this.bind();
        const body = document.getElementById('reports-body');
        if (body) body.setAttribute('aria-busy', 'true');
        this.setStatus('Loading reports…');
        const data = await this.controller.api.listReports();
        if (body) body.setAttribute('aria-busy', 'false');
        if (!data || data.success === false) {
            this.fail((data && (data.error || data.detail)) || 'Could not load reports.');
            return;
        }
        this.reports = data.reports || [];
        this.clearStatus();
        if (!this.reports.length) {
            this.showEmpty();
            return;
        }
        this.showList();
        const visible = this.visibleReports();
        const still = visible.find((item) => `${item.session_id}:${item.entry_id}` === this.selected);
        const next = still || visible[0];
        if (next) await this.open(next.session_id, next.entry_id);
    }

    showEmpty() {
        const list = document.getElementById('reports-layout');
        const empty = document.getElementById('reports-empty');
        if (list) list.hidden = true;
        if (empty) empty.hidden = false;
        const open = document.getElementById('reports-open-sessions');
        if (open && !open.dataset.bound) {
            open.dataset.bound = '1';
            open.addEventListener('click', () => this.controller.setActiveSection('sessions'));
        }
        const search = document.getElementById('reports-search');
        if (search) search.hidden = true;
    }

    showList() {
        const list = document.getElementById('reports-layout');
        const empty = document.getElementById('reports-empty');
        if (list) list.hidden = false;
        if (empty) empty.hidden = true;
        const search = document.getElementById('reports-search');
        if (search) search.hidden = false;
        const host = document.getElementById('reports-list');
        if (!host) return;
        host.replaceChildren();
        const visible = this.visibleReports();
        if (!visible.length) {
            const note = document.createElement('p');
            note.className = 'page-status';
            note.textContent = 'Nothing matches this search.';
            host.append(note);
            return;
        }
        let lastSession = '';
        visible.forEach((item) => {
            if (item.session_id !== lastSession) {
                lastSession = item.session_id;
                const label = document.createElement('div');
                label.className = 'library-group-label';
                label.textContent = item.session_name || 'Session';
                host.append(label);
            }
            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'library-file report-file';
            button.dataset.sessionId = item.session_id;
            button.dataset.entryId = item.entry_id;
            const title = document.createElement('span');
            title.textContent = item.session_name || 'Session';
            const command = document.createElement('span');
            command.className = 'report-command';
            command.textContent = item.command || '';
            const when = document.createElement('time');
            when.className = 'report-time';
            when.dateTime = item.at || '';
            when.textContent = formatPageWhen(item.at);
            button.append(title, command, when);
            if (`${item.session_id}:${item.entry_id}` === this.selected) {
                button.classList.add('active');
                button.setAttribute('aria-current', 'true');
            }
            button.addEventListener('click', () => this.open(item.session_id, item.entry_id));
            host.append(button);
        });
    }

    async open(sessionId, entryId) {
        this.selected = `${sessionId}:${entryId}`;
        document.querySelectorAll('#reports-list .report-file').forEach((button) => {
            const on = button.dataset.sessionId === sessionId && button.dataset.entryId === entryId;
            button.classList.toggle('active', on);
            if (on) button.setAttribute('aria-current', 'true');
            else button.removeAttribute('aria-current');
        });
        const doc = document.getElementById('reports-doc');
        if (doc) doc.scrollTop = 0;
        const data = await this.controller.api.readReport(sessionId, entryId);
        if (!data || data.success === false) {
            this.fail((data && (data.error || data.detail)) || 'Could not open this write-up.');
            return;
        }
        this.clearStatus();
        const title = document.getElementById('reports-read-title');
        const command = document.getElementById('reports-read-command');
        const when = document.getElementById('reports-read-time');
        const status = document.getElementById('reports-read-status');
        if (title) title.textContent = data.session_name || 'Report';
        if (command) command.textContent = data.command || '';
        if (when) {
            when.dateTime = data.at || '';
            when.textContent = formatPageWhen(data.at);
        }
        if (status) status.textContent = 'Completed';
        const open = document.getElementById('reports-open-session');
        if (open) {
            open.onclick = () => {
                if (this.controller.sessionManager) {
                    this.controller.sessionManager.switchToSession(sessionId);
                }
            };
        }
        if (doc) renderSanitizedMarkdown(data.markdown || '', doc, 'library-doc markdown-content');
    }

    setStatus(text) {
        const status = document.getElementById('reports-status');
        if (!status) return;
        status.hidden = false;
        status.classList.remove('is-error');
        status.textContent = text;
    }

    clearStatus() {
        const status = document.getElementById('reports-status');
        if (!status) return;
        status.textContent = '';
        status.hidden = true;
        status.classList.remove('is-error');
    }

    fail(message) {
        const body = document.getElementById('reports-body');
        if (body) body.setAttribute('aria-busy', 'false');
        const status = document.getElementById('reports-status');
        if (!status) return;
        status.hidden = false;
        status.classList.add('is-error');
        status.textContent = message;
    }
}
