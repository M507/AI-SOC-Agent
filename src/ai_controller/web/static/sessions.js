// Session Management — browser-style workspace tabs.
// Closing a tab dismisses it from the bar. The session file stays on disk.

const SESSION_TABS_KEY = 'samigpt.sessionTabs';
const OPEN_CAP = 20;
const RECENT_CAP = 15;
const TAB_MIN_WIDTH = 88;

class SessionManager {
    constructor(controller) {
        this.controller = controller;
        this.sessions = new Map();
        this.deletedSessionIds = new Set();
        this.pendingOpen = new Set();
        this.renamingId = null;
        this.menuSessionId = null;
        this.dragId = null;
        this.parkedIds = [];
        this.state = this.loadState();
        this.bindChrome();
        this.bindKeyboard();
    }

    loadState() {
        const empty = {
            openIds: [],
            order: [],
            pinnedIds: [],
            recentlyClosed: [],
            initialized: false,
        };
        try {
            const raw = localStorage.getItem(SESSION_TABS_KEY);
            if (!raw) return empty;
            const parsed = JSON.parse(raw);
            return {
                openIds: Array.isArray(parsed.openIds) ? parsed.openIds : [],
                order: Array.isArray(parsed.order) ? parsed.order : [],
                pinnedIds: Array.isArray(parsed.pinnedIds) ? parsed.pinnedIds : [],
                recentlyClosed: Array.isArray(parsed.recentlyClosed) ? parsed.recentlyClosed : [],
                initialized: Boolean(parsed.initialized),
            };
        } catch (error) {
            return empty;
        }
    }

    save() {
        localStorage.setItem(SESSION_TABS_KEY, JSON.stringify({
            openIds: this.state.openIds,
            order: this.state.order,
            pinnedIds: this.state.pinnedIds,
            recentlyClosed: this.state.recentlyClosed,
            initialized: this.state.initialized,
        }));
    }

    bar() {
        return document.getElementById('sessions-tab-group');
    }

    pinnedEl() {
        return document.getElementById('session-tab-pinned');
    }

    stripEl() {
        return document.getElementById('sessions-tabs');
    }

    visualIds() {
        const pinned = new Set(this.state.pinnedIds);
        const ordered = this.state.order.filter(id => this.state.openIds.includes(id));
        return [
            ...ordered.filter(id => pinned.has(id)),
            ...ordered.filter(id => !pinned.has(id)),
        ];
    }

    rememberOpen(sessionId) {
        if (!sessionId) return;
        if (!this.state.openIds.includes(sessionId)) {
            this.state.openIds.push(sessionId);
        }
        if (!this.state.order.includes(sessionId)) {
            this.state.order.push(sessionId);
        }
        this.state.recentlyClosed = this.state.recentlyClosed.filter(item => item.id !== sessionId);
        this.pendingOpen.add(sessionId);
        this.state.initialized = true;
        this.save();
    }

    /**
     * Diff and render the open set. Does not delete session files.
     */
    updateSessions(sessions) {
        const known = new Set(sessions.map(session => session.id));
        sessions.forEach(session => this.sessions.set(session.id, session));

        if (!this.state.initialized) {
            const seeded = sessions.slice(0, OPEN_CAP).map(session => session.id).reverse();
            this.state.openIds = seeded.slice();
            this.state.order = seeded.slice();
            this.state.pinnedIds = [];
            this.state.initialized = true;
        }

        this.state.openIds = this.state.openIds.filter(id => known.has(id) || this.pendingOpen.has(id));
        this.pendingOpen.forEach(id => {
            if (known.has(id)) this.pendingOpen.delete(id);
        });
        this.state.pinnedIds = this.state.pinnedIds.filter(id => this.state.openIds.includes(id));
        this.state.order = this.state.order.filter(id => this.state.openIds.includes(id));
        this.state.openIds.forEach(id => {
            if (!this.state.order.includes(id)) this.state.order.push(id);
        });
        this.state.recentlyClosed = this.state.recentlyClosed.filter(item => known.has(item.id));
        this.save();

        if (this.renamingId) {
            this.applyStatus(this.renamingId);
            return;
        }
        this.render();
    }

    render() {
        const pinnedHost = this.pinnedEl();
        const strip = this.stripEl();
        const divider = document.getElementById('session-tab-divider');
        if (!pinnedHost || !strip) return;

        const pinned = this.visualIds().filter(id => this.state.pinnedIds.includes(id));
        const normal = this.visualIds().filter(id => !this.state.pinnedIds.includes(id));
        pinnedHost.replaceChildren(...pinned.map(id => this.createTab(this.sessions.get(id))).filter(Boolean));
        strip.replaceChildren(...normal.map(id => this.createTab(this.sessions.get(id))).filter(Boolean));
        if (divider) divider.hidden = pinned.length === 0;
        this.syncActive();
        this.fitStrip();
    }

    createTab(session) {
        if (!session) return null;
        const pinned = this.state.pinnedIds.includes(session.id);
        const tab = document.createElement('button');
        tab.type = 'button';
        tab.className = 'session-tab' + (pinned ? ' is-pinned' : '');
        tab.dataset.sessionId = session.id;
        tab.dataset.status = session.status || 'pending';
        tab.setAttribute('role', 'tab');
        tab.setAttribute('draggable', 'true');
        tab.title = this.tooltip(session);
        tab.setAttribute('aria-label', session.name);

        const title = document.createElement('span');
        title.className = 'session-tab-title';
        title.textContent = session.name;

        const close = document.createElement('span');
        close.className = 'session-tab-close';
        close.setAttribute('role', 'button');
        close.setAttribute('aria-label', `Close ${session.name}`);
        close.textContent = '×';

        tab.append(
            this.statusMark(),
            title,
            close,
        );

        tab.addEventListener('click', (event) => {
            if (event.target.closest('.session-tab-close')) return;
            this.controller.switchToSession(session.id);
        });
        close.addEventListener('click', (event) => {
            event.stopPropagation();
            event.preventDefault();
            this.closeTab(session.id);
        });
        tab.addEventListener('auxclick', (event) => {
            if (event.button !== 1) return;
            event.preventDefault();
            this.closeTab(session.id);
        });
        tab.addEventListener('contextmenu', (event) => {
            event.preventDefault();
            this.openMenu(event.clientX, event.clientY, session.id);
        });
        tab.addEventListener('dragstart', (event) => {
            this.dragId = session.id;
            event.dataTransfer.setData('text/plain', session.id);
            event.dataTransfer.effectAllowed = 'move';
        });
        tab.addEventListener('dragover', (event) => {
            event.preventDefault();
            tab.classList.add('is-drop-target');
        });
        tab.addEventListener('dragleave', () => tab.classList.remove('is-drop-target'));
        tab.addEventListener('drop', (event) => {
            event.preventDefault();
            event.stopPropagation();
            tab.classList.remove('is-drop-target');
            const sourceId = this.dragId || event.dataTransfer.getData('text/plain');
            this.dropOn(sourceId, session.id, event.clientX, tab);
        });
        tab.addEventListener('dragend', () => {
            this.dragId = null;
            tab.classList.remove('is-drop-target');
        });
        return tab;
    }

    statusMark() {
        const mark = document.createElement('span');
        mark.className = 'session-tab-status';
        mark.setAttribute('aria-hidden', 'true');
        return mark;
    }

    tooltip(session) {
        const parts = [session.name];
        if (session.cluster && session.cluster.name) parts.push(session.cluster.name);
        return parts.join(' · ');
    }

    getTabElement(sessionId) {
        const bar = this.bar();
        if (!bar) return null;
        return bar.querySelector(`.session-tab[data-session-id="${sessionId}"]`);
    }

    syncActive() {
        const active = this.controller.activeSessionId;
        const bar = this.bar();
        if (!bar) return;
        bar.querySelectorAll('.session-tab').forEach(tab => {
            const on = tab.dataset.sessionId === active;
            tab.classList.toggle('active', on);
            tab.setAttribute('aria-selected', on ? 'true' : 'false');
        });
    }

    applyStatus(sessionId) {
        const session = this.sessions.get(sessionId);
        const tab = this.getTabElement(sessionId);
        if (session && tab) tab.dataset.status = session.status || 'pending';
    }

    fitStrip() {
        const strip = this.stripEl();
        if (!strip) return;
        const tabs = [...strip.querySelectorAll('.session-tab')];
        tabs.forEach(tab => {
            tab.hidden = false;
        });
        this.parkedIds = [];
        if (!tabs.length) {
            this.markOverflow(false);
            return;
        }
        const styles = getComputedStyle(strip);
        const gap = parseFloat(styles.columnGap || styles.gap || '0') || 0;
        let used = 0;
        const keep = [];
        const parked = [];
        tabs.forEach(tab => {
            const next = used + TAB_MIN_WIDTH + (keep.length ? gap : 0);
            if (next <= strip.clientWidth || keep.length === 0) {
                keep.push(tab);
                used = next;
            } else {
                parked.push(tab);
            }
        });
        const activeId = this.controller.activeSessionId;
        const activeParked = parked.find(tab => tab.dataset.sessionId === activeId);
        if (activeParked && keep.length) {
            const displaced = keep.pop();
            parked.splice(parked.indexOf(activeParked), 1);
            parked.unshift(displaced);
            keep.push(activeParked);
        }
        parked.forEach(tab => {
            tab.hidden = true;
        });
        this.parkedIds = parked.map(tab => tab.dataset.sessionId);
        this.markOverflow(parked.length > 0);
    }

    markOverflow(hasHidden) {
        const button = document.getElementById('session-tab-overflow');
        if (button) button.classList.toggle('has-overflow', hasHidden);
    }

    dropOn(sourceId, targetId, clientX, targetEl) {
        if (!sourceId || sourceId === targetId) return;
        const rect = targetEl.getBoundingClientRect();
        const before = clientX < rect.left + rect.width / 2;
        const pin = this.state.pinnedIds.includes(targetId);
        this.place(sourceId, targetId, pin, before);
    }

    place(sourceId, targetId, makePinned, before) {
        if (!this.state.openIds.includes(sourceId)) return;
        const pinnedOrder = this.visualIds().filter(id => this.state.pinnedIds.includes(id) && id !== sourceId);
        const normalOrder = this.visualIds().filter(id => !this.state.pinnedIds.includes(id) && id !== sourceId);
        const list = makePinned ? pinnedOrder : normalOrder;
        let index = list.indexOf(targetId);
        if (index < 0) index = list.length;
        else if (!before) index += 1;
        list.splice(index, 0, sourceId);
        if (makePinned) {
            this.state.pinnedIds = list.slice();
            this.state.order = [...list, ...normalOrder];
        } else {
            this.state.pinnedIds = pinnedOrder.slice();
            this.state.order = [...pinnedOrder, ...list];
        }
        this.save();
        this.render();
    }

    setPinned(sessionId, pinned) {
        if (pinned) {
            if (!this.state.pinnedIds.includes(sessionId)) {
                this.state.pinnedIds.push(sessionId);
            }
        } else {
            this.state.pinnedIds = this.state.pinnedIds.filter(id => id !== sessionId);
        }
        const pinnedOrder = this.visualIds().filter(id => this.state.pinnedIds.includes(id));
        const normalOrder = this.visualIds().filter(id => !this.state.pinnedIds.includes(id));
        this.state.order = [...pinnedOrder, ...normalOrder];
        this.save();
        this.render();
    }

    closeTab(sessionId) {
        if (!this.state.openIds.includes(sessionId)) return;
        const tab = this.getTabElement(sessionId);
        const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        if (tab && !reduce) {
            tab.classList.add('is-closing');
            window.setTimeout(() => this.commitClose(sessionId), 120);
            return;
        }
        this.commitClose(sessionId);
    }

    commitClose(sessionId) {
        if (!this.state.openIds.includes(sessionId)) return;
        const visual = this.visualIds();
        const index = visual.indexOf(sessionId);
        const session = this.sessions.get(sessionId);
        const name = session ? session.name : sessionId;
        this.state.openIds = this.state.openIds.filter(id => id !== sessionId);
        this.state.pinnedIds = this.state.pinnedIds.filter(id => id !== sessionId);
        this.state.order = this.state.order.filter(id => id !== sessionId);
        this.state.recentlyClosed = [
            { id: sessionId, name },
            ...this.state.recentlyClosed.filter(item => item.id !== sessionId),
        ].slice(0, RECENT_CAP);
        this.save();

        if (this.controller.activeSessionId === sessionId) {
            const next = visual[index + 1] || visual[index - 1];
            if (next && this.state.openIds.includes(next)) {
                this.controller.switchToSession(next);
            } else {
                this.controller.activeSessionId = null;
                if (this.controller.wsManager) this.controller.wsManager.disconnect(sessionId);
                const content = document.getElementById('session-content');
                const empty = document.getElementById('no-session-message');
                if (content) content.style.display = 'none';
                if (empty) empty.style.display = 'flex';
            }
        }
        this.render();
        this.closeMenu();
    }

    closeOthers(sessionId) {
        this.visualIds().filter(id => id !== sessionId).forEach(id => this.queueClose(id));
        this.flushQueuedCloses();
    }

    closeToTheRight(sessionId) {
        const visual = this.visualIds();
        const index = visual.indexOf(sessionId);
        visual.slice(index + 1).forEach(id => this.queueClose(id));
        this.flushQueuedCloses();
    }

    queueClose(sessionId) {
        const session = this.sessions.get(sessionId);
        this.state.recentlyClosed = [
            { id: sessionId, name: session ? session.name : sessionId },
            ...this.state.recentlyClosed.filter(item => item.id !== sessionId),
        ];
        this.state.openIds = this.state.openIds.filter(id => id !== sessionId);
        this.state.pinnedIds = this.state.pinnedIds.filter(id => id !== sessionId);
        this.state.order = this.state.order.filter(id => id !== sessionId);
    }

    flushQueuedCloses() {
        this.state.recentlyClosed = this.state.recentlyClosed.slice(0, RECENT_CAP);
        this.save();
        if (this.controller.activeSessionId && !this.state.openIds.includes(this.controller.activeSessionId)) {
            const next = this.visualIds()[0];
            if (next) this.controller.switchToSession(next);
        }
        this.render();
        this.closeMenu();
    }

    reopenLast() {
        const item = this.state.recentlyClosed[0];
        if (item) this.reopen(item);
    }

    reopen(item) {
        if (!item || !this.sessions.has(item.id)) {
            this.state.recentlyClosed = this.state.recentlyClosed.filter(entry => entry.id !== item.id);
            this.save();
            if (window.toast) window.toast.info('That session is no longer available.', { key: 'session' });
            return;
        }
        this.rememberOpen(item.id);
        this.render();
        this.controller.switchToSession(item.id);
        this.closeMenu();
    }

    async duplicate(sessionId) {
        const session = this.sessions.get(sessionId);
        if (!session) return;
        const clusterId = session.cluster && session.cluster.id ? session.cluster.id : null;
        const data = await this.controller.api.createSession(`${session.name} (copy)`, 'manual', clusterId);
        if (data.success && data.session) {
            this.rememberOpen(data.session.id);
            await this.controller.loadSessions('manual');
            await this.controller.switchToSession(data.session.id);
        } else if (window.toast) {
            window.toast.error(data.error || 'Could not duplicate session', { key: 'session' });
        }
        this.closeMenu();
    }

    startRename(sessionId) {
        const session = this.sessions.get(sessionId);
        const tab = this.getTabElement(sessionId);
        if (!session || !tab || this.renamingId) return;
        this.closeMenu();
        this.renamingId = sessionId;
        const title = tab.querySelector('.session-tab-title');
        if (!title) {
            this.renamingId = null;
            return;
        }
        const input = document.createElement('input');
        input.className = 'session-tab-rename';
        input.value = session.name;
        input.setAttribute('aria-label', 'Session name');
        title.replaceWith(input);
        input.focus();
        input.select();
        let settled = false;
        const finish = async (commit) => {
            if (settled) return;
            settled = true;
            this.renamingId = null;
            const next = input.value.trim();
            if (commit && next && next !== session.name) {
                const data = await this.controller.api.renameSession(sessionId, next);
                if (data.success && data.session) {
                    this.sessions.set(sessionId, data.session);
                    if (this.controller.activeSessionId === sessionId) {
                        const heading = document.getElementById('session-title');
                        if (heading) heading.textContent = data.session.name;
                    }
                } else if (window.toast) {
                    window.toast.error(data.error || 'Could not rename session', { key: 'session' });
                }
            }
            this.render();
        };
        input.addEventListener('click', (event) => event.stopPropagation());
        input.addEventListener('keydown', (event) => {
            event.stopPropagation();
            if (event.key === 'Enter') {
                event.preventDefault();
                finish(true);
            } else if (event.key === 'Escape') {
                event.preventDefault();
                finish(false);
            }
        });
        input.addEventListener('blur', () => finish(true));
    }

    async switchToSession(sessionId) {
        this.controller.setActiveSection('sessions');
        this.controller.activeSessionId = sessionId;
        this.syncActive();
        await this.controller.loadSessionDetails(sessionId);
        const content = document.getElementById('session-content');
        const empty = document.getElementById('no-session-message');
        if (content) content.style.display = 'flex';
        if (empty) empty.style.display = 'none';
        if (this.controller.wsManager) this.controller.wsManager.connect(sessionId);
    }

    async closeCurrent() {
        if (!this.controller.activeSessionId) return;
        this.closeTab(this.controller.activeSessionId);
    }

    async closeSession(sessionId) {
        this.closeTab(sessionId);
    }

    updateStatus(status) {
        const statusBadge = document.getElementById('session-status');
        if (statusBadge) {
            statusBadge.textContent = status || 'pending';
            statusBadge.className = `status-badge ${status || 'pending'}`;
        }
        const sessionId = this.controller.activeSessionId;
        if (!sessionId) return;
        const session = this.sessions.get(sessionId);
        if (session) session.status = status || 'pending';
        const tab = this.getTabElement(sessionId);
        if (tab) tab.dataset.status = status || 'pending';
    }

    bindChrome() {
        const create = document.getElementById('session-tab-new');
        if (create) {
            create.addEventListener('click', () => {
                this.controller.setActiveSection('sessions');
                this.controller.modals.showNewSession();
            });
        }
        const overflow = document.getElementById('session-tab-overflow');
        if (overflow) {
            overflow.addEventListener('click', (event) => {
                event.stopPropagation();
                this.toggleOverflow();
            });
        }
        const pinned = this.pinnedEl();
        const strip = this.stripEl();
        [pinned, strip].forEach(zone => {
            if (!zone) return;
            zone.addEventListener('dragover', (event) => event.preventDefault());
            zone.addEventListener('drop', (event) => {
                if (event.target.closest('.session-tab')) return;
                const sourceId = this.dragId || event.dataTransfer.getData('text/plain');
                if (!sourceId) return;
                event.preventDefault();
                this.setPinned(sourceId, zone === pinned);
            });
        });
        if (strip) {
            strip.addEventListener('wheel', (event) => {
                if (Math.abs(event.deltaY) <= Math.abs(event.deltaX)) return;
                strip.scrollLeft += event.deltaY;
                event.preventDefault();
            }, { passive: false });
        }
        if (strip && typeof ResizeObserver !== 'undefined') {
            this.resizeObserver = new ResizeObserver(() => this.fitStrip());
            this.resizeObserver.observe(strip);
        }
        const bar = this.bar();
        if (bar) {
            bar.addEventListener('contextmenu', (event) => {
                if (event.target.closest('.session-tab')) return;
                event.preventDefault();
                this.openMenu(event.clientX, event.clientY, this.controller.activeSessionId);
            });
        }
        document.addEventListener('click', (event) => {
            if (event.target.closest('#session-tab-overflow') || event.target.closest('.session-tab-menu')) return;
            this.closeMenu();
        });
        document.addEventListener('keydown', (event) => {
            if (event.key === 'Escape') this.closeMenu();
        });
        this.ensureMenu();
    }

    bindKeyboard() {
        document.addEventListener('keydown', (event) => {
            if (this.controller.activeSection !== 'sessions') return;
            if (this.isTyping(event.target)) return;
            const modal = document.getElementById('session-modal');
            if (modal && modal.classList.contains('active')) return;

            if (event.altKey && !event.ctrlKey && !event.metaKey && !event.shiftKey && event.key.toLowerCase() === 'n') {
                event.preventDefault();
                this.controller.modals.showNewSession();
                return;
            }
            if (event.altKey && !event.ctrlKey && !event.metaKey && !event.shiftKey && event.key.toLowerCase() === 'w') {
                event.preventDefault();
                this.closeCurrent();
                return;
            }
            if (event.ctrlKey && event.shiftKey && !event.altKey && !event.metaKey && event.key.toLowerCase() === 't') {
                event.preventDefault();
                this.reopenLast();
                return;
            }
            if (event.ctrlKey && !event.altKey && !event.metaKey && event.key === 'Tab') {
                event.preventDefault();
                this.cycle(event.shiftKey ? -1 : 1);
                return;
            }
            if (event.altKey && !event.ctrlKey && !event.metaKey && !event.shiftKey && /^[1-9]$/.test(event.key)) {
                event.preventDefault();
                this.activateIndex(Number(event.key));
            }
        });
    }

    isTyping(target) {
        if (!target || !target.closest) return false;
        const tag = target.tagName;
        return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || target.isContentEditable;
    }

    cycle(step) {
        const ids = this.visualIds();
        if (!ids.length) return;
        const current = ids.indexOf(this.controller.activeSessionId);
        const next = current < 0 ? 0 : (current + step + ids.length) % ids.length;
        this.controller.switchToSession(ids[next]);
    }

    activateIndex(number) {
        const ids = this.visualIds();
        if (!ids.length) return;
        const id = number === 9 ? ids[ids.length - 1] : ids[number - 1];
        if (id) this.controller.switchToSession(id);
    }

    ensureMenu() {
        if (document.getElementById('session-tab-menu')) return;
        const menu = document.createElement('div');
        menu.id = 'session-tab-menu';
        menu.className = 'session-tab-menu';
        menu.hidden = true;
        menu.setAttribute('role', 'menu');
        menu.innerHTML = `
            <button type="button" role="menuitem" data-action="new">New session <kbd>Alt+N</kbd></button>
            <button type="button" role="menuitem" data-action="rename">Rename</button>
            <button type="button" role="menuitem" data-action="duplicate">Duplicate</button>
            <button type="button" role="menuitem" data-action="pin">Pin</button>
            <div class="session-tab-menu-sep"></div>
            <button type="button" role="menuitem" data-action="close">Close <kbd>Alt+W</kbd></button>
            <button type="button" role="menuitem" data-action="close-others">Close others</button>
            <button type="button" role="menuitem" data-action="close-right">Close to the right</button>
            <div class="session-tab-menu-sep"></div>
            <button type="button" role="menuitem" data-action="reopen-toggle">Reopen closed <kbd>Ctrl+Shift+T</kbd></button>
            <div id="session-tab-reopen" hidden></div>
        `;
        const overflow = document.createElement('div');
        overflow.id = 'session-tab-overflow-panel';
        overflow.className = 'session-tab-menu';
        overflow.hidden = true;
        overflow.setAttribute('role', 'menu');
        overflow.innerHTML = `
            <input id="session-tab-search" type="search" placeholder="Search all sessions" aria-label="Search all sessions">
            <div id="session-tab-overflow-list"></div>
            <div class="session-tab-menu-heading">Recently closed</div>
            <div id="session-tab-recent"></div>
        `;
        document.body.append(menu, overflow);
        menu.addEventListener('click', (event) => {
            const action = event.target.closest('[data-action]');
            if (!action) return;
            this.runMenuAction(action.dataset.action);
        });
        menu.addEventListener('keydown', (event) => this.onMenuKey(event, menu));
        overflow.addEventListener('click', (event) => {
            const button = event.target.closest('[data-open-id]');
            if (!button) return;
            const id = button.dataset.openId;
            const kind = button.dataset.openKind;
            if (kind === 'recent') {
                const item = this.state.recentlyClosed.find(entry => entry.id === id);
                if (item) this.reopen(item);
            } else {
                this.rememberOpen(id);
                this.render();
                this.controller.switchToSession(id);
                this.closeMenu();
            }
        });
        const search = overflow.querySelector('#session-tab-search');
        if (search) search.addEventListener('input', () => this.fillOverflow(search.value));
    }

    openMenu(x, y, sessionId) {
        this.ensureMenu();
        this.menuSessionId = sessionId || null;
        const menu = document.getElementById('session-tab-menu');
        const overflow = document.getElementById('session-tab-overflow-panel');
        if (overflow) overflow.hidden = true;
        const pinned = sessionId && this.state.pinnedIds.includes(sessionId);
        menu.querySelector('[data-action="pin"]').textContent = pinned ? 'Unpin' : 'Pin';
        menu.querySelector('#session-tab-reopen').hidden = true;
        menu.querySelectorAll('[data-action]').forEach(button => {
            const needsTab = button.dataset.action !== 'new' && button.dataset.action !== 'reopen-toggle';
            button.disabled = needsTab && !sessionId;
        });
        menu.hidden = false;
        this.position(menu, x, y);
        const first = menu.querySelector('button:not(:disabled)');
        if (first) first.focus();
    }

    toggleOverflow() {
        this.ensureMenu();
        const menu = document.getElementById('session-tab-menu');
        const panel = document.getElementById('session-tab-overflow-panel');
        if (menu) menu.hidden = true;
        const button = document.getElementById('session-tab-overflow');
        if (!panel || !button) return;
        if (!panel.hidden) {
            panel.hidden = true;
            return;
        }
        const search = panel.querySelector('#session-tab-search');
        if (search) search.value = '';
        this.fillOverflow('');
        panel.hidden = false;
        const rect = button.getBoundingClientRect();
        this.position(panel, rect.right, rect.bottom);
        if (search) search.focus();
    }

    fillOverflow(query) {
        const list = document.getElementById('session-tab-overflow-list');
        const recent = document.getElementById('session-tab-recent');
        if (!list || !recent) return;
        const needle = (query || '').trim().toLowerCase();
        const sessions = [...this.sessions.values()]
            .filter(session => !needle || session.name.toLowerCase().includes(needle) || (session.cluster && session.cluster.name && session.cluster.name.toLowerCase().includes(needle)))
            .sort((a, b) => String(b.updated_at || '').localeCompare(String(a.updated_at || '')));
        list.replaceChildren();
        if (!sessions.length) {
            const empty = document.createElement('div');
            empty.className = 'is-empty';
            empty.textContent = 'No matching sessions';
            list.append(empty);
        } else {
            sessions.forEach(session => list.append(this.menuSessionButton(session, 'catalog')));
        }
        recent.replaceChildren();
        const closed = this.state.recentlyClosed.filter(item => !needle || item.name.toLowerCase().includes(needle));
        if (!closed.length) {
            const empty = document.createElement('div');
            empty.className = 'is-empty';
            empty.textContent = 'Nothing recently closed';
            recent.append(empty);
        } else {
            closed.forEach(item => {
                const button = document.createElement('button');
                button.type = 'button';
                button.dataset.openId = item.id;
                button.dataset.openKind = 'recent';
                button.textContent = item.name;
                recent.append(button);
            });
        }
    }

    menuSessionButton(session, kind) {
        const button = document.createElement('button');
        button.type = 'button';
        button.dataset.openId = session.id;
        button.dataset.openKind = kind;
        const parked = this.parkedIds.includes(session.id);
        button.textContent = parked ? `${session.name} (overflow)` : session.name;
        return button;
    }

    position(menu, x, y) {
        menu.style.left = '0px';
        menu.style.top = '0px';
        const rect = menu.getBoundingClientRect();
        const left = Math.max(8, Math.min(x, window.innerWidth - rect.width - 8));
        const top = Math.max(8, Math.min(y, window.innerHeight - rect.height - 8));
        menu.style.left = `${left}px`;
        menu.style.top = `${top}px`;
    }

    closeMenu() {
        const menu = document.getElementById('session-tab-menu');
        const panel = document.getElementById('session-tab-overflow-panel');
        if (menu) menu.hidden = true;
        if (panel) panel.hidden = true;
        this.menuSessionId = null;
    }

    onMenuKey(event, menu) {
        const items = [...menu.querySelectorAll('button:not(:disabled)')];
        const index = items.indexOf(document.activeElement);
        if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
            event.preventDefault();
            const step = event.key === 'ArrowDown' ? 1 : -1;
            const next = items[(index + step + items.length) % items.length];
            if (next) next.focus();
        } else if (event.key === 'Enter' && document.activeElement && document.activeElement.dataset) {
            event.preventDefault();
            this.runMenuAction(document.activeElement.dataset.action);
        }
    }

    runMenuAction(action) {
        const id = this.menuSessionId;
        if (action === 'new') {
            this.closeMenu();
            this.controller.modals.showNewSession();
        } else if (action === 'rename' && id) {
            this.startRename(id);
        } else if (action === 'duplicate' && id) {
            this.duplicate(id);
        } else if (action === 'pin' && id) {
            this.setPinned(id, !this.state.pinnedIds.includes(id));
            this.closeMenu();
        } else if (action === 'close' && id) {
            this.closeTab(id);
        } else if (action === 'close-others' && id) {
            this.closeOthers(id);
        } else if (action === 'close-right' && id) {
            this.closeToTheRight(id);
        } else if (action === 'reopen-toggle') {
            const box = document.getElementById('session-tab-reopen');
            if (!box) return;
            box.hidden = !box.hidden;
            box.replaceChildren();
            if (box.hidden) return;
            if (!this.state.recentlyClosed.length) {
                const empty = document.createElement('div');
                empty.className = 'is-empty';
                empty.textContent = 'Nothing to reopen';
                box.append(empty);
                return;
            }
            this.state.recentlyClosed.forEach(item => {
                const button = document.createElement('button');
                button.type = 'button';
                button.textContent = item.name;
                button.addEventListener('click', (event) => {
                    event.stopPropagation();
                    this.reopen(item);
                });
                box.append(button);
            });
        }
    }
}
