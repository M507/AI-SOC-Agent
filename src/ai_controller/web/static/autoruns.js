// Autorun management

class AutorunManager {
    constructor(controller) {
        this.controller = controller;
        this.autoruns = new Map();
        this.currentAutorunId = null;
        this.deletedAutorunIds = new Set();
        this.order = [];
        this.pinnedIds = [];
        this.parkedIds = [];
        this.dragId = null;
        this.loadState();
        this.attachEventListeners();
        this.bindChrome();
    }

    /**
     * Update autoruns list and render tabs.
     */
    updateAutoruns(autoruns) {
        const pinnedHost = document.getElementById('autorun-tab-pinned');
        const strip = document.getElementById('autoruns-tabs');
        if (!pinnedHost || !strip) {
            console.error('[AutorunManager] autoruns tab bar not found');
            return;
        }

        this.autoruns.clear();
        const activeAutoruns = autoruns.filter(a => !this.deletedAutorunIds.has(a.id));
        activeAutoruns.forEach(autorun => this.autoruns.set(autorun.id, autorun));

        const known = new Set(activeAutoruns.map(autorun => autorun.id));
        this.pinnedIds = this.pinnedIds.filter(id => known.has(id));
        this.order = this.order.filter(id => known.has(id));
        activeAutoruns.forEach(autorun => {
            if (!this.order.includes(autorun.id)) this.order.push(autorun.id);
        });
        this.save();

        const pinned = this.visualIds().filter(id => this.pinnedIds.includes(id));
        const normal = this.visualIds().filter(id => !this.pinnedIds.includes(id));
        pinnedHost.replaceChildren(...pinned.map(id => this.createTab(this.autoruns.get(id))).filter(Boolean));
        strip.replaceChildren(...normal.map(id => this.createTab(this.autoruns.get(id))).filter(Boolean));
        const divider = document.getElementById('autorun-tab-divider');
        if (divider) divider.hidden = pinned.length === 0;
        this.markActive();
        this.fitStrip();

        if (this.controller.activeSection === 'autoruns') {
            this.syncView();
        }
    }

    visualIds() {
        const pinned = new Set(this.pinnedIds);
        return [
            ...this.order.filter(id => pinned.has(id) && this.autoruns.has(id)),
            ...this.order.filter(id => !pinned.has(id) && this.autoruns.has(id)),
        ];
    }

    /**
     * Show either the empty state or the selected job. Never leave the
     * details chrome visible without a selected autorun.
     */
    syncView() {
        if (this.controller.activeSection !== 'autoruns') {
            this.setPanelOpen(false);
            this.setEmptyVisible(false);
            return;
        }

        if (this.autoruns.size === 0) {
            this.currentAutorunId = null;
            this.setPanelOpen(false);
            this.setEmptyVisible(true);
            return;
        }

        const selected = (this.currentAutorunId && this.autoruns.has(this.currentAutorunId))
            ? this.currentAutorunId
            : this.autoruns.keys().next().value;
        this.showAutorunDetails(selected);
    }

    setPanelOpen(open) {
        const autorunContent = document.getElementById('autorun-content');
        const contentArea = document.querySelector('.content-area');
        if (autorunContent) {
            autorunContent.classList.toggle('is-open', Boolean(open));
            autorunContent.hidden = !open;
        }
        if (contentArea) {
            contentArea.classList.toggle('has-autorun', Boolean(open));
        }
    }

    setEmptyVisible(visible) {
        const autorunEmpty = document.getElementById('autorun-empty-message');
        if (autorunEmpty) {
            autorunEmpty.style.display = visible ? 'flex' : 'none';
        }
    }

    /**
     * Create an autorun tab element.
     */
    createTab(autorun) {
        if (!autorun) return null;
        const pinned = this.pinnedIds.includes(autorun.id);
        const tab = document.createElement('button');
        tab.type = 'button';
        tab.className = 'session-tab' + (pinned ? ' is-pinned' : '');
        tab.dataset.autorunId = autorun.id;
        tab.dataset.status = autorun.enabled ? 'running' : 'stopped';
        tab.setAttribute('role', 'tab');
        tab.setAttribute('draggable', 'true');
        tab.title = this.tooltip(autorun);
        tab.setAttribute('aria-label', autorun.name || 'Autorun');

        const title = document.createElement('span');
        title.className = 'session-tab-title';
        title.textContent = autorun.name || 'Autorun';

        const close = document.createElement('span');
        close.className = 'session-tab-close';
        close.setAttribute('role', 'button');
        close.setAttribute('aria-label', `Close ${autorun.name || 'autorun'}`);
        close.textContent = '×';

        const mark = document.createElement('span');
        mark.className = 'session-tab-status';
        mark.setAttribute('aria-hidden', 'true');
        tab.append(mark, title, close);

        tab.addEventListener('click', (event) => {
            if (event.target.closest('.session-tab-close')) return;
            this.showAutorunDetails(autorun.id);
        });
        close.addEventListener('click', (event) => {
            event.stopPropagation();
            event.preventDefault();
            this.deleteAutorun(autorun.id);
        });
        tab.addEventListener('auxclick', (event) => {
            if (event.button !== 1) return;
            event.preventDefault();
            this.deleteAutorun(autorun.id);
        });
        tab.addEventListener('contextmenu', (event) => {
            event.preventDefault();
            this.openMenu(event.clientX, event.clientY, autorun.id);
        });
        tab.addEventListener('dragstart', (event) => {
            this.dragId = autorun.id;
            event.dataTransfer.setData('text/plain', autorun.id);
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
            this.dropOn(sourceId, autorun.id, event.clientX, tab);
        });
        tab.addEventListener('dragend', () => {
            this.dragId = null;
            tab.classList.remove('is-drop-target');
        });
        return tab;
    }

    tooltip(autorun) {
        const parts = [autorun.name || 'Autorun'];
        if (autorun.cluster && autorun.cluster.name) parts.push(autorun.cluster.name);
        if (autorun.interval_seconds) parts.push(formatInterval(autorun.interval_seconds));
        return parts.join(' · ');
    }

    /**
     * Attach event listeners for autorun action buttons.
     */
    attachEventListeners() {
        const editBtn = document.getElementById('autorun-edit-btn');
        const toggleBtn = document.getElementById('autorun-toggle-btn');
        const clearBtn = document.getElementById('autorun-clear-btn');
        const exportBtn = document.getElementById('autorun-export-btn');
        const deleteBtn = document.getElementById('autorun-delete-btn');
        const closeEditBtn = document.getElementById('close-edit-autorun-modal');
        const cancelEditBtn = document.getElementById('cancel-edit-autorun-btn');
        const saveEditBtn = document.getElementById('save-autorun-settings-btn');
        const editInterval = document.getElementById('edit-autorun-interval');

        if (editBtn) {
            editBtn.addEventListener('click', () => {
                if (!this.currentAutorunId) return;
                this.showEditModal(this.currentAutorunId);
            });
        }

        if (toggleBtn) {
            toggleBtn.addEventListener('click', () => {
                if (!this.currentAutorunId) return;
                this.toggleAutorun(this.currentAutorunId);
            });
        }

        if (clearBtn) {
            clearBtn.addEventListener('click', () => {
                if (!this.currentAutorunId) return;
                this.clearAutorun(this.currentAutorunId);
            });
        }

        if (exportBtn) {
            exportBtn.addEventListener('click', () => {
                if (!this.currentAutorunId) return;
                this.exportAutorun(this.currentAutorunId);
            });
        }

        if (deleteBtn) {
            deleteBtn.addEventListener('click', () => {
                if (!this.currentAutorunId) return;
                this.deleteAutorun(this.currentAutorunId);
            });
        }
        if (closeEditBtn) closeEditBtn.addEventListener('click', () => this.hideEditModal());
        if (cancelEditBtn) cancelEditBtn.addEventListener('click', () => this.hideEditModal());
        if (saveEditBtn) saveEditBtn.addEventListener('click', () => this.saveAutorunSettings());
        if (editInterval) {
            editInterval.addEventListener('input', () => this.updateEditIntervalPreview());
        }
        window.addEventListener('click', (event) => {
            const modal = document.getElementById('edit-autorun-modal');
            if (event.target === modal) this.hideEditModal();
        });
    }

    /**
     * Show details for a specific autorun.
     */
    showAutorunDetails(autorunId) {
        const autorun = this.autoruns.get(autorunId);
        if (!autorun) {
            console.warn('[AutorunManager] Autorun not found:', autorunId);
            return;
        }

        this.currentAutorunId = autorunId;
        if (this.controller.activeSection !== 'autoruns') {
            this.controller.setActiveSection('autoruns');
            return;
        }

        document.querySelectorAll('#autoruns-tab-group .session-tab').forEach(tab => {
            const on = tab.dataset.autorunId === autorunId;
            tab.classList.toggle('active', on);
            tab.setAttribute('aria-selected', on ? 'true' : 'false');
        });

        const sessionContent = document.getElementById('session-content');
        const noSessionMessage = document.getElementById('no-session-message');
        if (sessionContent) sessionContent.style.display = 'none';
        document.querySelectorAll('[data-settings-page-content]').forEach((panel) => {
            panel.style.display = 'none';
        });
        if (noSessionMessage) noSessionMessage.style.display = 'none';
        this.setEmptyVisible(false);
        this.setPanelOpen(true);

        // Populate details
        const titleEl = document.getElementById('autorun-title');
        const statusEl = document.getElementById('autorun-status');
        const promptEl = document.getElementById('autorun-prompt');
        const conditionDisplayEl = document.getElementById('autorun-condition-display');
        const conditionValueEl = document.getElementById('autorun-condition-value');
        const intervalEl = document.getElementById('autorun-interval-display');
        const metaEl = document.getElementById('autorun-meta');
        const toggleBtn = document.getElementById('autorun-toggle-btn');

        if (titleEl) titleEl.textContent = autorun.name || 'Autorun';

        if (statusEl) {
            const statusClass = autorun.enabled ? 'completed' : 'stopped';
            statusEl.className = `status-badge ${statusClass}`;
            statusEl.textContent = autorun.enabled ? 'Enabled' : 'Disabled';
        }

        if (promptEl) {
            promptEl.textContent = autorun.command || '';
        }

        // Show condition function if set
        if (conditionDisplayEl && conditionValueEl) {
            if (autorun.condition_function) {
                conditionDisplayEl.style.display = 'block';
                conditionValueEl.textContent = autorun.condition_function;
            } else {
                conditionDisplayEl.style.display = 'none';
            }
        }

        if (intervalEl) {
            intervalEl.textContent = formatIntervalPreview(autorun.interval_seconds);
        }

        if (metaEl) {
            const parts = [];
            if (autorun.last_run) {
                parts.push(`Last run: ${new Date(autorun.last_run).toLocaleString()}`);
            }
            if (autorun.next_run) {
                parts.push(`Next run: ${new Date(autorun.next_run).toLocaleString()}`);
            }
            metaEl.textContent = parts.join(' • ');
        }

        if (toggleBtn) {
            toggleBtn.textContent = autorun.enabled ? 'Disable' : 'Enable';
        }
        if (this.controller.setClusterPill) {
            this.controller.setClusterPill('autorun-cluster', autorun.cluster);
        }

        // Load and render the backing session as a long-running chat in the autorun terminal
        if (this.controller && this.controller.loadAutorunSession) {
            this.controller.loadAutorunSession(autorun);
        }
    }

    showEditModal(autorunId) {
        const autorun = this.autoruns.get(autorunId);
        const modal = document.getElementById('edit-autorun-modal');
        if (!autorun || !modal) return;

        const condition = splitConditionFunction(autorun.condition_function);
        document.getElementById('edit-autorun-name').value = autorun.name || '';
        document.getElementById('edit-autorun-command').value = autorun.command || '';
        document.getElementById('edit-autorun-condition').value = condition.name;
        document.getElementById('edit-autorun-condition-limit').value = condition.limit;
        document.getElementById('edit-autorun-interval').value = autorun.interval_seconds || 300;
        if (this.controller.elasticClusters) {
            this.controller.elasticClusters.fillSelect(
                document.getElementById('edit-autorun-cluster-select'),
                autorun.cluster_id
            );
        }
        this.updateEditIntervalPreview();
        modal.style.display = 'flex';
        document.getElementById('edit-autorun-name').focus();
    }

    hideEditModal() {
        const modal = document.getElementById('edit-autorun-modal');
        if (modal) modal.style.display = 'none';
    }

    updateEditIntervalPreview() {
        const interval = document.getElementById('edit-autorun-interval');
        const preview = document.getElementById('edit-autorun-interval-preview');
        if (interval && preview) preview.textContent = formatIntervalPreview(interval.value);
    }

    async saveAutorunSettings() {
        const autorunId = this.currentAutorunId;
        const autorun = autorunId ? this.autoruns.get(autorunId) : null;
        if (!autorun) return;

        const name = document.getElementById('edit-autorun-name').value.trim();
        const command = document.getElementById('edit-autorun-command').value.trim();
        const condition = joinConditionFunction(
            document.getElementById('edit-autorun-condition').value,
            document.getElementById('edit-autorun-condition-limit').value
        ) || null;
        const intervalSeconds = Number.parseInt(
            document.getElementById('edit-autorun-interval').value,
            10
        );
        if (!name || !command) {
            if (window.toast) {
                window.toast.info('Name and starting prompt are required.', { key: 'autorun-edit' });
            }
            return;
        }
        if (!Number.isFinite(intervalSeconds) || intervalSeconds < 5) {
            if (window.toast) {
                window.toast.info('Interval must be at least 5 seconds.', { key: 'autorun-edit' });
            }
            return;
        }

        const clusterId = this.controller.elasticClusters
            ? this.controller.elasticClusters.selectedClusterId('edit-autorun-cluster-select')
            : autorun.cluster_id;
        const result = await this.controller.api.updateAutorun(autorunId, {
            name,
            command,
            condition_function: condition,
            interval_seconds: intervalSeconds,
            cluster_id: clusterId,
        });
        if (!result || !result.success) {
            if (window.toast) {
                window.toast.error(result.error || 'Could not save autorun settings.', { key: 'autorun-edit' });
            }
            return;
        }

        this.hideEditModal();
        await this.controller.loadAutoruns();
        this.showAutorunDetails(autorunId);
        if (window.toast) {
            window.toast.success('Autorun settings saved.', { key: 'autorun-edit' });
        }
    }

    /**
     * Toggle enabled/disabled state for an autorun.
     */
    async toggleAutorun(autorunId) {
        const autorun = this.autoruns.get(autorunId);
        if (!autorun) return;

        const newEnabled = !autorun.enabled;

        try {
            const result = await this.controller.api.updateAutorun(autorunId, { enabled: newEnabled });
            if (result && result.success) {
                if (window.toast) {
                    window.toast.success(
                        newEnabled
                            ? 'Autorun enabled; an immediate run has been scheduled.'
                            : 'Autorun disabled; its timer has been stopped.',
                        { key: 'autorun' }
                    );
                }
                await this.controller.loadAutoruns();
                this.showAutorunDetails(autorunId);
            } else {
                if (window.toast) {
                    window.toast.error(result.error || 'Could not update autorun', { key: 'autorun' });
                }
            }
        } catch (error) {
            console.error('[AutorunManager] Error updating autorun:', error);
            if (window.toast) {
                window.toast.error('Could not update autorun.', { key: 'autorun' });
            }
        }
    }

    /**
     * Clear all entries from an autorun's backing session.
     */
    async clearAutorun(autorunId) {
        if (!autorunId) {
            console.error('[AutorunManager] clearAutorun called with null/undefined autorunId');
            return;
        }

        const confirmClear = confirm('Clear all chat history for this autorun? This cannot be undone.');
        if (!confirmClear) return;

        console.log(`[AutorunManager] Clearing autorun session ${autorunId}`);

        try {
            const result = await this.controller.api.clearAutorunSession(autorunId);
            if (result && result.success) {
                if (window.toast) {
                    window.toast.success('Autorun history cleared.', { key: 'autorun' });
                }
                const autorun = this.autoruns.get(autorunId);
                if (autorun && this.controller.loadAutorunSession) {
                    await this.controller.loadAutorunSession(autorun);
                }
            } else {
                console.error('[AutorunManager] Backend clear failed:', result);
                if (window.toast) {
                    window.toast.error(result.error || 'Could not clear autorun history', { key: 'autorun' });
                }
            }
        } catch (error) {
            console.error('[AutorunManager] Error clearing autorun session:', error);
            if (window.toast) {
                window.toast.error('Could not clear autorun history.', { key: 'autorun' });
            }
        }
    }

    /**
     * Export autorun chat as PDF.
     */
    async exportAutorun(autorunId) {
        if (!autorunId) {
            console.error('[AutorunManager] ERROR: exportAutorun called with null/undefined autorunId');
            return;
        }

        const autorun = this.autoruns.get(autorunId);
        if (!autorun) {
            console.error('[AutorunManager] ERROR: Autorun not found for export:', autorunId);
            console.log('[AutorunManager] Available autoruns:', Array.from(this.autoruns.keys()));
            return;
        }

        // Get terminal element for fallback
        const terminal = document.getElementById('autorun-terminal');
        
        // Use the PDF exporter
        await pdfExporter.exportAutorun(autorun, this.controller, terminal);
    }

    /**
     * Delete an autorun from UI and backend.
     */
    async deleteAutorun(autorunId) {
        if (!autorunId) {
            console.error('[AutorunManager] deleteAutorun called with null/undefined autorunId');
            return;
        }

        const confirmDelete = confirm('Delete this autorun? This cannot be undone.');
        if (!confirmDelete) return;

        console.log(`[AutorunManager] Deleting autorun ${autorunId}`);

        // Mark as deleted immediately to prevent any recreation
        this.deletedAutorunIds.add(autorunId);

        // Remove from local cache
        this.autoruns.delete(autorunId);
        this.order = this.order.filter(id => id !== autorunId);
        this.pinnedIds = this.pinnedIds.filter(id => id !== autorunId);
        this.save();

        // Remove tab from DOM
        const tab = document.querySelector(`#autoruns-tab-group .session-tab[data-autorun-id="${autorunId}"]`);
        if (tab && tab.parentNode) {
            tab.parentNode.removeChild(tab);
        }

        // If this was the currently selected autorun, clear details panel
        if (this.currentAutorunId === autorunId) {
            this.currentAutorunId = null;
            this.setPanelOpen(false);
        }

        try {
            const deleteResult = await this.controller.api.deleteAutorun(autorunId);
            if (deleteResult && deleteResult.success) {
                if (window.toast) {
                    window.toast.success('Autorun deleted.', { key: 'autorun' });
                }
            } else {
                console.error('[AutorunManager] Backend delete failed:', deleteResult);
                this.deletedAutorunIds.delete(autorunId);
                if (window.toast) {
                    window.toast.error(deleteResult.error || 'Could not delete autorun', { key: 'autorun' });
                }
            }
        } catch (error) {
            console.error('[AutorunManager] Error deleting autorun from backend:', error);
            this.deletedAutorunIds.delete(autorunId);
            if (window.toast) {
                window.toast.error('Could not delete autorun.', { key: 'autorun' });
            }
        }

        if (this.controller.activeSection === 'autoruns') {
            this.syncView();
        }
    }

    loadState() {
        try {
            const raw = localStorage.getItem('samigpt.autorunTabs');
            const parsed = raw ? JSON.parse(raw) : {};
            this.order = Array.isArray(parsed.order) ? parsed.order : [];
            this.pinnedIds = Array.isArray(parsed.pinnedIds) ? parsed.pinnedIds : [];
        } catch (error) {
            this.order = [];
            this.pinnedIds = [];
        }
    }

    save() {
        localStorage.setItem('samigpt.autorunTabs', JSON.stringify({
            order: this.order,
            pinnedIds: this.pinnedIds,
        }));
    }

    markActive() {
        const bar = document.getElementById('autoruns-tab-group');
        if (!bar) return;
        bar.querySelectorAll('.session-tab').forEach(tab => {
            const on = tab.dataset.autorunId === this.currentAutorunId;
            tab.classList.toggle('active', on);
            tab.setAttribute('aria-selected', on ? 'true' : 'false');
        });
    }

    fitStrip() {
        const strip = document.getElementById('autoruns-tabs');
        const button = document.getElementById('autorun-tab-overflow');
        if (!strip) return;
        const tabs = [...strip.querySelectorAll('.session-tab')];
        tabs.forEach(tab => {
            tab.hidden = false;
        });
        this.parkedIds = [];
        const styles = getComputedStyle(strip);
        const gap = parseFloat(styles.columnGap || styles.gap || '0') || 0;
        let used = 0;
        const keep = [];
        const parked = [];
        tabs.forEach(tab => {
            const next = used + 88 + (keep.length ? gap : 0);
            if (next <= strip.clientWidth || keep.length === 0) {
                keep.push(tab);
                used = next;
            } else {
                parked.push(tab);
            }
        });
        const activeParked = parked.find(tab => tab.dataset.autorunId === this.currentAutorunId);
        if (activeParked && keep.length) {
            const displaced = keep.pop();
            parked.splice(parked.indexOf(activeParked), 1);
            parked.unshift(displaced);
            keep.push(activeParked);
        }
        parked.forEach(tab => {
            tab.hidden = true;
        });
        this.parkedIds = parked.map(tab => tab.dataset.autorunId);
        if (button) button.classList.toggle('has-overflow', parked.length > 0);
    }

    dropOn(sourceId, targetId, clientX, targetEl) {
        if (!sourceId || sourceId === targetId) return;
        const rect = targetEl.getBoundingClientRect();
        const before = clientX < rect.left + rect.width / 2;
        const pin = this.pinnedIds.includes(targetId);
        const pinnedOrder = this.visualIds().filter(id => this.pinnedIds.includes(id) && id !== sourceId);
        const normalOrder = this.visualIds().filter(id => !this.pinnedIds.includes(id) && id !== sourceId);
        const list = pin ? pinnedOrder : normalOrder;
        let index = list.indexOf(targetId);
        if (index < 0) index = list.length;
        else if (!before) index += 1;
        list.splice(index, 0, sourceId);
        if (pin) {
            this.pinnedIds = list.slice();
            this.order = [...list, ...normalOrder];
        } else {
            this.pinnedIds = pinnedOrder.slice();
            this.order = [...pinnedOrder, ...list];
        }
        this.save();
        this.controller.loadAutoruns();
    }

    setPinned(autorunId, pinned) {
        if (pinned) {
            if (!this.pinnedIds.includes(autorunId)) this.pinnedIds.push(autorunId);
        } else {
            this.pinnedIds = this.pinnedIds.filter(id => id !== autorunId);
        }
        const pinnedOrder = this.visualIds().filter(id => this.pinnedIds.includes(id));
        const normalOrder = this.visualIds().filter(id => !this.pinnedIds.includes(id));
        this.order = [...pinnedOrder, ...normalOrder];
        this.save();
        this.controller.loadAutoruns();
    }

    bindChrome() {
        const create = document.getElementById('autorun-tab-new');
        if (create) {
            create.addEventListener('click', () => {
                this.controller.setActiveSection('autoruns');
                this.controller.modals.showNewAutorun();
            });
        }
        const overflow = document.getElementById('autorun-tab-overflow');
        if (overflow) {
            overflow.addEventListener('click', (event) => {
                event.stopPropagation();
                this.toggleOverflow();
            });
        }
        const strip = document.getElementById('autoruns-tabs');
        const pinned = document.getElementById('autorun-tab-pinned');
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
            if (typeof ResizeObserver !== 'undefined') {
                this.resizeObserver = new ResizeObserver(() => this.fitStrip());
                this.resizeObserver.observe(strip);
            }
        }
        const bar = document.getElementById('autoruns-tab-group');
        if (bar) {
            bar.addEventListener('contextmenu', (event) => {
                if (event.target.closest('.session-tab')) return;
                event.preventDefault();
                this.openMenu(event.clientX, event.clientY, this.currentAutorunId);
            });
        }
        document.addEventListener('click', (event) => {
            if (event.target.closest('#autorun-tab-overflow') || event.target.closest('#autorun-tab-menu')) return;
            this.closeMenu();
        });
        document.addEventListener('keydown', (event) => this.onKey(event));
    }

    onKey(event) {
        if (this.controller.activeSection !== 'autoruns') return;
        const tag = event.target && event.target.tagName;
        if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || (event.target && event.target.isContentEditable)) return;
        const modal = document.getElementById('new-autorun-modal');
        if (modal && modal.style.display === 'flex') return;

        if (event.altKey && !event.ctrlKey && !event.metaKey && !event.shiftKey && event.key.toLowerCase() === 'n') {
            event.preventDefault();
            this.controller.modals.showNewAutorun();
            return;
        }
        if (event.altKey && !event.ctrlKey && !event.metaKey && !event.shiftKey && event.key.toLowerCase() === 'w') {
            event.preventDefault();
            if (this.currentAutorunId) this.deleteAutorun(this.currentAutorunId);
            return;
        }
        if (event.ctrlKey && !event.altKey && !event.metaKey && event.key === 'Tab') {
            event.preventDefault();
            const ids = this.visualIds();
            if (!ids.length) return;
            const current = ids.indexOf(this.currentAutorunId);
            const next = current < 0 ? 0 : (current + (event.shiftKey ? -1 : 1) + ids.length) % ids.length;
            this.showAutorunDetails(ids[next]);
            return;
        }
        if (event.altKey && !event.ctrlKey && !event.metaKey && !event.shiftKey && /^[1-9]$/.test(event.key)) {
            event.preventDefault();
            const ids = this.visualIds();
            const number = Number(event.key);
            const id = number === 9 ? ids[ids.length - 1] : ids[number - 1];
            if (id) this.showAutorunDetails(id);
        }
    }

    toggleOverflow() {
        this.ensureMenu();
        const panel = document.getElementById('autorun-tab-overflow-panel');
        const button = document.getElementById('autorun-tab-overflow');
        if (!panel || !button) return;
        if (!panel.hidden) {
            panel.hidden = true;
            return;
        }
        const search = panel.querySelector('input');
        if (search) search.value = '';
        this.fillOverflow('');
        panel.hidden = false;
        const rect = button.getBoundingClientRect();
        panel.style.left = `${Math.max(8, rect.right - 240)}px`;
        panel.style.top = `${rect.bottom}px`;
        if (search) search.focus();
    }

    fillOverflow(query) {
        const list = document.getElementById('autorun-tab-overflow-list');
        if (!list) return;
        const needle = (query || '').trim().toLowerCase();
        const autoruns = [...this.autoruns.values()].filter(autorun => !needle || (autorun.name || '').toLowerCase().includes(needle));
        list.replaceChildren();
        if (!autoruns.length) {
            const empty = document.createElement('div');
            empty.className = 'is-empty';
            empty.textContent = 'No matching autoruns';
            list.append(empty);
            return;
        }
        autoruns.forEach(autorun => {
            const button = document.createElement('button');
            button.type = 'button';
            button.textContent = autorun.name || 'Autorun';
            button.addEventListener('click', () => {
                this.showAutorunDetails(autorun.id);
                this.closeMenu();
            });
            list.append(button);
        });
    }

    ensureMenu() {
        if (document.getElementById('autorun-tab-menu')) return;
        const menu = document.createElement('div');
        menu.id = 'autorun-tab-menu';
        menu.className = 'session-tab-menu';
        menu.hidden = true;
        menu.setAttribute('role', 'menu');
        menu.innerHTML = `
            <button type="button" data-action="new">New autorun <kbd>Alt+N</kbd></button>
            <button type="button" data-action="pin">Pin</button>
            <button type="button" data-action="close">Close <kbd>Alt+W</kbd></button>
        `;
        const panel = document.createElement('div');
        panel.id = 'autorun-tab-overflow-panel';
        panel.className = 'session-tab-menu';
        panel.hidden = true;
        panel.innerHTML = `
            <input type="search" placeholder="Search all autoruns" aria-label="Search all autoruns">
            <div id="autorun-tab-overflow-list"></div>
        `;
        document.body.append(menu, panel);
        menu.addEventListener('click', (event) => {
            const action = event.target.closest('[data-action]');
            if (!action) return;
            const id = this.menuAutorunId;
            if (action.dataset.action === 'new') {
                this.closeMenu();
                this.controller.modals.showNewAutorun();
            } else if (action.dataset.action === 'pin' && id) {
                this.setPinned(id, !this.pinnedIds.includes(id));
                this.closeMenu();
            } else if (action.dataset.action === 'close' && id) {
                this.closeMenu();
                this.deleteAutorun(id);
            }
        });
        const search = panel.querySelector('input');
        if (search) search.addEventListener('input', () => this.fillOverflow(search.value));
    }

    openMenu(x, y, autorunId) {
        this.ensureMenu();
        this.menuAutorunId = autorunId || null;
        const menu = document.getElementById('autorun-tab-menu');
        const panel = document.getElementById('autorun-tab-overflow-panel');
        if (panel) panel.hidden = true;
        const pin = menu.querySelector('[data-action="pin"]');
        if (pin) pin.textContent = autorunId && this.pinnedIds.includes(autorunId) ? 'Unpin' : 'Pin';
        menu.querySelectorAll('[data-action]').forEach(button => {
            button.disabled = button.dataset.action !== 'new' && !autorunId;
        });
        menu.hidden = false;
        menu.style.left = `${x}px`;
        menu.style.top = `${y}px`;
    }

    closeMenu() {
        const menu = document.getElementById('autorun-tab-menu');
        const panel = document.getElementById('autorun-tab-overflow-panel');
        if (menu) menu.hidden = true;
        if (panel) panel.hidden = true;
        this.menuAutorunId = null;
    }
}
