// Autorun management

class AutorunManager {
    constructor(controller) {
        this.controller = controller;
        this.autoruns = new Map();
        this.currentAutorunId = null;
        this.deletedAutorunIds = new Set(); // Track permanently deleted autoruns

        this.attachEventListeners();
    }

    /**
     * Update autoruns list and render tabs.
     */
    updateAutoruns(autoruns) {
        const autorunsTabs = document.getElementById('autoruns-tabs');
        if (!autorunsTabs) {
            console.error('[AutorunManager] autoruns-tabs container not found');
            return;
        }

        autorunsTabs.innerHTML = '';
        this.autoruns.clear();

        const activeAutoruns = autoruns.filter(a => !this.deletedAutorunIds.has(a.id));
        activeAutoruns.forEach(autorun => {
            this.autoruns.set(autorun.id, autorun);
            autorunsTabs.appendChild(this.createTab(autorun));
        });

        if (this.controller.activeSection === 'autoruns') {
            this.syncView();
        }
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
        const tab = document.createElement('button');
        tab.className = 'tab';
        tab.dataset.autorunId = autorun.id;
        
        const statusBadge = autorun.enabled ? 'active' : '';
        const intervalText = formatInterval(autorun.interval_seconds);
        
        tab.innerHTML = `
            <span>${escapeHtml(autorun.name)}</span>
            ${autorun.cluster && autorun.cluster.name ? `<span class="tab-cluster" title="${escapeHtml(autorun.cluster.base_url || '')}">${escapeHtml(autorun.cluster.name)}</span>` : ''}
            <span class="tab-badge ${statusBadge}">${intervalText}</span>
            <span class="tab-close" data-autorun-id="${autorun.id}">&times;</span>
        `;
        
        tab.addEventListener('click', (e) => {
            // Don't switch if clicking the close button
            if (e.target.classList.contains('tab-close') || e.target.closest('.tab-close')) {
                return;
            }
            this.showAutorunDetails(autorun.id);
        });

        // Handle close button click
        const closeBtn = tab.querySelector('.tab-close');
        if (closeBtn) {
            closeBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                e.preventDefault();
                this.deleteAutorun(autorun.id);
            });
        }
        
        return tab;
    }

    /**
     * Attach event listeners for autorun action buttons.
     */
    attachEventListeners() {
        const toggleBtn = document.getElementById('autorun-toggle-btn');
        const clearBtn = document.getElementById('autorun-clear-btn');
        const exportBtn = document.getElementById('autorun-export-btn');
        const deleteBtn = document.getElementById('autorun-delete-btn');

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

        document.querySelectorAll('button.tab[data-autorun-id]').forEach(tab => {
            tab.classList.remove('active');
        });
        const activeTab = document.querySelector(`button.tab[data-autorun-id="${autorunId}"]`);
        if (activeTab) {
            activeTab.classList.add('active');
        }

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
                    window.toast.success(newEnabled ? 'Autorun enabled.' : 'Autorun disabled.', { key: 'autorun' });
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

        // Remove tab from DOM
        const tab = document.querySelector(`button.tab[data-autorun-id="${autorunId}"]`);
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
}
