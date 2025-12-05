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
        
        const autorunContent = document.getElementById('autorun-content');
        const autorunEmpty = document.getElementById('autorun-empty-message');

        // Clear existing tabs and cache
        autorunsTabs.innerHTML = '';
        this.autoruns.clear();

        // Filter out deleted autoruns
        const activeAutoruns = autoruns.filter(a => !this.deletedAutorunIds.has(a.id));
        
        // Update cache and create tabs
        activeAutoruns.forEach(autorun => {
            this.autoruns.set(autorun.id, autorun);
            const tab = this.createTab(autorun);
            autorunsTabs.appendChild(tab);
        });

        // No autoruns available: show empty state when in Autoruns view
        if (activeAutoruns.length === 0) {
            this.currentAutorunId = null;
            if (autorunContent) {
                autorunContent.style.display = 'none';
                // Remove class from content-area
                const contentArea = document.querySelector('.content-area');
                if (contentArea) {
                    contentArea.classList.remove('has-autorun');
                }
            }
            if (autorunEmpty && this.controller.activeSection === 'autoruns') {
                autorunEmpty.style.display = 'flex';
            }
            return;
        }

        // We have autoruns: hide empty state, ensure one is selected and visible
        if (autorunEmpty) {
            autorunEmpty.style.display = 'none';
        }

        let autorunToShowId = null;
        if (this.currentAutorunId && this.autoruns.has(this.currentAutorunId)) {
            autorunToShowId = this.currentAutorunId;
        } else {
            autorunToShowId = activeAutoruns[0].id;
        }

        this.showAutorunDetails(autorunToShowId);
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

        // Ensure the main view is in "Autoruns" mode
        if (this.controller && typeof this.controller.setActiveSection === 'function') {
            this.controller.setActiveSection('autoruns');
        }

        this.currentAutorunId = autorunId;

        // Deactivate all autorun tabs, then activate this one
        document.querySelectorAll('button.tab[data-autorun-id]').forEach(tab => {
            tab.classList.remove('active');
        });
        const activeTab = document.querySelector(`button.tab[data-autorun-id="${autorunId}"]`);
        if (activeTab) {
            activeTab.classList.add('active');
        }

        // Hide other views
        const sessionContent = document.getElementById('session-content');
        const settingsContent = document.getElementById('settings-content');
        const noSessionMessage = document.getElementById('no-session-message');
        const autorunContent = document.getElementById('autorun-content');
        const autorunEmpty = document.getElementById('autorun-empty-message');

        if (sessionContent) sessionContent.style.display = 'none';
        if (settingsContent) settingsContent.style.display = 'none';
        if (noSessionMessage) noSessionMessage.style.display = 'none';
        if (autorunEmpty) autorunEmpty.style.display = 'none';

        // Show autorun details panel
        if (autorunContent) {
            autorunContent.style.display = 'block';
            // Add class to content-area to prevent it from scrolling
            const contentArea = document.querySelector('.content-area');
            if (contentArea) {
                contentArea.classList.add('has-autorun');
            }
        }

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
            intervalEl.textContent = `${autorun.interval_seconds}s (${formatInterval(autorun.interval_seconds)})`;
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
                // Refresh autorun list and details
                await this.controller.loadAutoruns();
                this.showAutorunDetails(autorunId);
            } else {
                alert(`Error updating autorun: ${result.error || 'Unknown error'}`);
            }
        } catch (error) {
            console.error('[AutorunManager] Error updating autorun:', error);
            alert('Error updating autorun. See console for details.');
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
                console.log(`[AutorunManager] Successfully cleared autorun session ${autorunId}`);
                // Reload the autorun session to show the cleared terminal
                const autorun = this.autoruns.get(autorunId);
                if (autorun && this.controller.loadAutorunSession) {
                    await this.controller.loadAutorunSession(autorun);
                }
            } else {
                console.error('[AutorunManager] Backend clear failed:', result);
                alert(`Error clearing autorun session: ${result.error || 'Unknown error'}`);
            }
        } catch (error) {
            console.error('[AutorunManager] Error clearing autorun session:', error);
            alert('Error clearing autorun session. See console for details.');
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
            const autorunContent = document.getElementById('autorun-content');
            const noSessionMessage = document.getElementById('no-session-message');
            if (autorunContent) {
                autorunContent.style.display = 'none';
                // Remove class from content-area
                const contentArea = document.querySelector('.content-area');
                if (contentArea) {
                    contentArea.classList.remove('has-autorun');
                }
            }
            if (noSessionMessage) noSessionMessage.style.display = 'flex';
        }

        // Delete autorun from backend
        try {
            const deleteResult = await this.controller.api.deleteAutorun(autorunId);
            if (deleteResult && deleteResult.success) {
                console.log(`[AutorunManager] Successfully deleted autorun ${autorunId} from backend`);
            } else {
                console.error('[AutorunManager] Backend delete failed:', deleteResult);
                alert(`Error deleting autorun: ${deleteResult.error || 'Unknown error'}`);
            }
        } catch (error) {
            console.error('[AutorunManager] Error deleting autorun from backend:', error);
            alert('Error deleting autorun. See console for details.');
        }
    }
}
