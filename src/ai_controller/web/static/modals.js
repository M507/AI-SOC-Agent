// Modal handling for sessions and autoruns

class ModalManager {
    constructor(controller) {
        this.controller = controller;
        this._sessionAlertLoadToken = 0;
        this.bindFormHelpers();
    }

    bindFormHelpers() {
        const nameInput = document.getElementById('session-name');
        if (nameInput) {
            nameInput.addEventListener('keydown', (event) => {
                if (event.key === 'Enter') {
                    event.preventDefault();
                    this.createSession();
                }
            });
        }
        const intervalInput = document.getElementById('autorun-interval');
        if (intervalInput) {
            intervalInput.addEventListener('input', () => this.updateIntervalPreview());
        }
        const clusterSelect = document.getElementById('session-cluster-select');
        if (clusterSelect) {
            clusterSelect.addEventListener('change', () => {
                this.loadSessionAlertOptions();
            });
        }
    }

    updateIntervalPreview() {
        const intervalInput = document.getElementById('autorun-interval');
        const preview = document.getElementById('autorun-interval-preview');
        if (!intervalInput || !preview) return;
        preview.textContent = formatIntervalPreview(intervalInput.value);
    }

    /**
     * Show new session modal.
     */
    showNewSession() {
        const modal = document.getElementById('new-session-modal');
        const nameInput = document.getElementById('session-name');
        if (modal) {
            modal.style.display = 'flex';
        }
        if (nameInput) {
            nameInput.value = '';
            nameInput.focus();
        }
        if (this.controller.elasticClusters) {
            this.controller.elasticClusters.fillSelect(document.getElementById('session-cluster-select'));
        }
        this.resetSessionAlertSelect('Loading recent alerts…');
        this.loadSessionAlertOptions();
    }

    /**
     * Hide new session modal.
     */
    hideNewSession() {
        const modal = document.getElementById('new-session-modal');
        if (modal) {
            modal.style.display = 'none';
        }
        this.resetSessionAlertSelect();
    }

    resetSessionAlertSelect(loadingLabel) {
        const select = document.getElementById('session-alert-select');
        if (!select) return;
        select.innerHTML = '';
        const none = document.createElement('option');
        none.value = '';
        none.textContent = 'None';
        select.appendChild(none);
        select.value = '';
        if (loadingLabel) {
            const loading = document.createElement('option');
            loading.value = '';
            loading.disabled = true;
            loading.textContent = loadingLabel;
            select.appendChild(loading);
            select.disabled = true;
        } else {
            select.disabled = false;
        }
    }

    formatAlertOptionLabel(alert) {
        const severity = (alert.severity || 'unknown').toUpperCase();
        const title = (alert.title || 'Untitled alert').trim();
        const shortId = String(alert.id || '').slice(0, 8);
        const truncated = title.length > 64 ? `${title.slice(0, 61)}…` : title;
        return `${severity} · ${truncated} · ${shortId}`;
    }

    async loadSessionAlertOptions() {
        const select = document.getElementById('session-alert-select');
        if (!select) return;

        const token = ++this._sessionAlertLoadToken;
        const clusterId = this.controller.elasticClusters
            ? this.controller.elasticClusters.selectedClusterId('session-cluster-select')
            : null;

        this.resetSessionAlertSelect('Loading recent alerts…');

        if (!clusterId) {
            if (token !== this._sessionAlertLoadToken) return;
            this.resetSessionAlertSelect();
            const empty = document.createElement('option');
            empty.value = '';
            empty.disabled = true;
            empty.textContent = 'No Elastic cluster selected';
            select.appendChild(empty);
            select.disabled = true;
            return;
        }

        const data = await this.controller.api.getRecentAlerts(clusterId, 10, 24);
        if (token !== this._sessionAlertLoadToken) return;

        this.resetSessionAlertSelect();

        if (!data.success) {
            const err = document.createElement('option');
            err.value = '';
            err.disabled = true;
            err.textContent = data.error ? `Could not load alerts: ${data.error}` : 'Could not load alerts';
            select.appendChild(err);
            select.disabled = false;
            return;
        }

        const alerts = Array.isArray(data.alerts) ? data.alerts : [];
        if (!alerts.length) {
            const empty = document.createElement('option');
            empty.value = '';
            empty.disabled = true;
            empty.textContent = 'No recent alerts found';
            select.appendChild(empty);
            select.disabled = false;
            return;
        }

        alerts.forEach((alert) => {
            if (!alert || !alert.id) return;
            const option = document.createElement('option');
            option.value = alert.id;
            option.textContent = this.formatAlertOptionLabel(alert);
            option.title = `${alert.title || ''} (${alert.id})`;
            select.appendChild(option);
        });
        select.disabled = false;
        select.value = '';
    }

    /**
     * Paste an investigate-alert prompt into the session input without sending.
     */
    seedCommandInputWithAlert(alertId) {
        const id = String(alertId || '').trim();
        if (!id) return;
        const commandInput = document.getElementById('command-input');
        if (!commandInput) return;

        const prompt = `investigate this alert _id: ${id}`;
        const current = commandInput.value || '';
        if (current.includes(id)) {
            if (!current.includes(prompt) && !current.trim()) {
                commandInput.value = prompt;
            }
            commandInput.focus();
            return;
        }

        const separator = current && !/\s$/.test(current) ? ' ' : '';
        commandInput.value = current ? `${current}${separator}${prompt}` : prompt;
        commandInput.focus();
        try {
            const end = commandInput.value.length;
            commandInput.setSelectionRange(end, end);
        } catch (_unused) {
            // Some browsers reject setSelectionRange on certain input types.
        }
    }

    /**
     * Show new autorun modal.
     */
    showNewAutorun() {
        const modal = document.getElementById('new-autorun-modal');
        const nameInput = document.getElementById('autorun-name');
        const commandInput = document.getElementById('autorun-command');
        const conditionInput = document.getElementById('autorun-condition');
        const intervalInput = document.getElementById('autorun-interval');
        const conditionHelpTooltip = document.getElementById('condition-help-tooltip');
        
        if (modal) {
            modal.style.display = 'flex';
        }
        const limitInput = document.getElementById('autorun-condition-limit');
        if (nameInput) nameInput.value = '';
        if (commandInput) commandInput.value = '';
        if (conditionInput) conditionInput.value = '';
        if (limitInput) limitInput.value = '';
        if (intervalInput) intervalInput.value = '300';
        this.updateIntervalPreview();
        if (conditionHelpTooltip) {
            conditionHelpTooltip.classList.add('help-tooltip-hidden');
        }
        if (this.controller.elasticClusters) {
            this.controller.elasticClusters.fillSelect(document.getElementById('autorun-cluster-select'));
        }
    }

    /**
     * Hide new autorun modal.
     */
    hideNewAutorun() {
        const modal = document.getElementById('new-autorun-modal');
        if (modal) {
            modal.style.display = 'none';
        }
    }

    /**
     * Create a new session from modal.
     */
    async createSession() {
        const nameInput = document.getElementById('session-name');
        if (!nameInput) return;
        
        // Empty name is allowed; the server assigns a random UUID.
        const name = nameInput.value.trim() || null;

        const alertSelect = document.getElementById('session-alert-select');
        const selectedAlertId = alertSelect && alertSelect.value ? alertSelect.value.trim() : '';
        
        const clusterId = this.controller.elasticClusters
            ? this.controller.elasticClusters.selectedClusterId('session-cluster-select')
            : null;
        const data = await this.controller.api.createSession(name, 'manual', clusterId);
        
        if (data.success) {
            this.hideNewSession();
            await this.controller.loadSessions();
            if (data.session && data.session.id) {
                await this.controller.sessionManager.switchToSession(data.session.id);
                if (selectedAlertId) {
                    this.seedCommandInputWithAlert(selectedAlertId);
                }
            }
        } else if (window.toast) {
            window.toast.error(data.error || 'Could not create session', { key: 'session' });
        }
    }

    /**
     * Create a new autorun from modal.
     */
    async createAutorun() {
        const nameInput = document.getElementById('autorun-name');
        const commandInput = document.getElementById('autorun-command');
        const conditionInput = document.getElementById('autorun-condition');
        const intervalInput = document.getElementById('autorun-interval');
        
        if (!nameInput || !commandInput || !intervalInput) return;
        
        const limitInput = document.getElementById('autorun-condition-limit');
        const name = nameInput.value.trim();
        const command = commandInput.value.trim();
        const conditionFunction = joinConditionFunction(
            conditionInput ? conditionInput.value : '',
            limitInput ? limitInput.value : ''
        );
        const intervalSeconds = parseInt(intervalInput.value, 10);
        
        if (!name || !command) {
            if (window.toast) {
                window.toast.info('Enter an autorun name and starting prompt.', { key: 'autorun' });
            }
            return;
        }
        
        if (isNaN(intervalSeconds) || intervalSeconds < 5) {
            if (window.toast) {
                window.toast.info('Interval must be at least 5 seconds.', { key: 'autorun' });
            }
            return;
        }
        
        const clusterId = this.controller.elasticClusters
            ? this.controller.elasticClusters.selectedClusterId('autorun-cluster-select')
            : null;
        const data = await this.controller.api.createAutorun(
            name, 
            command, 
            intervalSeconds,
            conditionFunction || undefined,
            clusterId
        );
        
        if (data.success) {
            this.hideNewAutorun();
            if (data.autorun && data.autorun.id) {
                this.controller.autorunManager.currentAutorunId = data.autorun.id;
            }
            await this.controller.loadAutoruns();
            if (this.controller.activeSection !== 'autoruns') {
                this.controller.setActiveSection('autoruns');
            }
            if (window.toast) {
                window.toast.success('Autorun created.', { key: 'autorun' });
            }
        } else if (window.toast) {
            window.toast.error(data.error || 'Could not create autorun', { key: 'autorun' });
        }
    }
}
