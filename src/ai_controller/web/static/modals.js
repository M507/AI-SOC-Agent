// Modal handling for sessions and autoruns

class ModalManager {
    constructor(controller) {
        this.controller = controller;
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
    }

    /**
     * Hide new session modal.
     */
    hideNewSession() {
        const modal = document.getElementById('new-session-modal');
        if (modal) {
            modal.style.display = 'none';
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
        if (nameInput) nameInput.value = '';
        if (commandInput) commandInput.value = '';
        if (conditionInput) conditionInput.value = '';
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
        
        const name = nameInput.value.trim();
        
        if (!name) {
            if (window.toast) {
                window.toast.info('Enter a session name.', { key: 'session' });
            }
            return;
        }
        
        const clusterId = this.controller.elasticClusters
            ? this.controller.elasticClusters.selectedClusterId('session-cluster-select')
            : null;
        const data = await this.controller.api.createSession(name, 'manual', clusterId);
        
        if (data.success) {
            this.hideNewSession();
            await this.controller.loadSessions();
            if (data.session && data.session.id) {
                await this.controller.sessionManager.switchToSession(data.session.id);
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
        
        const name = nameInput.value.trim();
        const command = commandInput.value.trim();
        const conditionFunction = conditionInput ? conditionInput.value.trim() : '';
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
