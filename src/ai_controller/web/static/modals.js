// Modal handling for sessions and autoruns

class ModalManager {
    constructor(controller) {
        this.controller = controller;
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
        if (conditionHelpTooltip) {
            conditionHelpTooltip.classList.add('help-tooltip-hidden');
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
            alert('Please enter a session name');
            return;
        }
        
        const data = await this.controller.api.createSession(name, 'manual');
        
        if (data.success) {
            this.hideNewSession();
            await this.controller.loadSessions();
            if (data.session && data.session.id) {
                await this.controller.sessionManager.switchToSession(data.session.id);
            }
        } else {
            alert(`Error creating session: ${data.error || 'Unknown error'}`);
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
            alert('Please enter autorun name and starting prompt');
            return;
        }
        
        if (isNaN(intervalSeconds) || intervalSeconds < 5) {
            alert('Interval must be at least 5 seconds');
            return;
        }
        
        const data = await this.controller.api.createAutorun(
            name, 
            command, 
            intervalSeconds,
            conditionFunction || undefined
        );
        
        if (data.success) {
            this.hideNewAutorun();
            await this.controller.loadAutoruns();
        } else {
            alert(`Error creating autorun: ${data.error || 'Unknown error'}`);
        }
    }
}
