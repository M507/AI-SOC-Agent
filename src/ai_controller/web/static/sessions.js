// Session management (create, switch, close, tabs)

class SessionManager {
    constructor(controller) {
        this.controller = controller;
        this.sessions = new Map();
        this.deletedSessionIds = new Set(); // Track permanently deleted sessions
    }

    /**
     * Update sessions list and render tabs.
     */
    updateSessions(sessions) {
        const sessionsTabs = document.getElementById('sessions-tabs');
        if (!sessionsTabs) {
            console.error('[SessionManager] sessions-tabs container not found');
            return;
        }

        // Filter out deleted sessions
        const activeSessions = sessions.filter(s => !this.deletedSessionIds.has(s.id));
        
        // Update session cache
        activeSessions.forEach(session => {
            this.sessions.set(session.id, session);
        });

        // Get current tab IDs in DOM
        const currentTabIds = new Set();
        Array.from(sessionsTabs.children).forEach(tab => {
            const sessionId = tab.dataset.sessionId;
            if (sessionId) {
                currentTabIds.add(sessionId);
            }
        });

        // Get desired tab IDs from backend
        const desiredTabIds = new Set(activeSessions.map(s => s.id));

        // Remove tabs that shouldn't exist
        currentTabIds.forEach(tabId => {
            if (!desiredTabIds.has(tabId) || this.deletedSessionIds.has(tabId)) {
                this.removeTab(tabId);
            }
        });

        // Add or update tabs that should exist
        activeSessions.forEach(session => {
            const existingTab = this.getTabElement(session.id);
            if (existingTab) {
                // Update existing tab
                this.updateTab(existingTab, session);
            } else {
                // Create new tab
                const newTab = this.createTab(session);
                sessionsTabs.appendChild(newTab);
            }
        });
    }

    /**
     * Get tab element by session ID.
     */
    getTabElement(sessionId) {
        const sessionsTabs = document.getElementById('sessions-tabs');
        if (!sessionsTabs) return null;
        
        return sessionsTabs.querySelector(`button.tab[data-session-id="${sessionId}"]`);
    }

    /**
     * Remove a tab from the DOM.
     */
    removeTab(sessionId) {
        const tab = this.getTabElement(sessionId);
        if (tab && tab.parentNode) {
            tab.parentNode.removeChild(tab);
            return true;
        }
        return false;
    }

    /**
     * Update an existing tab with new session data.
     */
    updateTab(tab, session) {
        // Update active state
        if (session.id === this.controller.activeSessionId) {
            tab.classList.add('active');
        } else {
            tab.classList.remove('active');
        }

        // Update badge count
        let badge = tab.querySelector('.tab-badge');
        if (!badge) {
            // Create badge if it doesn't exist
            const nameSpan = tab.querySelector('span:first-child');
            if (nameSpan) {
                badge = document.createElement('span');
                badge.className = 'tab-badge';
                nameSpan.after(badge);
            }
        }
        if (badge) {
            badge.textContent = session.entries?.length || 0;
        }

        let clusterEl = tab.querySelector('.tab-cluster');
        const clusterName = session.cluster && session.cluster.name;
        if (clusterName) {
            if (!clusterEl) {
                clusterEl = document.createElement('span');
                clusterEl.className = 'tab-cluster';
                const nameSpan = tab.querySelector('span:first-child');
                if (nameSpan) nameSpan.after(clusterEl);
            }
            clusterEl.textContent = clusterName;
            clusterEl.title = session.cluster.base_url || '';
        } else if (clusterEl) {
            clusterEl.remove();
        }

        // Update name if changed
        const nameSpan = tab.querySelector('span:first-child');
        if (nameSpan && nameSpan.textContent !== session.name) {
            nameSpan.textContent = session.name;
        }
    }

    /**
     * Create a session tab element.
     */
    createTab(session) {
        const tab = document.createElement('button');
        tab.className = 'tab';
        tab.dataset.sessionId = session.id;
        
        if (session.id === this.controller.activeSessionId) {
            tab.classList.add('active');
        }
        
        tab.innerHTML = `
            <span>${escapeHtml(session.name)}</span>
            ${session.cluster && session.cluster.name ? `<span class="tab-cluster" title="${escapeHtml(session.cluster.base_url || '')}">${escapeHtml(session.cluster.name)}</span>` : ''}
            <span class="tab-badge">${session.entries?.length || 0}</span>
        `;
        
        tab.addEventListener('click', () => {
            this.controller.switchToSession(session.id);
        });
        
        return tab;
    }

    /**
     * Switch to a different session.
     */
    async switchToSession(sessionId) {
        if (this.controller.activeSessionId === sessionId) {
            return;
        }
        
        // Ensure the main view is in "Manual Sessions" mode
        if (this.controller && typeof this.controller.setActiveSection === 'function') {
            this.controller.setActiveSection('sessions');
        }
        
        // Update active tab state
        document.querySelectorAll('button.tab[data-session-id]').forEach(tab => {
            tab.classList.remove('active');
        });
        
        const activeTab = this.getTabElement(sessionId);
        if (activeTab) {
            activeTab.classList.add('active');
        }
        
        // Deactivate settings tabs if active
        document.querySelectorAll('#settings-tabs [data-settings-page]').forEach((tab) => {
            tab.classList.remove('active');
        });
        
        this.controller.activeSessionId = sessionId;
        
        // Load session details
        await this.controller.loadSessionDetails(sessionId);
        
        // Show session content
        const noSessionMessage = document.getElementById('no-session-message');
        const sessionContent = document.getElementById('session-content');
        
        if (noSessionMessage) noSessionMessage.style.display = 'none';
        if (sessionContent) sessionContent.style.display = 'flex';
        document.querySelectorAll('[data-settings-page-content]').forEach((panel) => {
            panel.style.display = 'none';
        });
        
        // Connect WebSocket
        this.controller.wsManager.connect(sessionId);
    }

    /**
     * Session JSON files are kept on disk. Closing the browser or leaving
     * this view must not delete them.
     */
    async closeCurrent() {
        return;
    }

    async closeSession(_sessionId) {
        return;
    }

    /**
     * Update session status badge.
     */
    updateStatus(status) {
        const statusBadge = document.getElementById('session-status');
        if (statusBadge) {
            statusBadge.textContent = status.toUpperCase();
            statusBadge.className = `status-badge ${status}`;
        }
    }
}
