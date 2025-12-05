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
            <span class="tab-badge">${session.entries?.length || 0}</span>
            <span class="tab-close" data-session-id="${session.id}">&times;</span>
        `;
        
        // Handle tab click (switch to session)
        tab.addEventListener('click', (e) => {
            // Don't switch if clicking the close button
            if (e.target.classList.contains('tab-close') || e.target.closest('.tab-close')) {
                return;
            }
            this.controller.switchToSession(session.id);
        });
        
        // Handle close button click
        const closeBtn = tab.querySelector('.tab-close');
        if (closeBtn) {
            closeBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                e.preventDefault();
                this.controller.closeSession(session.id);
            });
        }
        
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
        
        // Deactivate settings tab if active
        const settingsTab = document.getElementById('settings-tab');
        if (settingsTab) {
            settingsTab.classList.remove('active');
        }
        
        this.controller.activeSessionId = sessionId;
        
        // Load session details
        await this.controller.loadSessionDetails(sessionId);
        
        // Show session content
        const noSessionMessage = document.getElementById('no-session-message');
        const sessionContent = document.getElementById('session-content');
        const settingsContent = document.getElementById('settings-content');
        
        if (noSessionMessage) noSessionMessage.style.display = 'none';
        if (sessionContent) sessionContent.style.display = 'flex';
        if (settingsContent) settingsContent.style.display = 'none';
        
        // Connect WebSocket
        this.controller.wsManager.connect(sessionId);
    }

    /**
     * Close current session UI and delete it (same as clicking X).
     */
    async closeCurrent() {
        if (!this.controller.activeSessionId) {
            return;
        }
        
        const sessionId = this.controller.activeSessionId;
        await this.closeSession(sessionId);
    }

    /**
     * Close and delete a session.
     */
    async closeSession(sessionId) {
        if (!sessionId) {
            console.error('[SessionManager] closeSession called with null/undefined sessionId');
            return;
        }
        
        console.log(`[SessionManager] Closing and deleting session ${sessionId}`);
        
        // Mark as deleted immediately to prevent any recreation
        this.deletedSessionIds.add(sessionId);
        
        // Remove from local cache
        this.sessions.delete(sessionId);
        
        // Remove tab from DOM immediately
        this.removeTab(sessionId);
        
        // Close WebSocket connection
        this.controller.wsManager.disconnect(sessionId);
        
        // If this was the active session, clear UI
        if (this.controller.activeSessionId === sessionId) {
            this.controller.activeSessionId = null;
            const noSessionMessage = document.getElementById('no-session-message');
            const sessionContent = document.getElementById('session-content');
            if (noSessionMessage) noSessionMessage.style.display = 'flex';
            if (sessionContent) sessionContent.style.display = 'none';
        }
        
        // Stop the session if it's running
        try {
            await this.controller.api.stopSession(sessionId);
        } catch (error) {
            console.warn('[SessionManager] Error stopping session:', error);
        }
        
        // Delete session from backend
        try {
            const deleteResult = await this.controller.api.deleteSession(sessionId);
            if (deleteResult && deleteResult.success) {
                console.log(`[SessionManager] Successfully deleted session ${sessionId} from backend`);
            } else {
                console.error('[SessionManager] Backend delete failed:', deleteResult);
            }
        } catch (error) {
            console.error('[SessionManager] Error deleting session from backend:', error);
        }
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
