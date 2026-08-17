// AI Controller Main Application
// Orchestrates all components

class AIController {
    constructor() {
        // Core state
        this.activeSessionId = null;
        this.uiDebugMode = false;
        this.activeSection = 'sessions'; // 'sessions' | 'autoruns' | 'settings' | 'mcp'
        this.activeSettingsPage = 'llm';
        
        // Initialize managers
        this.api = new APIClient();
        this.wsManager = new WebSocketManager(this);
        this.terminal = new TerminalRenderer(this);
        this.sessionManager = new SessionManager(this);
        this.autorunManager = new AutorunManager(this);
        this.modals = new ModalManager(this);
        this.settingsManager = new SettingsManager(this);
        this.mcpPanel = new MCPPanel(this);
        
        this.init();
    }
    
    init() {
        this.setupEventListeners();
        this.loadConfig();
        this.settingsManager.load();
        this.mcpPanel.refresh();
        // Default view is manual sessions; load initial data
        this.loadSessions('manual');
        this.loadAutoruns();

        // Poll for updates every 3 seconds to keep chats live without
        // interfering with non-chat views like Settings.
        this.pollInterval = setInterval(() => {
            // When in the Sessions view, refresh session list + active chat content
            if (this.activeSection === 'sessions') {
                this.loadSessions('manual');
                if (this.activeSessionId) {
                    this.loadSessionDetails(this.activeSessionId);
                }
            }

            // When in the Autoruns view, refresh autorun configs and the selected autorun's chat
            if (this.activeSection === 'autoruns') {
                this.loadAutoruns();
                const currentId = this.autorunManager && this.autorunManager.currentAutorunId;
                if (currentId) {
                    const autorun = this.autorunManager.autoruns.get(currentId);
                    if (autorun) {
                        this.loadAutorunSession(autorun);
                    }
                }
            }
        }, 3000);

        this.mcpHealthInterval = setInterval(() => {
            this.mcpPanel.refresh();
        }, 10000);
    }
    
    setupEventListeners() {
        // Left navigation
        const navSessions = document.getElementById('nav-sessions');
        const navAutoruns = document.getElementById('nav-autoruns');
        const navSettings = document.getElementById('nav-settings');
        const navMcp = document.getElementById('nav-mcp');

        if (navSessions) {
            navSessions.addEventListener('click', () => {
                this.setActiveSection('sessions');
            });
        }
        if (navAutoruns) {
            navAutoruns.addEventListener('click', () => {
                this.setActiveSection('autoruns');
            });
        }
        if (navSettings) {
            navSettings.addEventListener('click', () => {
                this.setActiveSection('settings');
            });
        }
        if (navMcp) {
            navMcp.addEventListener('click', () => {
                this.setActiveSection('mcp');
            });
        }

        // New session button
        const newSessionBtn = document.getElementById('new-session-btn');
        if (newSessionBtn) {
            newSessionBtn.addEventListener('click', () => {
                this.setActiveSection('sessions');
                this.modals.showNewSession();
            });
        }
        
        // New autorun button
        const newAutorunBtn = document.getElementById('new-autorun-btn');
        if (newAutorunBtn) {
            newAutorunBtn.addEventListener('click', () => {
                this.setActiveSection('autoruns');
                this.modals.showNewAutorun();
            });
        }
        
        // Settings / MCP header buttons
        const settingsBtn = document.getElementById('settings-btn');
        if (settingsBtn) {
            settingsBtn.addEventListener('click', () => {
                this.setActiveSection('settings');
            });
        }
        const mcpBtn = document.getElementById('mcp-btn');
        if (mcpBtn) {
            mcpBtn.addEventListener('click', () => {
                this.setActiveSection('mcp');
            });
        }
        const logoutBtn = document.getElementById('logout-btn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', async () => {
                try {
                    await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' });
                } finally {
                    window.location.href = '/login';
                }
            });
        }
        
        // Command input
        const commandInput = document.getElementById('command-input');
        if (commandInput) {
            commandInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    this.executeCommand();
                }
            });
        }
        
        // Execute button
        const executeBtn = document.getElementById('execute-btn');
        if (executeBtn) {
            executeBtn.addEventListener('click', () => {
                this.executeCommand();
            });
        }
        
        // Stop session button
        const stopSessionBtn = document.getElementById('stop-session-btn');
        if (stopSessionBtn) {
            stopSessionBtn.addEventListener('click', () => {
                this.stopSession();
            });
        }
        
        // Close session button (deletes the session)
        const closeSessionBtn = document.getElementById('close-session-btn');
        if (closeSessionBtn) {
            closeSessionBtn.addEventListener('click', async () => {
                if (this.activeSessionId) {
                    await this.sessionManager.closeCurrent();
                }
            });
        }
        
        // Modal handlers
        const closeSessionModal = document.getElementById('close-session-modal');
        if (closeSessionModal) {
            closeSessionModal.addEventListener('click', () => {
                this.modals.hideNewSession();
            });
        }
        
        const cancelSessionBtn = document.getElementById('cancel-session-btn');
        if (cancelSessionBtn) {
            cancelSessionBtn.addEventListener('click', () => {
                this.modals.hideNewSession();
            });
        }
        
        const createSessionBtn = document.getElementById('create-session-btn');
        if (createSessionBtn) {
            createSessionBtn.addEventListener('click', () => {
                this.modals.createSession();
            });
        }
        
        const closeAutorunModal = document.getElementById('close-autorun-modal');
        if (closeAutorunModal) {
            closeAutorunModal.addEventListener('click', () => {
                this.modals.hideNewAutorun();
            });
        }
        
        const cancelAutorunBtn = document.getElementById('cancel-autorun-btn');
        if (cancelAutorunBtn) {
            cancelAutorunBtn.addEventListener('click', () => {
                this.modals.hideNewAutorun();
            });
        }
        
        const createAutorunBtn = document.getElementById('create-autorun-btn');
        if (createAutorunBtn) {
            createAutorunBtn.addEventListener('click', () => {
                this.modals.createAutorun();
            });
        }
        
        // Condition help link toggle - use event delegation since modal might not be visible initially
        document.addEventListener('click', (e) => {
            // Check if clicked element is the help link or a child of it
            const helpLink = e.target.closest('#condition-help-link');
            if (helpLink) {
                e.preventDefault();
                e.stopPropagation();
                const tooltip = document.getElementById('condition-help-tooltip');
                if (tooltip) {
                    // Toggle visibility using class
                    const isHidden = tooltip.classList.contains('help-tooltip-hidden');
                    if (isHidden) {
                        tooltip.classList.remove('help-tooltip-hidden');
                        console.log('Tooltip shown');
                    } else {
                        tooltip.classList.add('help-tooltip-hidden');
                        console.log('Tooltip hidden');
                    }
                } else {
                    console.error('Tooltip element not found');
                }
            }
        });
        
        // Close modals on outside click
        window.addEventListener('click', (e) => {
            const sessionModal = document.getElementById('new-session-modal');
            const autorunModal = document.getElementById('new-autorun-modal');
            if (e.target === sessionModal) {
                this.modals.hideNewSession();
            }
            if (e.target === autorunModal) {
                this.modals.hideNewAutorun();
            }
        });
        
        // Settings sub-tabs (LLM, UI, and any future pages under Settings)
        const settingsTabs = document.getElementById('settings-tabs');
        if (settingsTabs) {
            settingsTabs.addEventListener('click', (event) => {
                const tab = event.target.closest('[data-settings-page]');
                if (!tab) return;
                if (this.activeSection !== 'settings') {
                    this.activeSettingsPage = tab.dataset.settingsPage;
                    this.setActiveSection('settings');
                    return;
                }
                this.setSettingsPage(tab.dataset.settingsPage);
            });
        }
        const mcpTab = document.getElementById('mcp-tab');
        if (mcpTab) {
            mcpTab.addEventListener('click', () => {
                this.setActiveSection('mcp');
            });
        }
        
        // Debug toggle
        const debugToggle = document.getElementById('debug-toggle');
        if (debugToggle) {
            debugToggle.addEventListener('change', () => {
                this.updateDebugMode(debugToggle.checked);
            });
        }
    }
    
    async loadConfig() {
        const data = await this.api.loadConfig();
        if (data && data.success) {
            this.uiDebugMode = data.ui_debug === true;
            const debugToggle = document.getElementById('debug-toggle');
            if (debugToggle) {
                debugToggle.checked = this.uiDebugMode;
            }
        }
    }
    
    async loadSessions(sessionType = 'manual') {
        const data = await this.api.loadSessions(sessionType);
        if (data.success) {
            // Filter out permanently deleted sessions
            const filteredSessions = data.sessions.filter(
                session => !this.sessionManager.deletedSessionIds.has(session.id)
            );
            this.sessionManager.updateSessions(filteredSessions);
        }
    }
    
    async loadAutoruns() {
        const data = await this.api.loadAutoruns();
        if (data.success) {
            this.autorunManager.updateAutoruns(data.autoruns);
        }
    }

    /**
     * Load and render the backing session for a given autorun as a long chat
     * into the read-only autorun terminal.
     */
    async loadAutorunSession(autorun) {
        if (!autorun || !autorun.session_id) {
            return;
        }

        try {
            const data = await this.api.getSession(autorun.session_id);
            if (data && data.success && data.session) {
                this.terminal.render(data.session, 'autorun-terminal');
            }
        } catch (error) {
            console.error('[AIController] Error loading autorun session chat:', error);
        }
    }
    
    async loadSessionDetails(sessionId) {
        const data = await this.api.getSession(sessionId);
        
        if (data.success) {
            const session = data.session;
            this.sessionManager.sessions.set(sessionId, session);
            
            // Update UI
            const sessionTitle = document.getElementById('session-title');
            if (sessionTitle) {
                sessionTitle.textContent = session.name;
            }
            this.sessionManager.updateStatus(session.status);
            
            // Render terminal
            this.terminal.render(session);
        }
    }
    
    async switchToSession(sessionId) {
        await this.sessionManager.switchToSession(sessionId);
    }
    
    async executeCommand() {
        if (!this.activeSessionId) {
            alert('Please select a session first');
            return;
        }
        
        const commandInput = document.getElementById('command-input');
        if (!commandInput) return;
        
        const command = commandInput.value.trim();
        
        if (!command) {
            return;
        }
        
        // Clear input
        commandInput.value = '';
        
        // Show command in terminal immediately
        this.terminal.addCommand(command);
        
        // Execute command
        const data = await this.api.executeCommand(this.activeSessionId, command);
        
        if (data.success) {
            // Result will come via WebSocket
            // But we can also reload session to get the result
            setTimeout(() => {
                this.loadSessionDetails(this.activeSessionId);
            }, 500);
        } else {
            // Show error
            this.terminal.showError(null, data.error || 'Unknown error');
        }
    }
    
    async stopSession() {
        if (!this.activeSessionId) {
            return;
        }
        
        await this.api.stopSession(this.activeSessionId);
    }
    
    async closeSession(sessionId) {
        await this.sessionManager.closeSession(sessionId);
    }
    
    setActiveSection(section) {
        if (!['sessions', 'autoruns', 'settings', 'mcp'].includes(section)) {
            console.warn('[AIController] Unknown section:', section);
            return;
        }

        this.activeSection = section;

        // Update sidebar nav active state
        const sections = ['sessions', 'autoruns', 'settings', 'mcp'];
        sections.forEach((name) => {
            const el = document.getElementById(`nav-${name}`);
            if (el) {
                if (name === section) {
                    el.classList.add('active');
                } else {
                    el.classList.remove('active');
                }
            }
        });

        // Tab groups
        const sessionsGroup = document.getElementById('sessions-tab-group');
        const autorunsGroup = document.getElementById('autoruns-tab-group');
        const settingsGroup = document.getElementById('settings-tab-group');
        const mcpGroup = document.getElementById('mcp-tab-group');

        if (sessionsGroup) {
            sessionsGroup.style.display = section === 'sessions' ? 'flex' : 'none';
        }
        if (autorunsGroup) {
            autorunsGroup.style.display = section === 'autoruns' ? 'flex' : 'none';
        }
        if (settingsGroup) {
            settingsGroup.style.display = section === 'settings' ? 'flex' : 'none';
        }
        if (mcpGroup) {
            mcpGroup.style.display = section === 'mcp' ? 'flex' : 'none';
        }

        const sessionContent = document.getElementById('session-content');
        const autorunContent = document.getElementById('autorun-content');
        const mcpContent = document.getElementById('mcp-content');
        const noSessionMessage = document.getElementById('no-session-message');
        const autorunEmpty = document.getElementById('autorun-empty-message');

        if (section !== 'settings') {
            this.hideSettingsPages();
        }

        if (section === 'sessions') {
            if (sessionContent) sessionContent.style.display = this.activeSessionId ? 'flex' : 'none';
            if (autorunContent) {
                autorunContent.style.display = 'none';
                const contentArea = document.querySelector('.content-area');
                if (contentArea) {
                    contentArea.classList.remove('has-autorun');
                }
            }
            if (mcpContent) mcpContent.style.display = 'none';
            if (noSessionMessage) noSessionMessage.style.display = this.activeSessionId ? 'none' : 'flex';
            if (autorunEmpty) autorunEmpty.style.display = 'none';
        } else if (section === 'autoruns') {
            if (sessionContent) sessionContent.style.display = 'none';
            if (mcpContent) mcpContent.style.display = 'none';
            if (noSessionMessage) noSessionMessage.style.display = 'none';

            const hasAutorunTabs = document.querySelector('button.tab[data-autorun-id]') !== null;
            if (hasAutorunTabs) {
                if (autorunContent) {
                    autorunContent.style.display = 'block';
                    const contentArea = document.querySelector('.content-area');
                    if (contentArea) {
                        contentArea.classList.add('has-autorun');
                    }
                }
                if (autorunEmpty) autorunEmpty.style.display = 'none';
            } else {
                if (autorunContent) {
                    autorunContent.style.display = 'none';
                    const contentArea = document.querySelector('.content-area');
                    if (contentArea) {
                        contentArea.classList.remove('has-autorun');
                    }
                }
                if (autorunEmpty) autorunEmpty.style.display = 'flex';
            }
        } else if (section === 'settings') {
            if (sessionContent) sessionContent.style.display = 'none';
            if (autorunContent) {
                autorunContent.style.display = 'none';
                const contentArea = document.querySelector('.content-area');
                if (contentArea) {
                    contentArea.classList.remove('has-autorun');
                }
            }
            if (mcpContent) mcpContent.style.display = 'none';
            if (noSessionMessage) noSessionMessage.style.display = 'none';
            if (autorunEmpty) autorunEmpty.style.display = 'none';

            document.querySelectorAll('button.tab[data-session-id]').forEach((tab) => {
                tab.classList.remove('active');
            });
            this.setSettingsPage(this.activeSettingsPage);
            this.settingsManager.load();

            if (this.activeSessionId) {
                this.wsManager.disconnect(this.activeSessionId);
            }
        } else if (section === 'mcp') {
            if (sessionContent) sessionContent.style.display = 'none';
            if (autorunContent) {
                autorunContent.style.display = 'none';
                const contentArea = document.querySelector('.content-area');
                if (contentArea) {
                    contentArea.classList.remove('has-autorun');
                }
            }
            if (mcpContent) mcpContent.style.display = 'block';
            if (noSessionMessage) noSessionMessage.style.display = 'none';
            if (autorunEmpty) autorunEmpty.style.display = 'none';

            document.querySelectorAll('button.tab[data-session-id]').forEach((tab) => {
                tab.classList.remove('active');
            });
            const mcpTab = document.getElementById('mcp-tab');
            if (mcpTab) {
                mcpTab.classList.add('active');
            }
            this.mcpPanel.load();
            if (this.activeSessionId) {
                this.wsManager.disconnect(this.activeSessionId);
            }
        }
    }

    hideSettingsPages() {
        document.querySelectorAll('[data-settings-page-content]').forEach((panel) => {
            panel.style.display = 'none';
        });
        document.querySelectorAll('#settings-tabs [data-settings-page]').forEach((tab) => {
            tab.classList.remove('active');
        });
    }

    setSettingsPage(pageId) {
        const tabs = Array.from(document.querySelectorAll('#settings-tabs [data-settings-page]'));
        const pages = tabs.map((tab) => tab.dataset.settingsPage);
        if (!pageId || !pages.includes(pageId)) {
            pageId = pages.includes(this.activeSettingsPage) ? this.activeSettingsPage : pages[0];
        }
        this.activeSettingsPage = pageId || 'llm';
        tabs.forEach((tab) => {
            tab.classList.toggle('active', tab.dataset.settingsPage === this.activeSettingsPage);
        });
        document.querySelectorAll('[data-settings-page-content]').forEach((panel) => {
            panel.style.display = panel.dataset.settingsPageContent === this.activeSettingsPage ? 'flex' : 'none';
        });
    }
    
    showSettings() {
        this.setActiveSection('settings');
    }

    updateMCPHealthIndicator(state, running) {
        const cls = running ? 'health-ok' : (state === 'unhealthy' ? 'health-bad' : 'health-unknown');
        ['mcp-health-dot', 'nav-mcp-dot'].forEach((id) => {
            const el = document.getElementById(id);
            if (!el) return;
            el.className = `health-dot ${cls}`;
            el.title = running ? 'MCP server running' : 'MCP server stopped';
        });
    }
    
    async updateDebugMode(enabled) {
        this.uiDebugMode = enabled;
        
        // Persist to backend
        const data = await this.api.updateConfig({ ui_debug: enabled });
        if (!data.success) {
            console.error('Failed to update debug mode:', data);
        }
    }
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    try {
        console.log('[AIController] Initializing...');
        window.controller = new AIController();
        console.log('[AIController] Initialized successfully');
    } catch (error) {
        console.error('[AIController] Initialization error:', error);
        // Show error to user
        const contentArea = document.querySelector('.content-area');
        if (contentArea) {
            contentArea.innerHTML = `
                <div style="padding: 20px; color: #f48771;">
                    <h2>Error Initializing Application</h2>
                    <p>${error.message}</p>
                    <p>Please check the browser console for more details.</p>
                </div>
            `;
        }
    }
});
