// AI Controller Main Application
// Orchestrates all components

class AIController {
    constructor() {
        // Core state
        this.activeSessionId = null;
        this.uiDebugMode = false;
        this.uiThinkingMode = false;
        this.generalDefaults = {
            max_tool_iterations: 12,
            tool_result_chars: 8000,
            trace_chars: 6000,
            request_timeout_seconds: 180,
        };
        this.activeSection = 'overview';
        this.activeSettingsPage = 'llm';
        this.activeLibraryPage = 'runbooks';
        this.activeDetectionsPage = 'findings';
        this.mcpReadiness = null;
        this.lastMCPAlertCode = null;
        
        // Initialize managers
        this.api = new APIClient();
        this.wsManager = new WebSocketManager(this);
        this.terminal = new TerminalRenderer(this);
        this.sessionManager = new SessionManager(this);
        this.autorunManager = new AutorunManager(this);
        this.modals = new ModalManager(this);
        this.settingsManager = new SettingsManager(this);
        this.elasticClusters = new ElasticClustersManager(this);
        this.netboxSettings = new NetBoxSettingsManager(this);
        this.integrationsSettings = new IntegrationsSettingsManager(this);
        this.mcpPanel = new MCPPanel(this);
        this.requestsManager = new RequestsManager(this);
        this.costManager = new CostManager(this);
        this.overviewManager = new OverviewManager(this);
        this.libraryManager = new LibraryManager(this);
        this.reportsManager = new ReportsManager(this);
        this.auditManager = new AuditManager(this);
        this.operatorsManager = new OperatorsManager(this);
        this.detectionsManager = new DetectionsManager(this);
        
        this.init();
    }
    
    init() {
        this.setupEventListeners();
        this.loadConfig();
        this.settingsManager.load();
        this.elasticClusters.load();
        this.netboxSettings.load();
        this.integrationsSettings.load();
        this.mcpPanel.refresh();
        this.refreshMCPReadiness({ notify: true });
        // Default view is manual sessions; load initial data
        this.loadSessions('manual');
        this.loadAutoruns();
        this.requestsManager.load();

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

            if (this.activeSection === 'cost' && this.costManager && this.costManager.activePage !== 'rates') {
                this.costManager.load();
            }
            if (this.activeSection === 'overview' && this.overviewManager) {
                this.overviewManager.load();
            }
        }, 3000);

        this.mcpHealthInterval = setInterval(() => {
            this.mcpPanel.refresh();
        }, 10000);
        this.mcpReadinessInterval = setInterval(() => {
            this.refreshMCPReadiness();
        }, 30000);
        this.setActiveSection('overview');
    }
    
    setupEventListeners() {
        const sidebar = document.querySelector('.sidebar');
        if (sidebar) {
            sidebar.addEventListener('click', (event) => {
                const item = event.target.closest('.nav-item[data-nav]');
                if (!item) return;
                if (item.dataset.settingsPage) {
                    this.activeSettingsPage = item.dataset.settingsPage;
                }
                if (item.dataset.libraryPage) {
                    this.activeLibraryPage = item.dataset.libraryPage;
                }
                if (item.dataset.detectionsPage) {
                    this.activeDetectionsPage = item.dataset.detectionsPage;
                }
                this.setActiveSection(item.dataset.nav);
            });
        }
        const readinessAction = document.getElementById('mcp-readiness-action');
        if (readinessAction) {
            readinessAction.addEventListener('click', () => this.openMCPReadinessAction());
        }

        const emptyNewSessionBtn = document.getElementById('empty-new-session-btn');
        if (emptyNewSessionBtn) {
            emptyNewSessionBtn.addEventListener('click', () => {
                this.setActiveSection('sessions');
                this.modals.showNewSession();
            });
        }
        const emptyNewAutorunBtn = document.getElementById('empty-new-autorun-btn');
        if (emptyNewAutorunBtn) {
            emptyNewAutorunBtn.addEventListener('click', () => {
                this.setActiveSection('autoruns');
                this.modals.showNewAutorun();
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
                this.activeSettingsPage = 'llm';
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
        
        // Request queue tabs stay in the horizontal strip. Settings pages live in the sidebar.
        const requestsTabs = document.getElementById('requests-tabs');
        if (requestsTabs) {
            requestsTabs.addEventListener('click', (event) => {
                const tab = event.target.closest('[data-request-queue]');
                if (!tab) {
                    return;
                }
                if (this.activeSection !== 'requests') {
                    this.setActiveSection('requests');
                }
                if (this.requestsManager) {
                    this.requestsManager.setQueueTab(tab.dataset.requestQueue);
                }
            });
        }
        
        // Debug toggle
        const debugToggle = document.getElementById('debug-toggle');
        if (debugToggle) {
            debugToggle.addEventListener('change', () => {
                this.updateDebugMode(debugToggle.checked);
            });
        }
        const thinkingToggle = document.getElementById('thinking-toggle');
        if (thinkingToggle) {
            thinkingToggle.addEventListener('change', () => {
                this.updateThinkingMode(thinkingToggle.checked);
            });
        }
        const generalSave = document.getElementById('general-save-btn');
        if (generalSave) {
            generalSave.addEventListener('click', () => this.saveGeneralLimits());
        }
        const generalReset = document.getElementById('general-reset-btn');
        if (generalReset) {
            generalReset.addEventListener('click', () => this.resetGeneralLimits());
        }
        const detectionSave = document.getElementById('detection-settings-save');
        if (detectionSave) {
            detectionSave.addEventListener('click', () => this.saveDetectionSettings());
        }
    }
    
    async loadConfig() {
        const data = await this.api.loadConfig();
        if (data && data.success) {
            this.uiDebugMode = data.ui_debug === true;
            this.uiThinkingMode = data.ui_thinking === true;
            const debugToggle = document.getElementById('debug-toggle');
            if (debugToggle) {
                debugToggle.checked = this.uiDebugMode;
            }
            const thinkingToggle = document.getElementById('thinking-toggle');
            if (thinkingToggle) {
                thinkingToggle.checked = this.uiThinkingMode;
            }
            this.generalDefaults = data.defaults || this.generalDefaults;
            this.fillGeneralLimits(data);
            this.loadDetectionSettings();
        }
    }

    fillGeneralLimits(data) {
        const fields = {
            'general-max-rounds': data.max_tool_iterations,
            'general-tool-result-chars': data.tool_result_chars,
            'general-trace-chars': data.trace_chars,
            'general-request-timeout': data.request_timeout_seconds,
        };
        Object.entries(fields).forEach(([id, value]) => {
            const input = document.getElementById(id);
            if (input && value != null && value !== '') {
                input.value = value;
            }
        });
    }

    fillDetectionSettings(settings) {
        const path = document.getElementById('detection-rules-dir');
        const findings = document.getElementById('detection-findings-hours');
        const match = document.getElementById('detection-match-hours');
        const status = document.getElementById('detection-rules-status');
        if (!settings) return;
        if (path) path.value = settings.rules_dir || '';
        if (findings && settings.findings_hours != null) findings.value = settings.findings_hours;
        if (match && settings.match_hours != null) match.value = settings.match_hours;
        if (status) {
            const bits = [];
            if (settings.env_override) {
                bits.push('SAMI_LAB_RULES_DIR is set and overrides the folder saved here.');
            }
            if (settings.effective_path) {
                bits.push(settings.configured
                    ? 'Using ' + settings.effective_path + '.'
                    : 'Folder not found: ' + settings.effective_path + '.');
            } else {
                bits.push('No rules folder is configured.');
            }
            status.textContent = bits.join(' ');
        }
    }

    async loadDetectionSettings() {
        const response = await this.api._fetch('/api/detections/settings');
        const data = await response.json().catch(() => ({}));
        if (response.ok && data.settings) {
            this.fillDetectionSettings(data.settings);
        }
    }

    async saveDetectionSettings() {
        const path = (document.getElementById('detection-rules-dir') || {}).value || '';
        const findings = Number((document.getElementById('detection-findings-hours') || {}).value);
        const match = Number((document.getElementById('detection-match-hours') || {}).value);
        const response = await this.api._fetch('/api/detections/settings', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                rules_dir: path.trim(),
                findings_hours: findings,
                match_hours: match,
            }),
        });
        const data = await response.json().catch(() => ({}));
        if (response.ok && data.success) {
            this.fillDetectionSettings(data.settings);
            if (window.toast) window.toast.success('Detection settings saved.', { key: 'ui' });
            if (this.detectionsManager && this.activeSection === 'detections') {
                this.detectionsManager.show(this.activeDetectionsPage);
            }
        } else {
            const detail = data.detail || data.error || 'Could not save detection settings';
            if (window.toast) window.toast.error(typeof detail === 'string' ? detail : 'Could not save detection settings', { key: 'ui' });
        }
    }

    async refreshVisibleTranscript() {
        if (this.activeSection === 'sessions' && this.activeSessionId) {
            await this.loadSessionDetails(this.activeSessionId);
        }
        if (this.activeSection === 'autoruns' && this.autorunManager && this.autorunManager.currentAutorunId) {
            const autorun = this.autorunManager.autoruns.get(this.autorunManager.currentAutorunId);
            if (autorun) {
                await this.loadAutorunSession(autorun);
            }
        }
    }

    async refreshMCPReadiness({ notify = false } = {}) {
        const readiness = await this.api.getMCPReadiness();
        this.mcpReadiness = readiness;
        this.renderMCPReadiness(readiness);

        if (
            notify
            && readiness
            && !readiness.ready
            && readiness.code !== this.lastMCPAlertCode
            && window.toast
        ) {
            window.toast.error(
                `${readiness.title}. ${readiness.message}`,
                { key: 'mcp-readiness', duration: 12000 }
            );
        }
        this.lastMCPAlertCode = readiness && readiness.ready ? null : (readiness && readiness.code);
        return readiness;
    }

    renderMCPReadiness(readiness) {
        const banner = document.getElementById('mcp-readiness-banner');
        if (!banner) return;
        const show = Boolean(readiness && !readiness.ready);
        banner.hidden = !show;
        banner.classList.toggle('is-error', Boolean(show && readiness.severity === 'error'));
        if (!show) return;

        const title = document.getElementById('mcp-readiness-title');
        const message = document.getElementById('mcp-readiness-message');
        const action = document.getElementById('mcp-readiness-action');
        if (title) title.textContent = readiness.title || 'AI tools are not connected';
        if (message) message.textContent = readiness.message || 'Open settings to connect MCP.';
        if (action) action.textContent = readiness.action_label || 'Open connection setup';
    }

    openMCPReadinessAction() {
        const readiness = this.mcpReadiness || {};
        if (readiness.action_section === 'mcp') {
            this.setActiveSection('mcp');
            return;
        }

        if (this.settingsManager) {
            this.settingsManager.revealOpenWebUI = true;
        }
        this.activeSettingsPage = readiness.action_page || 'llm';
        this.setActiveSection('settings');
        this.setSettingsPage(this.activeSettingsPage);
        const anchorId = readiness.action_anchor || 'openwebui-mcp-card';
        window.setTimeout(() => {
            const target = document.getElementById(anchorId);
            if (target) {
                target.hidden = false;
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });
                target.classList.add('settings-card-attention');
                window.setTimeout(() => target.classList.remove('settings-card-attention'), 2500);
            }
        }, 100);
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
            this.setClusterPill('session-cluster', session.cluster);
            
            // Render terminal
            this.terminal.render(session);
        }
    }
    
    async switchToSession(sessionId) {
        await this.sessionManager.switchToSession(sessionId);
    }
    
    async executeCommand() {
        if (!this.activeSessionId) {
            if (window.toast) {
                window.toast.info('Create or select a session first.', { key: 'session' });
            }
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
        const known = ['overview', 'sessions', 'autoruns', 'cost', 'requests', 'settings', 'mcp', 'library', 'audit', 'reports', 'operators', 'detections'];
        if (!known.includes(section)) {
            console.warn('[AIController] Unknown section:', section);
            return;
        }

        const previous = this.activeSection;
        this.activeSection = section;
        this.syncNav();

        const tabbed = ['sessions', 'autoruns', 'cost', 'requests'];
        const tabsContainer = document.getElementById('tabs-container');
        if (tabsContainer) {
            tabsContainer.style.display = tabbed.includes(section) ? '' : 'none';
        }
        const sessionsGroup = document.getElementById('sessions-tab-group');
        const autorunsGroup = document.getElementById('autoruns-tab-group');
        const costGroup = document.getElementById('cost-tab-group');
        const requestsGroup = document.getElementById('requests-tab-group');
        if (sessionsGroup) sessionsGroup.style.display = section === 'sessions' ? 'flex' : 'none';
        if (autorunsGroup) autorunsGroup.style.display = section === 'autoruns' ? 'flex' : 'none';
        if (costGroup) costGroup.style.display = section === 'cost' ? 'flex' : 'none';
        if (requestsGroup) requestsGroup.style.display = section === 'requests' ? 'flex' : 'none';

        this.syncHeaderActions(section);

        const sessionContent = document.getElementById('session-content');
        const mcpContent = document.getElementById('mcp-content');
        const requestsContent = document.getElementById('requests-content');
        const costContent = document.getElementById('cost-content');
        const noSessionMessage = document.getElementById('no-session-message');
        const overviewContent = document.getElementById('overview-content');
        const libraryContent = document.getElementById('library-content');
        const reportsContent = document.getElementById('reports-content');
        const auditContent = document.getElementById('audit-content');
        const operatorsContent = document.getElementById('operators-content');
        const detectionsContent = document.getElementById('detections-content');

        if (section !== 'settings') {
            this.hideSettingsPages();
        }
        if (section !== 'autoruns' && this.autorunManager) {
            this.autorunManager.setPanelOpen(false);
            this.autorunManager.setEmptyVisible(false);
        }

        const show = (element, display) => {
            if (element) element.style.display = display;
        };
        show(requestsContent, section === 'requests' ? 'flex' : 'none');
        show(costContent, section === 'cost' ? 'flex' : 'none');
        show(overviewContent, section === 'overview' ? 'flex' : 'none');
        show(libraryContent, section === 'library' ? 'flex' : 'none');
        show(reportsContent, section === 'reports' ? 'flex' : 'none');
        show(auditContent, section === 'audit' ? 'flex' : 'none');
        show(operatorsContent, section === 'operators' ? 'flex' : 'none');
        show(detectionsContent, section === 'detections' ? 'flex' : 'none');
            show(mcpContent, section === 'mcp' ? 'flex' : 'none');
        show(sessionContent, 'none');
        show(noSessionMessage, 'none');

        if (section === 'sessions') {
            show(sessionContent, this.activeSessionId ? 'flex' : 'none');
            show(noSessionMessage, this.activeSessionId ? 'none' : 'flex');
        } else if (section === 'autoruns') {
            this.autorunManager.syncView();
            this.autorunManager.fitStrip();
        } else if (section === 'overview') {
            if (this.overviewManager) this.overviewManager.load();
        } else if (section === 'library') {
            if (this.libraryManager) this.libraryManager.load(this.activeLibraryPage);
        } else if (section === 'reports') {
            if (this.reportsManager) this.reportsManager.load();
        } else if (section === 'audit') {
            if (this.auditManager) this.auditManager.load();
        } else if (section === 'operators') {
            if (this.operatorsManager) this.operatorsManager.load();
        } else if (section === 'detections') {
            if (this.detectionsManager) this.detectionsManager.show(this.activeDetectionsPage);
        } else if (section === 'cost') {
            document.querySelectorAll('button.tab[data-session-id]').forEach((tab) => {
                tab.classList.remove('active');
            });
            if (this.costManager) {
                this.costManager.setPage(this.costManager.activePage || 'overview');
                this.costManager.load();
            }
            if (this.activeSessionId) {
                this.wsManager.disconnect(this.activeSessionId);
            }
        } else if (section === 'requests') {
            document.querySelectorAll('button.tab[data-session-id]').forEach((tab) => {
                tab.classList.remove('active');
            });
            const requestsTab = document.querySelector('#requests-tabs .tab.active') || document.getElementById('requests-tab');
            if (requestsTab) {
                requestsTab.classList.add('active');
            }
            this.requestsManager.show({ justOpened: previous !== 'requests' });
            if (this.activeSessionId) {
                this.wsManager.disconnect(this.activeSessionId);
            }
        } else if (section === 'settings') {
            document.querySelectorAll('button.tab[data-session-id]').forEach((tab) => {
                tab.classList.remove('active');
            });
            this.setSettingsPage(this.activeSettingsPage);
            this.settingsManager.load();
            if (this.elasticClusters) this.elasticClusters.load();
            if (this.netboxSettings) this.netboxSettings.load();
            if (this.integrationsSettings) this.integrationsSettings.load();
            if (this.activeSessionId) {
                this.wsManager.disconnect(this.activeSessionId);
            }
        } else if (section === 'mcp') {
            show(mcpContent, 'flex');
            this.mcpPanel.load();
            if (this.activeSessionId) {
                this.wsManager.disconnect(this.activeSessionId);
            }
        }

        if (previous === 'requests' && section !== 'requests') {
            this.requestsManager.hide();
        }
    }

    syncNav() {
        document.querySelectorAll('.nav-item[data-nav]').forEach((item) => {
            let on = item.dataset.nav === this.activeSection;
            if (on && item.dataset.settingsPage) {
                on = item.dataset.settingsPage === this.activeSettingsPage;
            }
            if (on && item.dataset.libraryPage) {
                on = item.dataset.libraryPage === this.activeLibraryPage;
            }
            if (on && item.dataset.detectionsPage) {
                on = item.dataset.detectionsPage === this.activeDetectionsPage;
            }
            item.classList.toggle('active', on);
        });
    }

    syncHeaderActions(section) {
        const newSessionBtn = document.getElementById('new-session-btn');
        const newAutorunBtn = document.getElementById('new-autorun-btn');
        if (newSessionBtn) {
            newSessionBtn.hidden = section !== 'sessions';
        }
        if (newAutorunBtn) {
            newAutorunBtn.hidden = section !== 'autoruns';
        }
    }

    hideSettingsPages() {
        document.querySelectorAll('[data-settings-page-content]').forEach((panel) => {
            panel.style.display = 'none';
        });
    }

    setSettingsPage(pageId) {
        const tabs = Array.from(document.querySelectorAll('.nav-item[data-settings-page]'));
        const pages = tabs.map((tab) => tab.dataset.settingsPage);
        if (!pageId || !pages.includes(pageId)) {
            pageId = pages.includes(this.activeSettingsPage) ? this.activeSettingsPage : pages[0];
        }
        this.activeSettingsPage = pageId || 'llm';
        this.syncNav();
        document.querySelectorAll('[data-settings-page-content]').forEach((panel) => {
            panel.style.display = panel.dataset.settingsPageContent === this.activeSettingsPage ? 'flex' : 'none';
        });
    }
    
    showSettings() {
        this.setActiveSection('settings');
    }

    setClusterPill(elementId, cluster) {
        const el = document.getElementById(elementId);
        if (!el) return;
        const name = cluster && cluster.name;
        if (!name) {
            el.hidden = true;
            el.textContent = '';
            el.removeAttribute('title');
            return;
        }
        el.hidden = false;
        el.textContent = name;
        el.title = cluster.base_url ? `${name} — ${cluster.base_url}` : name;
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
        
        const data = await this.api.updateConfig({ ui_debug: enabled });
        if (data.success) {
            await this.refreshVisibleTranscript();
            if (window.toast) {
                window.toast.success(
                    enabled ? 'Debug mode on — full JSON will be shown.' : 'Debug mode off — replies only.',
                    { key: 'ui' }
                );
            }
        } else {
            console.error('Failed to update debug mode:', data);
            if (window.toast) {
                window.toast.error(data.error || 'Could not save debug mode', { key: 'ui' });
            }
        }
    }

    async updateThinkingMode(enabled) {
        this.uiThinkingMode = enabled;
        const data = await this.api.updateConfig({ ui_thinking: enabled });
        if (data.success) {
            await this.refreshVisibleTranscript();
            if (window.toast) {
                window.toast.success(
                    enabled
                        ? 'Thinking view on — decisions and MCP tools will be shown.'
                        : 'Thinking view off.',
                    { key: 'ui' }
                );
            }
        } else if (window.toast) {
            window.toast.error(data.error || 'Could not save thinking view', { key: 'ui' });
        }
    }

    async saveGeneralLimits(message) {
        const numberValue = (id) => Number((document.getElementById(id) || {}).value);
        const payload = {
            max_tool_iterations: numberValue('general-max-rounds'),
            tool_result_chars: numberValue('general-tool-result-chars'),
            trace_chars: numberValue('general-trace-chars'),
            request_timeout_seconds: numberValue('general-request-timeout'),
        };
        const data = await this.api.updateConfig(payload);
        if (data && data.success) {
            if (data.defaults) {
                this.generalDefaults = data.defaults;
            }
            this.fillGeneralLimits(data);
            if (window.toast) {
                window.toast.success(message || 'Investigation limits saved.', { key: 'ui' });
            }
        } else if (window.toast) {
            window.toast.error((data && (data.error || data.detail)) || 'Could not save limits', { key: 'ui' });
        }
    }

    async resetGeneralLimits() {
        this.fillGeneralLimits(this.generalDefaults);
        await this.saveGeneralLimits('Investigation limits restored to defaults.');
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
                <div class="init-error">
                    <h2>Error Initializing Application</h2>
                    <p>${error.message}</p>
                    <p>Please check the browser console for more details.</p>
                </div>
            `;
        }
    }
});
