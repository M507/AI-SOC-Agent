// Configuration Manager JavaScript

let currentConfig = {};

// Check authentication status on page load
document.addEventListener('DOMContentLoaded', async () => {
    // Check if authenticated
    try {
        const response = await fetch('/api/auth/status');
        const result = await response.json();
        if (!result.authenticated) {
            window.location.href = '/';
            return;
        }
    } catch (error) {
        console.error('Failed to check auth status:', error);
        window.location.href = '/';
        return;
    }
    
    // Load config and setup
    loadConfig();
    setupEventListeners();
    setupLogout();
});

function setupLogout() {
    // Add logout button if it doesn't exist
    const header = document.querySelector('header');
    if (header && !document.getElementById('logout-btn')) {
        const logoutBtn = document.createElement('button');
        logoutBtn.id = 'logout-btn';
        logoutBtn.className = 'btn-secondary';
        logoutBtn.style.cssText = 'position: absolute; top: 20px; right: 20px; padding: 8px 16px; font-size: 14px;';
        logoutBtn.textContent = 'Logout';
        logoutBtn.onclick = async () => {
            try {
                await fetch('/api/auth/logout', { method: 'POST' });
                window.location.href = '/';
            } catch (error) {
                console.error('Logout failed:', error);
            }
        };
        header.style.position = 'relative';
        header.appendChild(logoutBtn);
    }
}

function setupEventListeners() {
    // Enable/disable toggles
    document.getElementById('thehive-enabled').addEventListener('change', (e) => {
        toggleSection('thehive', e.target.checked);
    });
    
    document.getElementById('iris-enabled').addEventListener('change', (e) => {
        toggleSection('iris', e.target.checked);
    });
    
    document.getElementById('elastic-enabled').addEventListener('change', (e) => {
        toggleSection('elastic', e.target.checked);
    });
    
    document.getElementById('edr-enabled').addEventListener('change', (e) => {
        toggleSection('edr', e.target.checked);
    });

    // Form submission
    document.getElementById('config-form').addEventListener('submit', (e) => {
        e.preventDefault();
        saveConfig();
    });
}

function toggleSection(section, enabled) {
    const content = document.getElementById(`${section}-content`);
    if (enabled) {
        content.style.display = 'block';
        // Make required fields required when enabled
        const inputs = content.querySelectorAll('input[type="url"], input[type="password"]');
        inputs.forEach(input => {
            if (input.id.includes('url') || input.id.includes('api-key')) {
                input.required = true;
            }
        });
    } else {
        content.style.display = 'none';
        // Remove required when disabled
        const inputs = content.querySelectorAll('input[type="url"], input[type="password"]');
        inputs.forEach(input => input.required = false);
    }
}

async function loadConfig() {
    try {
        const response = await fetch('/api/config');
        if (response.status === 401) {
            // Not authenticated, redirect to login
            window.location.href = '/';
            return;
        }
        if (!response.ok) throw new Error('Failed to load configuration');
        
        const config = await response.json();
        currentConfig = config;
        
        // Handle masked passwords (replace *** with actual value if we have it)
        // Note: We need to keep the current values since API masks them for security
        
        // Load TheHive config
        if (config.thehive) {
            document.getElementById('thehive-enabled').checked = true;
            document.getElementById('thehive-url').value = config.thehive.base_url || '';
            // Only set API key if it's not masked (***)
            if (config.thehive.api_key && config.thehive.api_key !== '***') {
                document.getElementById('thehive-api-key').value = config.thehive.api_key || '';
            }
            document.getElementById('thehive-timeout').value = config.thehive.timeout_seconds || 30;
            toggleSection('thehive', true);
        } else {
            document.getElementById('thehive-enabled').checked = false;
            toggleSection('thehive', false);
        }
        
        // Load IRIS config
        if (config.iris) {
            document.getElementById('iris-enabled').checked = true;
            document.getElementById('iris-url').value = config.iris.base_url || '';
            // Only set API key if it's not masked (***)
            if (config.iris.api_key && config.iris.api_key !== '***') {
                document.getElementById('iris-api-key').value = config.iris.api_key || '';
            }
            document.getElementById('iris-timeout').value = config.iris.timeout_seconds || 30;
            toggleSection('iris', true);
        } else {
            document.getElementById('iris-enabled').checked = false;
            toggleSection('iris', false);
        }
        
        // Load Elastic config
        if (config.elastic) {
            document.getElementById('elastic-enabled').checked = true;
            document.getElementById('elastic-url').value = config.elastic.base_url || '';
            if (config.elastic.api_key && config.elastic.api_key !== '***') {
                document.getElementById('elastic-api-key').value = config.elastic.api_key || '';
            }
            document.getElementById('elastic-username').value = config.elastic.username || '';
            if (config.elastic.password && config.elastic.password !== '***') {
                document.getElementById('elastic-password').value = config.elastic.password || '';
            }
            document.getElementById('elastic-timeout').value = config.elastic.timeout_seconds || 30;
            document.getElementById('elastic-verify-ssl').checked = config.elastic.verify_ssl !== false;
            toggleSection('elastic', true);
        } else {
            document.getElementById('elastic-enabled').checked = false;
            toggleSection('elastic', false);
        }
        
        // Load EDR config
        if (config.edr) {
            document.getElementById('edr-enabled').checked = true;
            document.getElementById('edr-type').value = config.edr.edr_type || 'velociraptor';
            document.getElementById('edr-url').value = config.edr.base_url || '';
            if (config.edr.api_key && config.edr.api_key !== '***') {
                document.getElementById('edr-api-key').value = config.edr.api_key || '';
            }
            document.getElementById('edr-timeout').value = config.edr.timeout_seconds || 30;
            toggleSection('edr', true);
        } else {
            document.getElementById('edr-enabled').checked = false;
            toggleSection('edr', false);
        }
        
        // Load Logging config
        if (config.logging) {
            document.getElementById('log-dir').value = config.logging.log_dir || 'logs';
            document.getElementById('log-level').value = config.logging.log_level || 'INFO';
        }
        
        // Display file locations
        if (config._meta) {
            const fileLocations = document.getElementById('file-locations');
            if (fileLocations) {
                let html = '';
                if (config._meta.env_file_exists) {
                    html += `<div>📄 .env: <code>${config._meta.env_file}</code></div>`;
                } else {
                    html += `<div>📄 .env: <code>${config._meta.env_file}</code> <span style="color: #999;">(not found)</span></div>`;
                }
                if (config._meta.config_file_exists) {
                    html += `<div>📄 config.json: <code>${config._meta.config_file}</code></div>`;
                } else {
                    html += `<div>📄 config.json: <code>${config._meta.config_file}</code> <span style="color: #999;">(not found)</span></div>`;
                }
                fileLocations.innerHTML = html;
            }
        }
        
    } catch (error) {
        showAlert('Failed to load configuration: ' + error.message, 'error');
    }
}

async function reloadFromFiles() {
    const reloadBtn = document.getElementById('reload-btn');
    if (!reloadBtn) return;
    
    try {
        reloadBtn.disabled = true;
        reloadBtn.textContent = '🔄 Reloading...';
        
        const response = await fetch('/api/config/reload', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
        });
        
        if (response.status === 401) {
            window.location.href = '/';
            return;
        }
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to reload configuration');
        }
        
        const result = await response.json();
        if (result.success) {
            showAlert('Configuration reloaded from files successfully!', 'success');
            // Reload the form with fresh data
            await loadConfig();
        } else {
            throw new Error(result.message || 'Reload failed');
        }
    } catch (error) {
        showAlert('Failed to reload configuration: ' + error.message, 'error');
    } finally {
        reloadBtn.disabled = false;
        reloadBtn.textContent = '🔄 Reload from Files';
    }
}

async function saveConfig() {
    try {
        // Check authentication first
        const authCheck = await fetch('/api/auth/status');
        if (!authCheck.ok || !(await authCheck.json()).authenticated) {
            window.location.href = '/';
            return;
        }
        
        const configUpdate = {
            thehive: document.getElementById('thehive-enabled').checked ? {
                enabled: true,
                base_url: document.getElementById('thehive-url').value,
                api_key: document.getElementById('thehive-api-key').value,
                timeout_seconds: parseInt(document.getElementById('thehive-timeout').value) || 30,
            } : { enabled: false },
            
            iris: document.getElementById('iris-enabled').checked ? {
                enabled: true,
                base_url: document.getElementById('iris-url').value,
                api_key: document.getElementById('iris-api-key').value,
                timeout_seconds: parseInt(document.getElementById('iris-timeout').value) || 30,
            } : { enabled: false },
            
            elastic: document.getElementById('elastic-enabled').checked ? {
                enabled: true,
                base_url: document.getElementById('elastic-url').value,
                api_key: document.getElementById('elastic-api-key').value || null,
                username: document.getElementById('elastic-username').value || null,
                password: document.getElementById('elastic-password').value || null,
                timeout_seconds: parseInt(document.getElementById('elastic-timeout').value) || 30,
                verify_ssl: document.getElementById('elastic-verify-ssl').checked,
            } : { enabled: false },
            
            edr: document.getElementById('edr-enabled').checked ? {
                enabled: true,
                edr_type: document.getElementById('edr-type').value,
                base_url: document.getElementById('edr-url').value,
                api_key: document.getElementById('edr-api-key').value,
                timeout_seconds: parseInt(document.getElementById('edr-timeout').value) || 30,
            } : { enabled: false },
            
            logging: {
                log_dir: document.getElementById('log-dir').value || 'logs',
                log_level: document.getElementById('log-level').value || 'INFO',
            },
        };
        
        const response = await fetch('/api/config', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(configUpdate),
        });
        
        if (response.status === 401) {
            window.location.href = '/';
            return;
        }
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to save configuration');
        }
        
        const result = await response.json();
        currentConfig = result.config;
        showAlert('Configuration saved successfully!', 'success');
        
    } catch (error) {
        showAlert('Failed to save configuration: ' + error.message, 'error');
    }
}

async function testConnection(type) {
    const testBtn = event.target;
    const originalText = testBtn.textContent;
    
    testBtn.disabled = true;
    testBtn.innerHTML = '<span class="spinner"></span> Testing...';
    
    try {
        const response = await fetch(`/api/config/test/${type}`);
        const result = await response.json();
        
        if (result.success) {
            showAlert(`${type.toUpperCase()} connection test successful!`, 'success');
        } else {
            showAlert(`${type.toUpperCase()} connection test failed: ${result.message}`, 'error');
        }
    } catch (error) {
        showAlert(`Connection test failed: ${error.message}`, 'error');
    } finally {
        testBtn.disabled = false;
        testBtn.textContent = originalText;
    }
}

function showAlert(message, type = 'success') {
    const alert = document.getElementById('alert');
    alert.textContent = message;
    alert.className = `alert ${type}`;
    alert.style.display = 'block';
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
        alert.style.display = 'none';
    }, 5000);
    
    // Scroll to top to see alert
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

