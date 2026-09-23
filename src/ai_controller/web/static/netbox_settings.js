// NetBox DCIM/IPAM settings page

class NetBoxSettingsManager {
    constructor(controller) {
        this.controller = controller;
        this.api = controller.api;
        this.settings = {
            base_url: '',
            api_token: '',
            timeout_seconds: 30,
            verify_ssl: true,
        };
        this.bind();
    }

    bind() {
        const save = document.getElementById('netbox-save-btn');
        if (save) save.addEventListener('click', () => this.save());
        const test = document.getElementById('netbox-test-btn');
        if (test) test.addEventListener('click', () => this.test());
    }

    async load() {
        const data = await this.api.getNetBoxSettings();
        if (!data || data.success === false) {
            this.setStatus((data && (data.error || data.detail)) || 'Could not load NetBox settings.', true);
            return;
        }
        this.settings = Object.assign({}, this.settings, data.settings || {});
        this.fillForm();
        this.setStatus('');
    }

    fillForm() {
        const url = document.getElementById('netbox-url');
        const token = document.getElementById('netbox-token');
        const timeout = document.getElementById('netbox-timeout');
        const verify = document.getElementById('netbox-verify-ssl');
        if (url) url.value = this.settings.base_url || '';
        if (token) token.value = this.settings.api_token || '';
        if (timeout) timeout.value = this.settings.timeout_seconds || 30;
        if (verify) verify.checked = this.settings.verify_ssl !== false;
    }

    readForm() {
        return {
            base_url: (document.getElementById('netbox-url') || {}).value || '',
            api_token: (document.getElementById('netbox-token') || {}).value || '',
            timeout_seconds: parseInt((document.getElementById('netbox-timeout') || {}).value, 10) || 30,
            verify_ssl: Boolean((document.getElementById('netbox-verify-ssl') || {}).checked),
        };
    }

    async save() {
        const payload = this.readForm();
        if (!payload.base_url.trim()) {
            this.setStatus('Base URL is required.', true);
            return;
        }
        if (window.toast) window.toast.info('Saving NetBox settings…', { key: 'netbox', duration: 0 });
        const data = await this.api.saveNetBoxSettings(payload);
        if (!data || data.success === false) {
            const message = (data && (data.error || data.detail)) || 'Could not save NetBox settings.';
            this.setStatus(message, true);
            if (window.toast) window.toast.error(message, { key: 'netbox' });
            return;
        }
        this.settings = Object.assign({}, this.settings, data.settings || payload);
        this.fillForm();
        this.setStatus('NetBox settings saved.');
        if (window.toast) window.toast.success('NetBox settings saved.', { key: 'netbox' });
        if (this.controller.integrationsSettings) this.controller.integrationsSettings.load();
        if (this.controller.mcpPanel) this.controller.mcpPanel.refresh();
    }

    async test() {
        const payload = this.readForm();
        if (!payload.base_url.trim()) {
            this.setStatus('Base URL is required before testing.', true);
            return;
        }
        if (window.toast) window.toast.info('Testing NetBox…', { key: 'netbox', duration: 0 });
        const data = await this.api.testNetBoxSettings(payload);
        const ok = Boolean(data && (data.ok || data.success));
        const message = (data && data.message) || (ok ? 'NetBox connection passed.' : 'NetBox connection failed.');
        this.setStatus(message, !ok);
        if (window.toast) {
            if (ok) window.toast.success(message, { key: 'netbox' });
            else window.toast.error(message, { key: 'netbox' });
        }
    }

    setStatus(message, isError = false) {
        const el = document.getElementById('netbox-settings-status');
        if (!el) return;
        el.hidden = !message;
        el.className = `settings-status${isError ? ' is-error' : ''}`;
        el.textContent = message || '';
    }
}

window.NetBoxSettingsManager = NetBoxSettingsManager;
