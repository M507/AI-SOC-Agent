class CostManager {
    constructor(controller) {
        this.controller = controller;
        this.data = null;
        this.activePage = 'overview';
        this._bound = false;
    }

    bind() {
        if (this._bound) {
            return;
        }
        this._bound = true;
        document.querySelectorAll('#cost-tabs [data-cost-page]').forEach((tab) => {
            tab.addEventListener('click', () => this.setPage(tab.dataset.costPage));
        });
        const refresh = document.getElementById('cost-refresh-btn');
        if (refresh) {
            refresh.addEventListener('click', () => this.load({ force: true }));
        }
        const ratesRoot = document.getElementById('cost-rates');
        if (ratesRoot) {
            ratesRoot.addEventListener('click', (event) => {
                if (event.target && event.target.id === 'cost-auto-save') {
                    this.saveAutoRates();
                }
            });
        }
    }

    setPage(pageId) {
        const pages = ['overview', 'sessions', 'models', 'calls', 'rates'];
        this.activePage = pages.includes(pageId) ? pageId : 'overview';
        document.querySelectorAll('#cost-tabs [data-cost-page]').forEach((tab) => {
            tab.classList.toggle('active', tab.dataset.costPage === this.activePage);
        });
        document.querySelectorAll('[data-cost-page-content]').forEach((panel) => {
            panel.style.display = panel.dataset.costPageContent === this.activePage ? 'block' : 'none';
        });
        this.render();
    }

    async load() {
        this.bind();
        const data = await this.controller.api.loadUsage();
        this.data = data;
        this.render();
        return data;
    }

    render() {
        const data = this.data;
        const status = document.getElementById('cost-status');
        if (!data || data.success === false) {
            if (status) {
                status.hidden = false;
                status.textContent = (data && (data.error || data.detail)) || 'Could not load usage.';
            }
            return;
        }
        if (status) {
            const notes = [];
            if (!data.pricing_ok) {
                notes.push('Pricing file unreadable. Token counts are shown; dollar amounts are not.');
            }
            if (data.unreported_calls) {
                notes.push(`${data.unreported_calls} call${data.unreported_calls === 1 ? '' : 's'} did not report usage.`);
            }
            if (data.unpriced_calls) {
                notes.push(`${data.unpriced_calls} priced-unknown model${data.unpriced_calls === 1 ? '' : 's'} — add a rate on the Rates tab.`);
            }
            status.hidden = notes.length === 0;
            status.textContent = notes.join(' ');
        }
        this.renderOverview(data);
        this.renderSessions(data);
        this.renderModels(data);
        this.renderCalls(data);
        this.renderRates(data);
    }

    renderOverview(data) {
        const root = document.getElementById('cost-overview');
        if (!root) {
            return;
        }
        const windows = [
            ['today', 'Today'],
            ['7d', '7 days'],
            ['30d', '30 days'],
            ['all', 'All time'],
        ];
        const cards = windows.map(([key, label]) => {
            const summary = (data.overview && data.overview[key]) || {};
            return `<article class="cost-card">
                <h3>${this.escape(label)}</h3>
                <p class="cost-metric">${this.escape(summary.cost_label || (summary.reported_calls ? 'unpriced' : 'usage not reported'))}</p>
                <p class="settings-help">${this.number(summary.input_tokens)} in · ${this.number(summary.cached_input_tokens)} cached · ${this.number(summary.output_tokens)} out · ${this.number(summary.calls)} calls</p>
            </article>`;
        }).join('');
        const models = (data.models || []).slice(0, 8).map((row) => `
            <tr>
                <td>${this.escape(row.model)}</td>
                <td>${this.escape(row.cost_label || (row.reported_calls ? 'unpriced' : 'not reported'))}</td>
                <td>${this.number(row.input_tokens)}</td>
                <td>${this.number(row.output_tokens)}</td>
                <td>${this.number(row.calls)}</td>
            </tr>
        `).join('') || '<tr><td colspan="5">No model calls recorded yet.</td></tr>';
        root.innerHTML = `
            <section class="cost-grid">${cards}</section>
            <section class="settings-card">
                <h3>Spend by model</h3>
                <div class="cost-table-wrap">
                    <table class="cost-table">
                        <thead><tr><th>Model</th><th>Cost</th><th>Input</th><th>Output</th><th>Calls</th></tr></thead>
                        <tbody>${models}</tbody>
                    </table>
                </div>
            </section>
        `;
    }

    renderSessions(data) {
        const root = document.getElementById('cost-sessions');
        if (!root) {
            return;
        }
        const rows = (data.sessions || []).map((row) => `
            <tr>
                <td>${this.escape(row.session_name || 'Untitled session')}</td>
                <td>${this.escape(row.session_type === 'autorun' ? 'Autorun' : 'Manual')}</td>
                <td>${this.escape(row.autorun_name || '')}</td>
                <td>${this.escape(row.cost_label || (row.reported_calls ? 'unpriced' : 'not reported'))}</td>
                <td>${this.number(row.input_tokens)}</td>
                <td>${this.number(row.output_tokens)}</td>
                <td>${this.number(row.calls)}</td>
                <td>${this.escape(this.when(row.last_at))}</td>
            </tr>
        `).join('') || '<tr><td colspan="8">No session spend yet. Run a prompt in Sessions or Autoruns.</td></tr>';
        root.innerHTML = `
            <section class="settings-card">
                <h3>Sessions</h3>
                <p class="settings-help">Names are stored with the token row, so deleting a session later still leaves this history.</p>
                <div class="cost-table-wrap">
                    <table class="cost-table">
                        <thead><tr><th>Session</th><th>Type</th><th>Autorun</th><th>Cost</th><th>Input</th><th>Output</th><th>Calls</th><th>Last</th></tr></thead>
                        <tbody>${rows}</tbody>
                    </table>
                </div>
            </section>
        `;
    }

    renderModels(data) {
        const root = document.getElementById('cost-models');
        if (!root) {
            return;
        }
        const rows = (data.models || []).map((row) => {
            const rates = row.rates || {};
            return `<tr>
                <td>${this.escape(row.model)}</td>
                <td>${this.escape(row.provider || '')}</td>
                <td>${this.escape(row.cost_label || (row.reported_calls ? 'unpriced' : 'not reported'))}</td>
                <td>${this.number(row.input_tokens)}</td>
                <td>${this.number(row.cached_input_tokens)}</td>
                <td>${this.number(row.output_tokens)}</td>
                <td>${this.number(row.calls)}</td>
                <td>${rates.input != null ? `$${rates.input} / $${rates.cache_read} / $${rates.output}` : '—'}</td>
            </tr>`;
        }).join('') || '<tr><td colspan="8">No model usage yet.</td></tr>';
        root.innerHTML = `
            <section class="settings-card">
                <h3>Models</h3>
                <p class="settings-help">Rates are dollars per million tokens: input / cached input / output, taken from pricing.json.</p>
                <div class="cost-table-wrap">
                    <table class="cost-table">
                        <thead><tr><th>Model</th><th>Provider</th><th>Cost</th><th>Input</th><th>Cached</th><th>Output</th><th>Calls</th><th>Rate / 1M</th></tr></thead>
                        <tbody>${rows}</tbody>
                    </table>
                </div>
            </section>
        `;
    }

    renderCalls(data) {
        const root = document.getElementById('cost-calls');
        if (!root) {
            return;
        }
        const rows = (data.calls || []).map((row) => `
            <tr>
                <td>${this.escape(this.when(row.at))}</td>
                <td>${this.escape(row.session_name || '')}</td>
                <td>${this.escape(row.session_type === 'autorun' ? 'Autorun' : 'Manual')}</td>
                <td>${this.escape(row.reported_model || row.model || '')}</td>
                <td>${row.usage_reported ? this.escape(row.cost_label || 'unpriced') : 'usage not reported'}</td>
                <td>${this.number(row.input_tokens)}</td>
                <td>${this.number(row.cached_input_tokens)}</td>
                <td>${this.number(row.output_tokens)}</td>
                <td>${this.escape(row.command || '')}</td>
            </tr>
        `).join('') || '<tr><td colspan="9">No model calls recorded yet.</td></tr>';
        root.innerHTML = `
            <section class="settings-card">
                <h3>Calls</h3>
                <p class="settings-help">One row per model round. Newest first. The command is a short snippet, not the full prompt.</p>
                <div class="cost-table-wrap">
                    <table class="cost-table">
                        <thead><tr><th>When</th><th>Session</th><th>Type</th><th>Model</th><th>Cost</th><th>In</th><th>Cached</th><th>Out</th><th>Command</th></tr></thead>
                        <tbody>${rows}</tbody>
                    </table>
                </div>
            </section>
        `;
    }

    renderRates(data) {
        const root = document.getElementById('cost-rates');
        if (!root) {
            return;
        }
        const models = ((data.rates && data.rates.models) || {});
        const auto = models.auto || { input: 2.5, cache_write: 2.5, cache_read: 0.35, output: 10 };
        const rows = Object.entries(models).map(([key, rates]) => `
            <tr>
                <td>${this.escape((rates && rates.name) || key)}</td>
                <td>${this.escape((rates && rates.provider) || '')}</td>
                <td>${this.escape(String((rates && rates.input) != null ? rates.input : ''))}</td>
                <td>${this.escape(String((rates && rates.cache_write) != null ? rates.cache_write : ''))}</td>
                <td>${this.escape(String((rates && rates.cache_read) != null ? rates.cache_read : ''))}</td>
                <td>${this.escape(String((rates && rates.output) != null ? rates.output : ''))}</td>
            </tr>
        `).join('');
        root.innerHTML = `
            <section class="settings-card">
                <h3>Auto rates</h3>
                <p class="settings-help">These are the estimated Auto rates. Saving writes /var/lib/servee/pricing.json. The next Cost refresh and every reply footer use the new numbers.</p>
                <div class="cost-auto-form">
                    <label>Input / 1M<input type="number" step="0.01" min="0" id="cost-auto-input" value="${this.escape(auto.input)}"></label>
                    <label>Cache write / 1M<input type="number" step="0.01" min="0" id="cost-auto-write" value="${this.escape(auto.cache_write)}"></label>
                    <label>Cached input / 1M<input type="number" step="0.01" min="0" id="cost-auto-read" value="${this.escape(auto.cache_read)}"></label>
                    <label>Output / 1M<input type="number" step="0.01" min="0" id="cost-auto-output" value="${this.escape(auto.output)}"></label>
                    <button type="button" id="cost-auto-save" class="btn btn-primary btn-sm">Save Auto rates</button>
                </div>
            </section>
            <section class="settings-card">
                <h3>Model rates</h3>
                <p class="settings-help">Dollars per million tokens, from the Cursor price list. Edit the JSON file on disk to add a model.</p>
                <div class="cost-table-wrap">
                    <table class="cost-table">
                        <thead><tr><th>Model</th><th>Provider</th><th>Input</th><th>Cache write</th><th>Cache read</th><th>Output</th></tr></thead>
                        <tbody>${rows}</tbody>
                    </table>
                </div>
            </section>
        `;
    }

    async saveAutoRates() {
        const numberValue = (id) => Number((document.getElementById(id) || {}).value);
        const auto = {
            input: numberValue('cost-auto-input'),
            cache_write: numberValue('cost-auto-write'),
            cache_read: numberValue('cost-auto-read'),
            output: numberValue('cost-auto-output'),
        };
        if (Object.values(auto).some((value) => !Number.isFinite(value) || value < 0)) {
            if (window.toast) {
                window.toast.error('Auto rates must be numbers at least 0.', { key: 'cost' });
            }
            return;
        }
        const payload = { auto };
        const data = await this.controller.api.updateUsagePricing(payload);
        if (data && data.success) {
            if (window.toast) {
                window.toast.success('Auto rates saved.', { key: 'cost' });
            }
            await this.load();
        } else if (window.toast) {
            window.toast.error((data && (data.error || data.detail)) || 'Could not save rates', { key: 'cost' });
        }
    }

    number(value) {
        const n = Number(value || 0);
        return Number.isFinite(n) ? n.toLocaleString() : '0';
    }

    when(value) {
        if (!value) {
            return '';
        }
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) {
            return String(value);
        }
        return date.toLocaleString();
    }

    escape(value) {
        return String(value == null ? '' : value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }
}
