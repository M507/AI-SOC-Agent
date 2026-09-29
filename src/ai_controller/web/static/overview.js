class OverviewManager {
    constructor(controller) {
        this.controller = controller;
        this.range = '30d';
        this.svg = 'http://www.w3.org/2000/svg';
        this.bind();
    }

    bind() {
        const bar = document.getElementById('overview-range');
        if (bar && !bar.dataset.bound) {
            bar.dataset.bound = '1';
            bar.addEventListener('click', (event) => {
                const button = event.target.closest('[data-overview-range]');
                if (!button) return;
                this.range = button.dataset.overviewRange;
                this.markRange();
                this.load();
            });
        }
        this.markRange();
        this.bindAction('overview-review', () => this.openQueue('all'));
        this.bindAction('overview-new-session', () => {
            if (this.controller.modals) this.controller.modals.showNewSession();
        });
        this.bindAction('overview-cost', () => this.controller.setActiveSection('cost'));
    }

    bindAction(id, action) {
        const button = document.getElementById(id);
        if (!button || button.dataset.bound) return;
        button.dataset.bound = '1';
        button.addEventListener('click', action);
    }

    markRange() {
        document.querySelectorAll('[data-overview-range]').forEach((button) => {
            const on = button.dataset.overviewRange === this.range;
            button.classList.toggle('btn-primary', on);
            button.classList.toggle('btn-secondary', !on);
            button.setAttribute('aria-pressed', on ? 'true' : 'false');
        });
    }

    async load() {
        const body = document.querySelector('#overview-content .overview-body');
        const status = document.getElementById('overview-status');
        if (body) body.setAttribute('aria-busy', 'true');
        this.setStatus('Loading dashboard…');
        const data = await this.controller.api.getOverview(this.range);
        if (body) body.setAttribute('aria-busy', 'false');
        if (!data || data.success === false) {
            this.showError((data && (data.error || data.detail)) || 'Could not load the dashboard.');
            return;
        }
        this.clearStatus();
        this.render(data);
    }

    setStatus(text) {
        const status = document.getElementById('overview-status');
        if (!status) return;
        status.hidden = false;
        status.replaceChildren();
        status.textContent = text;
    }

    clearStatus() {
        const status = document.getElementById('overview-status');
        if (!status) return;
        status.replaceChildren();
        status.hidden = true;
    }

    showError(message) {
        const status = document.getElementById('overview-status');
        if (!status) return;
        status.hidden = false;
        status.replaceChildren();
        const text = document.createElement('p');
        text.className = 'overview-error';
        text.textContent = message;
        const retry = document.createElement('button');
        retry.type = 'button';
        retry.className = 'btn btn-secondary btn-sm';
        retry.textContent = 'Retry';
        retry.addEventListener('click', () => this.load());
        status.append(text, retry);
    }

    render(data) {
        const attention = data.attention || {};
        const open = Number(attention.pending || 0)
            + Number(attention.awaiting || 0)
            + Number(attention.informational || 0);
        const review = document.getElementById('overview-review');
        if (review) {
            review.classList.toggle('btn-primary', open > 0);
            review.classList.toggle('btn-secondary', open === 0);
        }
        this.renderAttention(attention);
        this.renderActivity(data);
        this.renderDonut(
            'overview-decisions',
            data.decisions || [],
            {
                false_positive: 'high',
                benign_true_positive: 'success',
                escalations: 'danger',
            }
        );
        this.renderBars('overview-outcomes', data.outcomes || [], {
            executed: 'success',
            denied: 'muted',
            failed: 'danger',
            acknowledged: 'info',
        });
        this.renderBars('overview-detection', data.detection || [], { '*': 'info' }, () => this.openQueue('detection'));
        this.renderBars('overview-response', data.response || [], { '*': 'accent' }, () => this.openQueue('soc'));
        this.renderSpend(data);
        this.renderRecent(data.recent || []);
    }

    renderAttention(attention) {
        const parts = [
            { id: 'pending', label: 'Pending', count: Number(attention.pending || 0), tone: 'accent' },
            { id: 'awaiting', label: 'Waiting on integration', count: Number(attention.awaiting || 0), tone: 'warning' },
            { id: 'informational', label: 'Review notes', count: Number(attention.informational || 0), tone: 'info' },
        ];
        const host = document.getElementById('overview-waiting');
        if (!host) return;
        host.replaceChildren();
        const total = parts.reduce((sum, part) => sum + part.count, 0);
        if (!total) {
            host.append(this.emptyNote('Nothing waiting.'));
            return;
        }
        host.append(this.stackSvg(parts, this.summary(parts)));
        host.append(this.legend(parts));
    }

    renderActivity(data) {
        const host = document.getElementById('overview-activity');
        if (!host) return;
        host.replaceChildren();
        const note = document.createElement('p');
        note.className = 'overview-chart-note';
        const unit = data.series_unit === 'week' ? 'By week' : 'By day';
        note.textContent = data.series_capped ? `${unit}. ${this.capNote(data)}` : unit;
        host.append(note);
        const plot = document.createElement('div');
        host.append(plot);
        this.columnChart(plot, data.activity || [], [
            { key: 'filed', label: 'Filed', tone: 'info' },
            { key: 'settled', label: 'Settled', tone: 'success' },
        ], data.series_unit);
    }

    renderSpend(data) {
        const host = document.getElementById('overview-work');
        if (!host) return;
        host.replaceChildren();
        const caption = document.createElement('p');
        caption.className = 'overview-chart-note';
        const spend = (data.work || []).find((item) => item.id === 'spend');
        const bits = [spend && spend.value ? spend.value : '—'];
        if (data.spend_unpriced) bits.push('Some calls are unpriced and are not on this chart.');
        if (data.series_capped) bits.push(this.capNote(data));
        caption.textContent = bits.join(' ');
        const link = document.createElement('button');
        link.type = 'button';
        link.className = 'chart-inline-link';
        link.textContent = 'Open cost';
        link.addEventListener('click', () => this.controller.setActiveSection('cost'));
        caption.append(link);
        host.append(caption);
        const plot = document.createElement('div');
        host.append(plot);
        this.columnChart(
            plot,
            data.spend_series || [],
            [{ key: 'cost_usd', label: 'Spend', tone: 'accent', format: 'cost' }],
            data.series_unit,
            data.spend_unpriced ? 'No priced calls in this range.' : 'None in this range.'
        );
        const links = document.createElement('div');
        links.className = 'overview-links';
        (data.work || []).filter((item) => item.go && item.id !== 'spend').forEach((item) => {
            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'btn btn-secondary btn-sm';
            button.textContent = `${item.label} ${item.count}`;
            button.addEventListener('click', () => this.controller.setActiveSection(item.go));
            links.append(button);
        });
        host.append(links);
    }

    renderDonut(id, rows, tones) {
        const host = document.getElementById(id);
        if (!host) return;
        host.replaceChildren();
        const parts = rows.map((row) => ({
            id: row.id,
            label: row.label,
            count: Number(row.count || 0),
            tone: tones[row.id] || 'muted',
        }));
        const total = parts.reduce((sum, part) => sum + part.count, 0);
        if (!total) {
            host.append(this.emptyNote('None in this range.'));
            return;
        }
        const wrap = document.createElement('div');
        wrap.className = 'chart-donut-wrap';
        const svg = this.el('svg');
        svg.setAttribute('class', 'chart-donut');
        svg.setAttribute('viewBox', '0 0 112 112');
        svg.setAttribute('role', 'img');
        svg.setAttribute('aria-label', this.summary(parts));
        const group = this.el('g');
        group.setAttribute('transform', 'rotate(-90 56 56)');
        const radius = 36;
        const circ = 2 * Math.PI * radius;
        let offset = 0;
        const drawn = parts.filter((part) => part.count > 0);
        drawn.forEach((part) => {
            const len = drawn.length === 1 ? circ : (part.count / total) * circ;
            const arc = this.el('circle');
            arc.setAttribute('class', `chart-arc tone-${part.tone}`);
            arc.setAttribute('cx', '56');
            arc.setAttribute('cy', '56');
            arc.setAttribute('r', String(radius));
            arc.setAttribute('stroke-width', '14');
            if (drawn.length > 1) {
                arc.setAttribute('stroke-dasharray', `${len} ${circ - len}`);
                arc.setAttribute('stroke-dashoffset', String(-offset));
            }
            const title = this.el('title');
            title.textContent = `${part.label}: ${part.count}`;
            arc.append(title);
            group.append(arc);
            offset += len;
        });
        const totalText = this.el('text');
        totalText.setAttribute('class', 'chart-donut-total');
        totalText.setAttribute('x', '56');
        totalText.setAttribute('y', '60');
        totalText.setAttribute('text-anchor', 'middle');
        totalText.textContent = String(total);
        svg.append(group, totalText);
        wrap.append(svg, this.legend(parts));
        host.append(wrap);
    }

    renderBars(id, rows, tones, onPick) {
        const host = document.getElementById(id);
        if (!host) return;
        host.replaceChildren();
        const parts = (rows || []).map((row) => ({
            id: row.id,
            label: row.label,
            count: Number(row.count || 0),
            tone: tones[row.id] || tones['*'] || 'muted',
        }));
        if (!parts.length || parts.every((part) => !part.count)) {
            host.append(this.emptyNote('None in this range.'));
            return;
        }
        const max = Math.max(...parts.map((part) => part.count), 1);
        const list = document.createElement('div');
        list.className = 'chart-hbars';
        parts.forEach((part) => {
            const row = onPick ? document.createElement('button') : document.createElement('div');
            row.className = 'chart-hbar';
            if (onPick) {
                row.type = 'button';
                row.addEventListener('click', () => onPick(part));
            }
            const name = document.createElement('span');
            name.className = 'chart-hbar-name';
            name.textContent = part.label;
            const value = document.createElement('span');
            value.className = 'chart-hbar-value';
            value.textContent = String(part.count);
            row.append(name, this.barSvg(part, max), value);
            row.setAttribute('aria-label', `${part.label}: ${part.count}`);
            list.append(row);
        });
        host.append(list);
    }

    columnChart(host, points, series, unit, emptyText) {
        host.replaceChildren();
        const rows = points || [];
        const flat = series.every((item) => rows.every((point) => !Number(point[item.key])));
        if (!rows.length || flat) {
            host.append(this.emptyNote(emptyText || 'None in this range.'));
            return;
        }
        const max = Math.max(
            1,
            ...rows.map((point) => Math.max(...series.map((item) => Number(point[item.key]) || 0)))
        );
        const svg = this.el('svg');
        svg.setAttribute('class', 'chart-columns');
        svg.setAttribute('role', 'img');
        svg.setAttribute('viewBox', `0 0 ${rows.length * 12} 100`);
        svg.setAttribute('preserveAspectRatio', 'none');
        const legendRows = series.map((item) => ({
            label: item.label,
            tone: item.tone,
            count: rows.reduce((sum, point) => sum + (Number(point[item.key]) || 0), 0),
            format: item.format,
        }));
        svg.setAttribute('aria-label', this.summary(legendRows));
        rows.forEach((point, index) => {
            series.forEach((item, seriesIndex) => {
                const value = Number(point[item.key]) || 0;
                const barH = (value / max) * 100;
                const width = series.length === 1 ? 7 : 4;
                const x = index * 12 + (series.length === 1 ? 2.5 : (seriesIndex === 0 ? 1.5 : 6.5));
                const rect = this.el('rect');
                rect.setAttribute('class', `chart-bar tone-${item.tone}`);
                rect.setAttribute('x', String(x));
                rect.setAttribute('y', String(100 - barH));
                rect.setAttribute('width', String(width));
                rect.setAttribute('height', String(Math.max(barH, 0)));
                const title = this.el('title');
                title.textContent = `${point.bucket}: ${item.label} ${this.formatValue(value, item.format)}`;
                rect.append(title);
                svg.append(rect);
            });
        });
        host.append(svg, this.xLabels(rows, unit), this.legend(legendRows));
    }

    stackSvg(parts, label) {
        const svg = this.el('svg');
        svg.setAttribute('class', 'chart-stack');
        svg.setAttribute('viewBox', '0 0 100 8');
        svg.setAttribute('preserveAspectRatio', 'none');
        svg.setAttribute('role', 'img');
        svg.setAttribute('aria-label', label);
        const total = parts.reduce((sum, part) => sum + part.count, 0) || 1;
        let x = 0;
        parts.forEach((part) => {
            if (!part.count) return;
            const width = (part.count / total) * 100;
            const rect = this.el('rect');
            rect.setAttribute('class', `chart-seg tone-${part.tone}`);
            rect.setAttribute('x', String(x));
            rect.setAttribute('y', '0');
            rect.setAttribute('width', String(width));
            rect.setAttribute('height', '8');
            const title = this.el('title');
            title.textContent = `${part.label}: ${part.count}`;
            rect.append(title);
            svg.append(rect);
            x += width;
        });
        return svg;
    }

    barSvg(part, max) {
        const svg = this.el('svg');
        svg.setAttribute('viewBox', '0 0 100 8');
        svg.setAttribute('preserveAspectRatio', 'none');
        svg.setAttribute('aria-hidden', 'true');
        const track = this.el('rect');
        track.setAttribute('class', 'chart-track');
        track.setAttribute('width', '100');
        track.setAttribute('height', '8');
        const fill = this.el('rect');
        fill.setAttribute('class', `chart-seg tone-${part.tone}`);
        fill.setAttribute('width', String((part.count / max) * 100));
        fill.setAttribute('height', '8');
        svg.append(track, fill);
        return svg;
    }

    xLabels(points, unit) {
        const row = document.createElement('div');
        row.className = 'chart-xlabels';
        const step = points.length > 12 ? Math.ceil(points.length / 6) : 1;
        points.forEach((point, index) => {
            const cell = document.createElement('span');
            const show = index % step === 0 || index === points.length - 1;
            if (show) cell.textContent = this.shortDate(point.bucket, unit);
            row.append(cell);
        });
        return row;
    }

    legend(parts) {
        const list = document.createElement('ul');
        list.className = 'chart-legend';
        parts.forEach((part) => {
            const item = document.createElement('li');
            const swatch = document.createElement('span');
            swatch.className = `chart-swatch tone-${part.tone}`;
            swatch.setAttribute('aria-hidden', 'true');
            item.append(swatch, document.createTextNode(`${part.label} ${this.formatValue(part.count, part.format)}`));
            list.append(item);
        });
        return list;
    }

    renderRecent(rows) {
        const host = document.getElementById('overview-recent');
        if (!host) return;
        host.replaceChildren();
        if (!rows.length) {
            host.append(this.emptyNote('None in this range.'));
            return;
        }
        const statusLabel = {
            executed: 'Done',
            denied: 'Denied',
            failed: 'Failed',
            acknowledged: 'Reviewed',
        };
        rows.forEach((row) => {
            const line = document.createElement('button');
            line.type = 'button';
            line.className = 'overview-recent-row';
            line.addEventListener('click', () => this.openRequest(row.id));
            const title = document.createElement('span');
            title.className = 'overview-recent-title';
            title.textContent = row.title || row.label || 'Request';
            const kind = document.createElement('span');
            kind.className = 'overview-recent-meta overview-recent-kind';
            kind.textContent = row.label || '';
            const status = document.createElement('span');
            status.className = `status-badge ${row.status || ''}`;
            status.textContent = statusLabel[row.status] || row.status || '';
            const when = document.createElement('time');
            when.className = 'overview-recent-meta';
            when.dateTime = row.at || '';
            when.textContent = this.formatWhen(row.at);
            when.title = row.at ? row.at.replace('T', ' ') : '';
            line.append(title, kind, status, when);
            host.append(line);
        });
    }

    openQueue(queue) {
        const requests = this.controller.requestsManager;
        if (requests) {
            requests.filter = 'open';
            requests.queueTab = queue || 'all';
            requests.selectedId = null;
            requests.selectedIds = new Set();
            requests.receipt = null;
        }
        this.controller.setActiveSection('requests');
    }

    openRequest(id) {
        const requests = this.controller.requestsManager;
        if (requests) {
            requests.filter = 'all';
            requests.queueTab = 'all';
            requests.selectedId = id;
            requests.selectedIds = new Set();
            requests.receipt = null;
        }
        this.controller.setActiveSection('requests');
    }

    emptyNote(text) {
        const note = document.createElement('p');
        note.className = 'overview-empty';
        note.textContent = text;
        return note;
    }

    summary(parts) {
        return parts.map((part) => `${part.label} ${this.formatValue(part.count, part.format)}`).join(', ');
    }

    capNote(data) {
        const unit = data.series_unit === 'week' ? 'weeks' : 'days';
        return `Showing the latest 30 ${unit}.`;
    }

    shortDate(bucket, unit) {
        if (!bucket) return '';
        const parts = String(bucket).split('-');
        if (parts.length < 3) return bucket;
        const label = `${parts[1]}/${parts[2]}`;
        return unit === 'week' ? label : label;
    }

    formatWhen(iso) {
        if (!iso) return '';
        const date = new Date(iso);
        if (Number.isNaN(date.getTime())) return String(iso).replace('T', ' ');
        return date.toLocaleString(undefined, {
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
        });
    }

    formatValue(value, format) {
        const number = Number(value) || 0;
        if (format !== 'cost') return String(Math.round(number));
        if (number === 0) return '$0.00';
        if (number < 1) return `$${number.toFixed(4)}`;
        return `$${number.toFixed(2)}`;
    }

    el(name) {
        return document.createElementNS(this.svg, name);
    }
}
