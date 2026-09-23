// Transient status toasts — bottom-right, 4 seconds by default.

class ToastManager {
    constructor({ defaultDuration = 4000 } = {}) {
        this.defaultDuration = defaultDuration;
        this.items = new Map();
        this.seq = 0;
        this.maxVisible = 4;
        this.container = null;
    }

    ensureContainer() {
        if (this.container && document.body.contains(this.container)) {
            return this.container;
        }
        let el = document.getElementById('toast-region');
        if (!el) {
            el = document.createElement('div');
            el.id = 'toast-region';
            document.body.appendChild(el);
        }
        el.className = 'toast-region';
        el.setAttribute('aria-live', 'polite');
        el.setAttribute('aria-relevant', 'additions text');
        this.container = el;
        return el;
    }

    show(message, options = {}) {
        const text = String(message || '').trim();
        if (!text) {
            return null;
        }

        const type = options.type || (this._looksBusy(text) ? 'info' : 'success');
        const key = options.key || `toast-${++this.seq}`;
        const sticky = options.duration === 0 || (options.duration == null && this._looksBusy(text));
        const duration = sticky
            ? 0
            : (options.duration == null ? this.defaultDuration : options.duration);

        const existing = this.items.get(key);
        if (existing) {
            this._update(existing, text, type, duration);
            return key;
        }

        this._evictIfNeeded();
        const node = this._createNode(key, text, type, duration);
        this.ensureContainer().appendChild(node.el);
        this.items.set(key, node);
        return key;
    }

    success(message, options = {}) {
        return this.show(message, { ...options, type: 'success' });
    }

    error(message, options = {}) {
        return this.show(message, { ...options, type: 'error' });
    }

    info(message, options = {}) {
        return this.show(message, { ...options, type: 'info' });
    }

    dismiss(key) {
        const node = this.items.get(key);
        if (!node) {
            return;
        }
        if (node.timer) {
            window.clearTimeout(node.timer);
        }
        node.el.classList.add('is-leaving');
        const remove = () => {
            if (node.el.parentNode) {
                node.el.parentNode.removeChild(node.el);
            }
            this.items.delete(key);
        };
        if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
            remove();
            return;
        }
        window.setTimeout(remove, 180);
    }

    _looksBusy(text) {
        return /(?:…|\.\.\.)$/.test(text);
    }

    _update(node, text, type, duration) {
        node.el.classList.remove('is-success', 'is-error', 'is-info');
        node.el.classList.add(`is-${type}`);
        node.el.setAttribute('role', type === 'error' ? 'alert' : 'status');
        node.messageEl.textContent = text;
        this._restartTimer(node, duration);
    }

    _createNode(key, text, type, duration) {
        const el = document.createElement('div');
        el.className = `toast is-${type}`;
        el.setAttribute('role', type === 'error' ? 'alert' : 'status');

        const messageEl = document.createElement('p');
        messageEl.className = 'toast-message';
        messageEl.textContent = text;

        const closeBtn = document.createElement('button');
        closeBtn.type = 'button';
        closeBtn.className = 'toast-close';
        closeBtn.setAttribute('aria-label', 'Dismiss notification');
        closeBtn.textContent = '\u00d7';
        closeBtn.addEventListener('click', () => this.dismiss(key));

        const progress = document.createElement('span');
        progress.className = 'toast-progress';
        progress.setAttribute('aria-hidden', 'true');

        el.appendChild(messageEl);
        el.appendChild(closeBtn);
        el.appendChild(progress);

        const node = { el, messageEl, progress, timer: null, key };
        this._restartTimer(node, duration);
        return node;
    }

    _restartTimer(node, duration) {
        if (node.timer) {
            window.clearTimeout(node.timer);
            node.timer = null;
        }
        node.progress.classList.remove('is-running');
        node.progress.style.animationDuration = '';
        if (!duration) {
            node.progress.style.display = 'none';
            return;
        }
        node.progress.style.display = '';
        node.progress.style.animationDuration = `${duration}ms`;
        void node.progress.offsetWidth;
        node.progress.classList.add('is-running');
        node.timer = window.setTimeout(() => this.dismiss(node.key), duration);
    }

    _evictIfNeeded() {
        if (this.items.size < this.maxVisible) {
            return;
        }
        const oldest = this.items.keys().next().value;
        this.dismiss(oldest);
    }
}

window.toast = new ToastManager();
