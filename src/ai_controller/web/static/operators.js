const WEAK_PASSWORDS = new Set(['', 'changeme', 'admin', 'password', 'secret']);

class OperatorsManager {
    constructor(controller) {
        this.controller = controller;
        this.username = '';
        this.bound = false;
    }

    bind() {
        if (this.bound) return;
        this.bound = true;
        const form = document.getElementById('operator-form');
        if (!form) return;
        form.addEventListener('input', () => this.syncSave());
        form.addEventListener('submit', (event) => {
            event.preventDefault();
            this.save();
        });
    }

    async load() {
        this.bind();
        const body = document.getElementById('operators-body');
        if (body) body.setAttribute('aria-busy', 'true');
        this.setStatus('Loading operator…');
        const data = await this.controller.api.getOperator();
        if (body) body.setAttribute('aria-busy', 'false');
        if (!data || data.success === false) {
            this.fail((data && (data.error || data.detail)) || 'Could not load the operator.');
            return;
        }
        this.username = data.username || '';
        this.clearStatus();
        this.clearErrors();
        this.showIdentity();
        const username = document.getElementById('operator-username');
        if (username) username.value = this.username;
        ['operator-current', 'operator-new', 'operator-confirm'].forEach((id) => {
            const input = document.getElementById(id);
            if (input) input.value = '';
        });
        this.renderGroups(data.groups || []);
        this.syncSave();
    }

    showIdentity(message) {
        const line = document.getElementById('operator-identity');
        if (!line) return;
        line.replaceChildren();
        if (message) {
            line.textContent = message;
            return;
        }
        line.append(document.createTextNode('Signed in as '));
        const name = document.createElement('strong');
        name.textContent = this.username || '—';
        line.append(name, document.createTextNode('.'));
    }

    renderGroups(groups) {
        const host = document.getElementById('operator-groups');
        if (!host) return;
        host.replaceChildren();
        const intro = document.createElement('p');
        intro.className = 'page-caption';
        intro.textContent = 'This account can approve every action below.';
        host.append(intro);
        groups.forEach((group) => {
            const section = document.createElement('section');
            section.className = 'operator-group';
            const heading = document.createElement('h4');
            heading.textContent = group.label || '';
            section.append(heading);
            if (group.note) {
                const note = document.createElement('p');
                note.className = 'page-note';
                note.textContent = group.note;
                section.append(note);
            }
            (group.actions || []).forEach((action) => {
                const row = document.createElement('div');
                row.className = 'operator-action';
                const title = document.createElement('strong');
                title.textContent = action.label || '';
                const risk = document.createElement('span');
                risk.className = 'operator-risk';
                risk.textContent = action.risk || '';
                const description = document.createElement('p');
                description.textContent = action.description || '';
                row.append(title, risk, description);
                section.append(row);
            });
            host.append(section);
        });
    }

    syncSave() {
        const save = document.getElementById('operator-save');
        if (!save) return;
        const current = this.value('operator-current');
        const username = this.value('operator-username').trim();
        const next = this.value('operator-new');
        const confirm = this.value('operator-confirm');
        const changed = username !== this.username || next.length > 0;
        const mismatch = next.length > 0 && next !== confirm;
        this.setFieldError('operator-confirm-error', mismatch ? 'Confirmation does not match the new password.' : '');
        this.setFieldError(
            'operator-new-error',
            next && WEAK_PASSWORDS.has(next.trim().toLowerCase())
                ? 'Choose a password that is not a well-known default.'
                : '',
        );
        const weak = next && WEAK_PASSWORDS.has(next.trim().toLowerCase());
        save.disabled = !current || !changed || mismatch || weak || !username;
    }

    async save() {
        this.clearErrors();
        const current = this.value('operator-current');
        const username = this.value('operator-username').trim();
        const next = this.value('operator-new');
        const confirm = this.value('operator-confirm');
        const save = document.getElementById('operator-save');
        if (save) save.disabled = true;
        const data = await this.controller.api.updateOperator({
            current_password: current,
            username,
            new_password: next,
            confirm_password: confirm,
        });
        if (!data || data.success === false) {
            const errors = (data && data.errors) || {};
            if (data && data.detail && !data.errors) {
                this.fail(typeof data.detail === 'string' ? data.detail : 'Could not save the operator.');
            }
            this.setFieldError('operator-current-error', errors.current_password || '');
            this.setFieldError('operator-username-error', errors.username || '');
            this.setFieldError('operator-new-error', errors.new_password || '');
            this.setFieldError('operator-confirm-error', errors.confirm_password || '');
            if (!Object.keys(errors).length && data && data.error) this.fail(data.error);
            this.syncSave();
            return;
        }
        this.username = data.username || username;
        ['operator-current', 'operator-new', 'operator-confirm'].forEach((id) => {
            const input = document.getElementById(id);
            if (input) input.value = '';
        });
        const nameInput = document.getElementById('operator-username');
        if (nameInput) nameInput.value = this.username;
        this.showIdentity(`Signed in as ${this.username}. Use it the next time you sign in.`);
        this.syncSave();
    }

    value(id) {
        const input = document.getElementById(id);
        return input ? input.value : '';
    }

    setFieldError(id, message) {
        const node = document.getElementById(id);
        if (!node) return;
        node.textContent = message || '';
        node.hidden = !message;
        const inputId = {
            'operator-current-error': 'operator-current',
            'operator-username-error': 'operator-username',
            'operator-new-error': 'operator-new',
            'operator-confirm-error': 'operator-confirm',
        }[id];
        const input = inputId ? document.getElementById(inputId) : null;
        if (input) {
            if (message) input.setAttribute('aria-invalid', 'true');
            else input.removeAttribute('aria-invalid');
        }
    }

    clearErrors() {
        ['operator-current-error', 'operator-username-error', 'operator-new-error', 'operator-confirm-error'].forEach((id) => {
            this.setFieldError(id, '');
        });
        const status = document.getElementById('operators-status');
        if (status) {
            status.textContent = '';
            status.hidden = true;
            status.classList.remove('is-error');
        }
    }

    setStatus(text) {
        const status = document.getElementById('operators-status');
        if (!status) return;
        status.hidden = false;
        status.classList.remove('is-error');
        status.textContent = text;
    }

    clearStatus() {
        const status = document.getElementById('operators-status');
        if (!status) return;
        status.textContent = '';
        status.hidden = true;
    }

    fail(message) {
        const body = document.getElementById('operators-body');
        if (body) body.setAttribute('aria-busy', 'false');
        const status = document.getElementById('operators-status');
        if (!status) return;
        status.hidden = false;
        status.classList.add('is-error');
        status.textContent = message;
    }
}
