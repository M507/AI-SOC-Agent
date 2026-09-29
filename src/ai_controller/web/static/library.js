class LibraryManager {
    constructor(controller) {
        this.controller = controller;
        this.collection = 'runbooks';
        this.selected = null;
    }

    async load(collection) {
        this.collection = collection || this.collection;
        const titles = { runbooks: 'Runbooks', standards: 'Standards', documentation: 'Documentation' };
        const heading = document.getElementById('library-title');
        if (heading) heading.textContent = titles[this.collection] || 'Library';
        const data = await this.controller.api.listLibrary(this.collection);
        const list = document.getElementById('library-list');
        const doc = document.getElementById('library-doc');
        if (!list || !doc) return;
        list.replaceChildren();
        doc.replaceChildren();
        const groups = (data && data.groups) || [];
        let first = null;
        groups.forEach((group) => {
            const label = document.createElement('div');
            label.className = 'library-group-label';
            label.textContent = group.label;
            list.append(label);
            (group.files || []).forEach((file) => {
                if (!first) first = file.path;
                const button = document.createElement('button');
                button.type = 'button';
                button.className = 'library-file';
                button.dataset.path = file.path;
                button.textContent = file.title || file.path;
                button.addEventListener('click', () => this.open(file.path));
                list.append(button);
            });
        });
        if (!groups.length) {
            doc.textContent = 'No documents in this library.';
            return;
        }
        await this.open(first);
    }

    async open(path) {
        if (!path) return;
        this.selected = path;
        document.querySelectorAll('#library-list .library-file').forEach((button) => {
            button.classList.toggle('active', button.dataset.path === path);
        });
        const data = await this.controller.api.readLibraryFile(this.collection, path);
        const doc = document.getElementById('library-doc');
        if (!doc) return;
        if (!data || data.success === false) {
            doc.textContent = (data && data.error) || 'Could not open this document.';
            return;
        }
        this.renderMarkdown(data.markdown || '', doc);
    }

    renderMarkdown(text, target) {
        renderSanitizedMarkdown(text, target, 'library-doc markdown-content');
    }
}

function renderSanitizedMarkdown(text, target, className) {
    target.className = className || 'library-doc markdown-content';
    if (typeof marked === 'undefined') {
        target.textContent = text || '';
        return;
    }
    const html = marked.parse(text || '', { gfm: true, breaks: true });
    const parsed = new DOMParser().parseFromString(html, 'text/html');
    parsed.querySelectorAll('script, iframe, object, embed, link, style').forEach((node) => node.remove());
    parsed.body.querySelectorAll('*').forEach((element) => {
        [...element.attributes].forEach((attribute) => {
            const name = attribute.name.toLowerCase();
            const value = (attribute.value || '').trim().toLowerCase();
            if (name.startsWith('on') || value.startsWith('javascript:')) {
                element.removeAttribute(attribute.name);
            }
        });
    });
    target.replaceChildren(...parsed.body.childNodes);
}
