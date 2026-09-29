const LIBRARY_FOLDER_LABELS = { soc1: 'SOC1', soc2: 'SOC2', soc3: 'SOC3' };

function libraryFolderLabel(name) {
    if (LIBRARY_FOLDER_LABELS[name]) return LIBRARY_FOLDER_LABELS[name];
    return String(name || '').replace(/_/g, ' ');
}

function mountLinkTree(host, leaves, options) {
    const settings = options || {};
    host.replaceChildren();
    if (!leaves.length) {
        const note = document.createElement('p');
        note.className = 'page-status';
        note.textContent = settings.emptyText || 'Nothing matches this search.';
        host.append(note);
        return;
    }
    const root = { dirs: new Map(), leaves: [] };
    leaves.forEach((leaf) => {
        let node = root;
        (leaf.segments || []).forEach((segment) => {
            const key = segment && typeof segment === 'object' ? segment.id : String(segment);
            const label = segment && typeof segment === 'object' ? segment.label : String(segment);
            if (!node.dirs.has(key)) {
                node.dirs.set(key, { name: label, dirs: new Map(), leaves: [] });
            }
            node = node.dirs.get(key);
        });
        node.leaves.push(leaf);
    });
    const tree = document.createElement('ul');
    tree.className = 'library-tree';
    tree.setAttribute('role', 'tree');
    appendLinkTree(tree, root, settings.sortFolders !== false);
    host.append(tree);
}

function appendLinkTree(list, node, sortFolders) {
    node.leaves.forEach((leaf) => {
        const item = document.createElement('li');
        item.className = 'library-tree-leaf';
        item.setAttribute('role', 'none');
        const button = document.createElement('button');
        button.type = 'button';
        button.className = leaf.className || 'library-file';
        if (leaf.meta) {
            const title = document.createElement('span');
            title.textContent = leaf.label;
            const when = document.createElement('time');
            when.className = 'report-time';
            when.dateTime = leaf.when || '';
            when.textContent = leaf.meta;
            button.append(title, when);
        } else {
            button.textContent = leaf.label;
        }
        Object.entries(leaf.dataset || {}).forEach(([key, value]) => {
            button.dataset[key] = value;
        });
        if (leaf.active) {
            button.classList.add('active');
            button.setAttribute('aria-current', 'page');
        }
        button.addEventListener('click', leaf.onSelect);
        item.append(button);
        list.append(item);
    });
    const folders = [...node.dirs.values()];
    if (sortFolders) folders.sort((a, b) => a.name.localeCompare(b.name));
    folders.forEach((folder) => {
        const item = document.createElement('li');
        item.className = 'library-tree-branch';
        item.setAttribute('role', 'treeitem');
        item.setAttribute('aria-expanded', 'true');
        const toggle = document.createElement('button');
        toggle.type = 'button';
        toggle.className = 'library-tree-folder';
        toggle.textContent = libraryFolderLabel(folder.name);
        const nested = document.createElement('ul');
        nested.className = 'library-tree';
        nested.setAttribute('role', 'group');
        toggle.addEventListener('click', () => {
            const open = item.getAttribute('aria-expanded') === 'true';
            item.setAttribute('aria-expanded', open ? 'false' : 'true');
        });
        appendLinkTree(nested, folder, sortFolders);
        item.append(toggle, nested);
        list.append(item);
    });
}

class LibraryManager {
    constructor(controller) {
        this.controller = controller;
        this.collection = 'runbooks';
        this.selected = null;
        this.files = [];
        this.groups = [];
        this.bound = false;
    }

    bind() {
        if (this.bound) return;
        this.bound = true;
        const search = document.getElementById('library-search');
        if (search) search.addEventListener('input', () => this.renderList());
    }

    searchable() {
        return this.collection === 'runbooks' || this.collection === 'standards';
    }

    query() {
        const search = document.getElementById('library-search');
        return ((search && search.value) || '').trim().toLowerCase();
    }

    syncSearch() {
        const search = document.getElementById('library-search');
        if (!search) return;
        const on = this.searchable();
        search.hidden = !on;
        if (!on) search.value = '';
        const label = this.collection === 'standards' ? 'Search standards' : 'Search runbooks';
        search.placeholder = label;
        search.setAttribute('aria-label', label);
    }

    visibleFiles() {
        const query = this.query();
        if (!query || !this.searchable()) return this.files;
        return this.files.filter((file) => {
            const haystack = [file.title, file.path].join(' ').toLowerCase();
            return haystack.includes(query);
        });
    }

    async load(collection) {
        this.bind();
        const changed = collection && collection !== this.collection;
        this.collection = collection || this.collection;
        if (changed) {
            const search = document.getElementById('library-search');
            if (search) search.value = '';
            this.selected = null;
        }
        const titles = { runbooks: 'Runbooks', standards: 'Standards', documentation: 'Documentation' };
        const heading = document.getElementById('library-title');
        if (heading) heading.textContent = titles[this.collection] || 'Library';
        this.syncSearch();
        const data = await this.controller.api.listLibrary(this.collection);
        const list = document.getElementById('library-list');
        const doc = document.getElementById('library-doc');
        if (!list || !doc) return;
        const groups = (data && data.groups) || [];
        this.groups = groups;
        this.files = groups.flatMap((group) => group.files || []);
        doc.replaceChildren();
        if (!this.files.length) {
            list.replaceChildren();
            doc.textContent = 'No documents in this library.';
            return;
        }
        this.renderList();
        const visible = this.visibleFiles();
        const still = visible.find((file) => file.path === this.selected);
        await this.open((still || visible[0] || {}).path);
    }

    renderList() {
        const list = document.getElementById('library-list');
        if (!list) return;
        const visible = this.visibleFiles();
        if (!this.searchable()) {
            this.renderGroups(list);
            return;
        }
        mountLinkTree(list, visible.map((file) => {
            const parts = String(file.path || '').split('/');
            parts.pop();
            return {
                segments: parts.filter(Boolean),
                label: file.title || file.path,
                dataset: { path: file.path },
                active: file.path === this.selected,
                onSelect: () => this.open(file.path),
            };
        }));
    }

    renderGroups(list) {
        list.replaceChildren();
        (this.groups || []).forEach((group) => {
            const label = document.createElement('div');
            label.className = 'library-group-label';
            label.textContent = group.label;
            list.append(label);
            (group.files || []).forEach((file) => {
                const button = document.createElement('button');
                button.type = 'button';
                button.className = 'library-file';
                button.dataset.path = file.path;
                button.textContent = file.title || file.path;
                if (file.path === this.selected) button.classList.add('active');
                button.addEventListener('click', () => this.open(file.path));
                list.append(button);
            });
        });
    }

    async open(path) {
        if (!path) return;
        this.selected = path;
        document.querySelectorAll('#library-list .library-file').forEach((button) => {
            const on = button.dataset.path === path;
            button.classList.toggle('active', on);
            if (on) button.setAttribute('aria-current', 'page');
            else button.removeAttribute('aria-current');
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
