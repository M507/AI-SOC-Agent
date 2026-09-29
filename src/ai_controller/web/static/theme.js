const Appearance = (() => {
    const STORAGE_KEY = 'samigpt.appearance';
    const MODES = ['system', 'ft', 'u', 'b'];
    const DEFAULT_MODE = 'u';

    function readMode() {
        try {
            const stored = JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}');
            if (stored && MODES.includes(stored.mode)) {
                return stored.mode;
            }
        } catch (err) {
            /* keep default */
        }
        return DEFAULT_MODE;
    }

    function resolveTheme(mode) {
        if (mode === 'system') {
            return window.matchMedia('(prefers-color-scheme: light)').matches ? 'b' : 'u';
        }
        return mode === 'ft' || mode === 'b' ? mode : 'u';
    }

    function apply(mode) {
        const theme = resolveTheme(mode);
        document.documentElement.dataset.theme = theme;
        document.documentElement.dataset.appearanceMode = mode;
    }

    function persist(mode) {
        localStorage.setItem(STORAGE_KEY, JSON.stringify({ mode }));
    }

    function syncRadios(mode) {
        document.querySelectorAll('input[name="appearance-theme"]').forEach((input) => {
            input.checked = input.value === mode;
        });
    }

    function setMode(mode) {
        const next = MODES.includes(mode) ? mode : DEFAULT_MODE;
        persist(next);
        apply(next);
        syncRadios(next);
    }

    function bindPicker() {
        const picker = document.querySelector('.theme-picker');
        if (!picker) {
            return;
        }
        picker.addEventListener('change', (event) => {
            const input = event.target.closest('input[name="appearance-theme"]');
            if (!input) {
                return;
            }
            setMode(input.value);
        });
        syncRadios(readMode());
    }

    function watchSystem() {
        const media = window.matchMedia('(prefers-color-scheme: light)');
        const onChange = () => {
            if (readMode() === 'system') {
                apply('system');
            }
        };
        if (typeof media.addEventListener === 'function') {
            media.addEventListener('change', onChange);
        } else if (typeof media.addListener === 'function') {
            media.addListener(onChange);
        }
    }

    function init() {
        apply(readMode());
        watchSystem();
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', bindPicker);
        } else {
            bindPicker();
        }
    }

    init();

    return { setMode, readMode, resolveTheme };
})();
