"""Static UI shell: toasts replace inline status; autorun panel is not force-shown."""

from pathlib import Path

WEB = Path(__file__).resolve().parents[2] / "src" / "ai_controller" / "web"
INDEX = WEB / "templates" / "index.html"
TOAST_JS = WEB / "static" / "toast.js"
TOAST_CSS = WEB / "static" / "css" / "toast.css"
AUTORUN_CSS = WEB / "static" / "css" / "autorun.css"
APP_JS = WEB / "static" / "app.js"


def test_index_uses_toast_region_instead_of_inline_llm_status():
    html = INDEX.read_text(encoding="utf-8")
    assert 'id="toast-region"' in html
    assert 'id="llm-status"' not in html
    assert "/static/toast.js" in html
    assert "/static/css/toast.css" in html
    assert "empty-new-session-btn" in html
    assert "empty-new-autorun-btn" in html


def test_toast_assets_exist_and_default_to_four_seconds():
    js = TOAST_JS.read_text(encoding="utf-8")
    css = TOAST_CSS.read_text(encoding="utf-8")
    assert "defaultDuration = 4000" in js
    assert "class ToastManager" in js
    assert ".toast-region" in css
    assert "bottom: 20px" in css
    assert "right: 20px" in css


def test_autorun_panel_is_not_forced_visible():
    css = AUTORUN_CSS.read_text(encoding="utf-8")
    block = css.split(".autorun-content {", 1)[1].split("}", 1)[0]
    assert "flex !important" not in block
    assert ".autorun-content.is-open" in css
    html = INDEX.read_text(encoding="utf-8")
    opening_tag = html.split('id="autorun-content"', 1)[1].split(">", 1)[0]
    assert "hidden" in opening_tag


def test_mcp_readiness_banner_is_actionable_and_accessible():
    html = INDEX.read_text(encoding="utf-8")
    app_js = APP_JS.read_text(encoding="utf-8")

    assert 'id="mcp-readiness-banner"' in html
    assert 'role="alert"' in html
    assert 'aria-live="assertive"' in html
    assert 'id="mcp-readiness-action"' in html
    assert "refreshMCPReadiness({ notify: true })" in app_js
    assert "openMCPReadinessAction()" in app_js
    assert "openwebui-mcp-card" in app_js
