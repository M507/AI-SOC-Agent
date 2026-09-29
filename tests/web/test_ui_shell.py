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
    assert 'id="session-alert-select"' in html
    assert "None" in html.split('id="session-alert-select"', 1)[1].split("</select>", 1)[0]


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


def test_requests_view_is_in_the_shell():
    html = INDEX.read_text(encoding="utf-8")
    app_js = APP_JS.read_text(encoding="utf-8")
    assert 'id="nav-requests"' in html
    assert 'id="requests-content"' in html
    assert "requests.js" in html
    assert "requests.css" in html
    assert "setActiveSection('requests')" in app_js
    assert "RequestsManager" in app_js


def test_cost_view_is_in_the_shell():
    html = INDEX.read_text(encoding="utf-8")
    app_js = APP_JS.read_text(encoding="utf-8")
    cost_js = (WEB / "static" / "cost.js").read_text(encoding="utf-8")
    assert 'id="nav-cost"' in html
    assert 'id="cost-content"' in html
    assert 'data-cost-page="overview"' in html
    assert 'data-cost-page="sessions"' in html
    assert 'data-cost-page="models"' in html
    assert 'data-cost-page="calls"' in html
    assert 'data-cost-page="rates"' in html
    assert "cost.js" in html
    assert "cost.css" in html
    assert "setActiveSection('cost')" in app_js
    assert "CostManager" in app_js
    assert "class CostManager" in cost_js
    assert "/api/usage" in (WEB / "static" / "api.js").read_text(encoding="utf-8")


def test_session_tab_bar_is_separate_from_section_tabs():
    html = INDEX.read_text(encoding="utf-8")
    sessions_js = (WEB / "static" / "sessions.js").read_text(encoding="utf-8")
    session_css = (WEB / "static" / "css" / "session_tabs.css").read_text(encoding="utf-8")
    server = (WEB / "server.py").read_text(encoding="utf-8")
    api = (WEB / "static" / "api.js").read_text(encoding="utf-8")
    assert 'class="session-tab-bar"' in html
    assert 'id="session-tab-new"' in html
    assert 'id="session-tab-overflow"' in html
    assert 'id="sessions-tabs"' in html
    assert 'id="autoruns-tabs"' in html
    assert 'id="autoruns-tab-group"' in html
    assert 'class="session-tab-bar" id="autoruns-tab-group"' in html
    autoruns_js = (WEB / "static" / "autoruns.js").read_text(encoding="utf-8")
    assert "samigpt.autorunTabs" in autoruns_js
    assert "session-tab" in autoruns_js
    assert 'data-cost-page="overview"' in html
    assert "samigpt.sessionTabs" in sessions_js
    assert "recentlyClosed" in sessions_js
    assert "auxclick" in sessions_js
    assert "Close others" in sessions_js
    assert "deleteSession" not in sessions_js
    assert "method: 'PATCH'" in api
    assert '@app.patch("/api/sessions/{session_id}")' in server
    assert "rename_session" in server
    hex_color = __import__("re").compile(r"#[0-9a-fA-F]{3,8}\b")
    assert not hex_color.search(session_css)


def test_new_session_modal_seeds_selected_alert_uuid_into_prompt():
    modals = (WEB / "static" / "modals.js").read_text(encoding="utf-8")
    api = (WEB / "static" / "api.js").read_text(encoding="utf-8")
    html = INDEX.read_text(encoding="utf-8")
    assert "session-alert-select" in modals
    assert "loadSessionAlertOptions" in modals
    assert "seedCommandInputWithAlert" in modals
    assert "investigate this alert _id:" in modals
    assert "Enter a session name." not in modals
    assert "Session Name (optional)" in html
    assert "getRecentAlerts" in api
    assert "/api/elastic/recent-alerts" in api


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


def test_netbox_settings_page_is_wired():
    html = INDEX.read_text(encoding="utf-8")
    app_js = APP_JS.read_text(encoding="utf-8")
    integrations = (WEB / "static" / "integrations_settings.js").read_text(encoding="utf-8")

    assert 'data-settings-page="netbox"' in html
    assert 'data-settings-page-content="netbox"' in html
    assert 'id="netbox-url"' in html
    assert "netbox_settings.js" in html
    assert "NetBoxSettingsManager" in app_js
    assert "netboxSettings.load()" in app_js
    assert "Asset inventory" in integrations


def test_appearance_theme_system_is_wired():
    html = INDEX.read_text(encoding="utf-8")
    login = (WEB / "templates" / "login.html").read_text(encoding="utf-8")
    tokens = (WEB / "static" / "css" / "tokens.css").read_text(encoding="utf-8")
    theme_js = (WEB / "static" / "theme.js").read_text(encoding="utf-8")
    css_dir = WEB / "static" / "css"

    assert 'data-settings-page="appearance"' in html
    assert 'data-settings-page-content="appearance"' in html
    assert "/static/css/tokens.css" in html
    assert "/static/theme.js" in html
    assert "FT-Theme" in html
    assert "U-Theme" in html
    assert "B-Theme" in html
    assert "Match system" in html
    assert 'id="appearance-theme-ft"' in html
    assert 'id="appearance-theme-u"' in html
    assert 'id="appearance-theme-b"' in html
    assert 'id="appearance-theme-system"' in html
    assert 'class="sidebar-title">Work</span>' in html
    assert 'class="sidebar-title">Insight</span>' in html
    assert 'class="sidebar-title">System</span>' in html
    assert 'class="tab-subgroup-label">AI</span>' in html
    assert 'class="tab-subgroup-label">Connections</span>' in html
    assert 'class="tab-subgroup-label">Preferences</span>' in html
    assert 'id="nav-sessions"' in html
    assert 'id="nav-mcp"' in html

    assert 'html[data-theme="u"]' in tokens
    assert 'html[data-theme="ft"]' in tokens
    assert 'html[data-theme="b"]' in tokens
    assert "samigpt.appearance" in theme_js
    assert "prefers-color-scheme" in theme_js
    assert "samigpt.appearance" in html
    assert "/static/css/tokens.css" in login
    assert "/static/theme.js" in login
    assert "samigpt.appearance" in login

    hex_color = __import__("re").compile(r"#[0-9a-fA-F]{3,8}\b")
    for path in css_dir.glob("*.css"):
        if path.name == "tokens.css":
            continue
        text = path.read_text(encoding="utf-8")
        assert not hex_color.search(text), path.name

