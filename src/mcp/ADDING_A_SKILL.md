# Adding a New MCP Skill (End-to-End)

This is the checklist used when adding skills such as `get_alert_notes`. Follow it so the skill shows up in MCP, the Elastic skill-vector UI, Integrations safe-tests, agent profiles, runbooks, and docs — not only in one Python file.

## Mental model

```
Vendor client  →  tools_* wrapper  →  mcp_server register + dispatch
        ↓
 SIEM_SKILLS / SKILL_GROUPS (skill_vector.py)  →  UI catalog + MSV filter
        ↓
 Agent profile tools[]  +  runbooks/guidelines  +  skills.md / TOOLS.md
        ↓
 Tests (catalog, MCP list, unit, optional UI inventory)
```

The **UI does not hardcode SIEM skill names**. Settings → Elastic → **MCP skills** and Integrations → **Skills** both load from `catalog_payload()` / `skill_inventory()`, which read `SIEM_SKILLS` (and other groups) in `src/core/skill_vector.py`. If the skill is missing from that tuple, it will not appear in the UI.

---

## 1. Implement the capability (backend)

| Layer | Where | What to do |
|---|---|---|
| Protocol / interface | `src/api/<domain>.py` (e.g. `siem.py`) | Add the method signature on the client Protocol / ABC |
| Vendor client | `src/integrations/...` (e.g. `siem/elastic/elastic_client.py`) | Implement the API call; normalize a stable return shape |
| HTTP helpers | e.g. `elastic_http.py` | Only if you need new verbs/headers (`extra_headers`, `patch`, …) |
| LLM tool wrapper | `src/orchestrator/tools_<domain>.py` (e.g. `tools_siem.py`) | Thin function: validate args, call client, return `{success, …}` |

**Conventions**
- Prefer returning plain dicts with `success`, ids, and human-usable fields.
- External failures that are enrichment-only should often be non-fatal when nested inside another skill (see notes on `get_security_alert_by_id`).
- Destructive / irreversible skills may need approval-queue gating (`src/ai_controller/approval_queue/`).

---

## 2. Register the MCP tool

**File:** `src/mcp/mcp_server.py`

1. **Schema** — add `self.tools["your_skill"] = { "name", "description", "inputSchema" }` next to sibling tools.
2. **Dispatch** — in the tool-call handler, add `elif tool_name == "your_skill" …` and call `tools_<domain>.your_skill(...)`.

Without both, the tool either never lists or always 404s at call time.

---

## 3. Skill vector / UI catalog (required for UI)

**File:** `src/core/skill_vector.py`

1. Add the skill id to the correct tuple (`SIEM_SKILLS`, `CASE_SKILLS`, `NETBOX_SKILLS`, or a group’s inline `skills`).
2. Optionally add a friendly label in `_LABEL_OVERRIDES` (otherwise `human_skill_label` title-cases the snake_case name).
3. Confirm the skill lands in `SKILL_GROUPS` → `SKILL_TO_SOLUTIONS` / `KNOWN_SKILLS` (built automatically from groups).

**UI surfaces this unlocks (no separate JS list to edit):**
- Elastic cluster **MCP skills** modal (`elastic_settings.js` renders `skill_catalog.groups`)
- Integrations card **Skills** panel (`integrations_settings.js` + `/api/integrations/.../skills`)
- MCP HTTP `/tools` filtered by cluster skill vector (`allowed_tool_names`)

Default vectors (`MSV:1/…/SIEM:Y/…`) enable whole groups. Per-skill overrides use `SK:your_skill=N|Y`.

---

## 4. Integrations safe-test policy (UI “Test safe skills”)

**File:** `src/ai_controller/web/integration_skill_tests.py`

| Situation | What to add |
|---|---|
| Safe dummy args exist | Entry in `SIEM_ARGS` / `NETBOX_ARGS` / etc. |
| Needs a real fixture / id | Entry in `NEEDS_REAL_FIXTURE` with a clear skip reason |
| Destructive | Already covered if listed in `CRITICAL_SKILLS` |

If a SIEM skill is in `SIEM_SKILLS` but missing from `SIEM_ARGS` **and** `NEEDS_REAL_FIXTURE`, the UI will skip it with “No safe dummy input…”. Prefer an explicit `NEEDS_REAL_FIXTURE` reason.

---

## 5. Agent profile (so SOC agents may call it)

**File:** `config/agent_profiles.json`

Add the skill name to the relevant agent’s `"tools"` array (e.g. `soc1_triage_agent`). Profiles are what `execute_as_agent` / runbook routing expect as the allowed tool set.

Optional: mention in `run_books/AGENT_PROFILES_IMPLEMENTATION.md` if you change agent capabilities.

---

## 6. Documentation

| Doc | Path | Update |
|---|---|---|
| Human catalog | `skills.md` (repo root) | Row in the right table + bump Unique/Listed counts |
| Tool reference | `src/mcp/TOOLS.md` | Checklist `- [x] \`skill\`` + full `### \`skill\`` section |
| MCP overview | `src/mcp/README.md` | Mention if it is a notable SIEM/case tool |
| This guide | `src/mcp/ADDING_A_SKILL.md` | You are here |

---

## 7. Runbooks & guidelines (behavior, not just availability)

Update wherever analysts/agents are told which tools to use:

- `run_books/runbook_guidelines.md` — Tools lists / SOC1 principles
- `run_books/soc1/guidelines.md` — mandatory workflow rules
- Primary triage: `run_books/soc1/triage/initial_alert_triage.md` (+ flow script if diagrams list tools)
- Case playbooks: `run_books/soc1/cases/*.md`
- Remediation: `run_books/soc1/remediation/*.md`
- Prompt templates that author runbooks: e.g. `src/ai_controller/approval_queue/create_runbook.py`

Wrap tool names in backticks so `RunbookManager` can extract them.

---

## 8. Tests (minimum bar)

| Test | Path / idea |
|---|---|
| Unit / client | `tests/integrations/...` — mock HTTP; assert endpoint, headers, shape |
| Catalog ↔ MCP | `tests/mcp/test_elastic_siem_skills.py` — skill in `SIEM_SKILLS` == registered `server.tools` |
| UI inventory | `tests/web/test_integration_skill_tests.py` — skill appears in `skill_inventory("elastic:…")` |
| Skill filter | `tests/mcp/test_skill_vector_filter.py` — optional coverage for MSV hide/show |
| Live smoke (optional) | `tests/integrations/siem/elastic/test_siem_tools.py` |

Run (from repo root):

```bash
./venv/bin/python -m pytest tests/mcp/test_elastic_siem_skills.py tests/web/test_integration_skill_tests.py -q
```

---

## Quick checklist (copy/paste)

- [ ] Client method implemented
- [ ] Protocol updated (`src/api/...`)
- [ ] `tools_<domain>.py` wrapper
- [ ] `mcp_server.py` schema + dispatch
- [ ] `skill_vector.py` group tuple (+ optional label override)
- [ ] `integration_skill_tests.py` args **or** `NEEDS_REAL_FIXTURE`
- [ ] `config/agent_profiles.json` tools list (if agents should use it)
- [ ] `skills.md` + `TOOLS.md`
- [ ] Guidelines / runbooks / prompts that mandate the skill
- [ ] Unit + catalog/UI inventory tests green

---

## Example: `get_alert_notes` (SIEM)

| Step | Location |
|---|---|
| Kibana Notes API | `ElasticSIEMClient.get_alert_notes` (+ `Elastic-Api-Version`) |
| Also attached on single-alert load | `get_security_alert_by_id` → `notes` / `note_texts` / `notes_total_count` |
| Wrapper | `tools_siem.get_alert_notes` |
| MCP | `mcp_server` tool + dispatch |
| Catalog / UI | `SIEM_SKILLS` includes `get_alert_notes` |
| Safe-test skip | `NEEDS_REAL_FIXTURE["get_alert_notes"]` |
| Agent | `soc1_triage_agent.tools` |
| Docs | `skills.md`, `TOOLS.md` |
| Process | SOC1 guidelines + `initial_alert_triage` require notes on similar past alerts; batch via `get_alert_notes`, single alert via `get_security_alert_by_id` |

---

## Common mistakes

1. **Only adding the client method** — MCP never sees it; UI never lists it.
2. **Registering in MCP but skipping `SIEM_SKILLS`** — tool may exist on the server process but is missing from the skill-vector editor and Integrations skill list.
3. **Forgetting `agent_profiles.json`** — UI/catalog show the skill; the SOC1 agent still cannot call it.
4. **Updating `skills.md` only** — docs lie; runtime catalog comes from `skill_vector.py`.
5. **Hardcoding skill names in JS** — do not; keep the catalog data-driven.
6. **Destructive skill without approval / CRITICAL skip** — unsafe for Integrations “Test safe skills”.

---

## Where *not* to edit for a normal SIEM skill

- `src/ai_controller/web/static/elastic_settings.js` / `integrations_settings.js` — renderers only
- `index.html` — no per-skill markup
- Open WebUI / Cursor MCP client configs — they discover tools from the MCP server at runtime

When in doubt: **skill_vector + mcp_server + tools_* + client** are mandatory; everything else is discoverability, agent allowlisting, or process documentation.
