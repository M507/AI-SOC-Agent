# Detection as Code

SamiGPT section for reading an external Elastic rule folder, working open alerts, and writing an exception or a disable only after an analyst implements a review. The sidebar group is **Detection as Code**: **Findings**, **Rules**, and **Review**. Settings live under **Settings → General → Detection as Code**.

Rule JSON stays in the configured folder. It is not vendored, copied, or imported from another rules application. Prompts, model calls, usage, validation, the diff, and the file write are in `src/ai_controller/detection/`.

## What is implemented

| Surface | What the analyst can do | What is written |
| --- | --- | --- |
| Findings | Search open alerts, check evidence, Ask, send checked fields to Review, ask the model to suggest an exception, acknowledge or close | Ask and Suggest do not write a rule file. Acknowledge and Close change Elastic workflow status only |
| Rules | Search the folder, open one rule, start a disable review | Disable does not rename the file until Implement |
| Review | Keep or drop conditions, Draft, Ask for changes, Implement, Reject | Implement writes the rule JSON. Reject archives the review and leaves the file unchanged |

Not implemented: pushing the rule to Kibana, pulling or merging an upstream rules catalog, a Discord notifier, and the setup-wizard step that would store the folder path. The wizard step is still the TODO in [Setup](setup.md). **Settings → General** already saves that same `detection.rules_dir` field.

Filing a **Fine-tune detection** note from the agent still only stores an informational Requests card. It does not call the Detection as Code model and does not edit a file. See [Requests tab](requests.md). Findings actions below are separate from that card.

## Rules folder

Resolution, first match wins:

1. `SAMI_LAB_RULES_DIR`
2. `config.json` section `detection.rules_dir`
3. Default path `/root/Home-Lab-Rules/rules/elastic_1/rules`

An empty saved path is allowed and falls through to the default. A non-empty path must already be a directory (`expanduser` + `resolve`). Saving settings (`PUT /api/detections/settings`) clears the in-memory rule index.

`detection.findings_hours` defaults to **168**. `detection.match_hours` defaults to **2160** (90 days). Both are clamped to 1..2160. Findings uses the findings lookback. Acknowledge and Close use the match lookback.

`config.json.example` has the `detection` section. The UI card is **Settings → General**, saved by its own button so saving investigation limits does not clear the path.

## Rule files

Each detection is one JSON object in that folder:

| Key | Role |
| --- | --- |
| `_dac` | Local status, `rule_id`, sync metadata. Disable sets `_dac.status` to `disabled` |
| `rule` | Elastic rule document (`name`, `query`, `enabled`, `investigation_fields`, and the rest) |
| `exception_items` | Exception entries written by Implement. Absent until the first write |

Filenames look like `[enabled]_name_uuid.json` or `[disabled]_name_uuid.json`. The indexer (`src/ai_controller/approval_queue/lab_rules.py`) skips `suggested_fields.json`. Search returns at most 100 hits; the Rules page asks for 50.

### Suggested fields

A finding field is marked **Suggested**, and starts checked, when its dotted name is in either set:

- The rule's highlighted fields: `rule.investigation_fields.field_names` (also read from `signal.rule.investigation_fields` or `kibana.alert.rule.investigation_fields` on the alert when present)
- Extra names in `suggested_fields.json` in the rules folder

The catalog file is an object with a `fields` array (a bare array is also accepted). It applies to every finding. The rule list applies only to that rule. Missing or unreadable JSON does not fail the finding; those extra names are simply omitted. Suggested does not write anything. A field is sent with Ask, exception, acknowledge, or close only while its checkbox stays checked.

## Package

Each module below has a docstring that points back at this file.

| Module | Responsibility |
| --- | --- |
| `detection/findings.py` | Flatten alert fields, suggest names, list open alerts, acknowledge and close |
| `detection/rules_store.py` | Folder status, load and search, render a file with exceptions or disabled, atomic write |
| `detection/settings.py` | `detection` section and the env override |
| `detection/prompts.py` | Ask templates and the draft JSON contract. Not the global SOC system prompt |
| `detection/ask.py` | One model call about a finding. `mcp_client=None`, `max_tool_iterations=0` |
| `detection/drafting.py` | Parse the draft JSON and normalize exception cards |
| `detection/review.py` | Create, draft, revise, select, implement, reject. Stored as an informational `fine_tune` request |
| `detection/validation.py` | Blocks a write that is empty, wildcarded, off-evidence, duplicated, or against a file that changed |
| `detection/diff.py` | Unified diff used by the Review **Change** pane |
| `detection/apply.py` | Builds an exception item and calls the store write |
| `detection/usage.py` | One usage-ledger row per model round, `session_type=detection` |
| `web/routes_detections.py` | `/api/detections`, behind the same session auth as the rest of the console |
| `web/static/detections.js` | Findings, Rules, and Review UI |

The active LLM provider is `get_active_provider().complete`. There is no second HTTP client and no tool loop.

## Findings

`GET /api/detections/findings` loads up to 100 open alerts from the configured Elastic cluster (`include_investigated=true`). Omit `hours` and the server uses `findings_hours`. The list search is a case-insensitive match on title, rule name, rule id, severity, and host.

`GET /api/detections/findings/{alert_id}` returns the summary plus up to 400 flattened scalar fields. Nested object keys become dotted names (`host.name`). Lists of scalars are joined. Prefixes `kibana.alert.rule.parameters`, `kibana.alert.rule.note`, `signal.rule.note`, and `signal.rule.investigation_fields` are not evidence rows. Suggested rows sort first.

Every Findings action in the UI requires at least one checked field.

| Action | API | Model | Rule file | Alerts |
| --- | --- | --- | --- | --- |
| Ask about this finding | `POST .../ask` | One call. The answer stays on the finding | Unchanged | Unchanged |
| Create exception from checked fields | `POST .../exception` | None | Unchanged. Opens Review with the fields as one AND condition, **unchecked** | Unchanged |
| Suggest with AI | `POST .../suggest` | None yet. Opens Review at stage `proposed` | Unchanged until Draft, and Draft still does not write | Unchanged |
| Acknowledge | `POST .../status` with `acknowledged` | None | Unchanged | This alert, plus other open alerts for the same rule whose fields contain every checked value, set to `acknowledged` |
| Close | `POST .../status` with `closed` | None | Unchanged. Does not add an exception | Same match set, closed as `false_positive` with no close comment |

If the note box has text, that text is `add_alert_note` before the status change. An empty note updates status and does not write a note. The action is audited (`record_action`). It is not an approval-queue Approve.

Ask templates (`prompts.py`): `ask_about`, `is_fp`, `suggest_exception`, `investigate`, `explain_rule`, `risk_severity`, `ticket_summary`, `custom`. Custom uses the text box. Ask does not create a review.

## Review

Reviews are informational `fine_tune` approval requests whose payload has a `dac` object. `GET /api/detections/reviews` returns the open ones (not archived). The Requests tab can still show the same note; Done or Ignore there does not write the file.

`dac` holds `stage`, `kind` (`exceptions` or `disable`), `file`, `file_sha256`, `rule_id`, `evidence_fields`, and `revisions`. The current revision holds `rationale`, `exceptions` (cards), and for a model draft `safe_to_except` and `notes`.

| Stage | How you get there | Buttons |
| --- | --- | --- |
| `proposed` | Suggest with AI | **Draft** only. One model call. File unchanged |
| `drafted` | After Draft, or immediately for a field exception or a disable | Checkboxes, **Ask for changes** (exceptions only), **Implement**, **Reject** |
| `implemented` | Implement succeeded | No further edits. The request is acknowledged |
| `rejected` | Reject | File unchanged. The request is ignored |

A field exception card is one AND of the checked fields and starts with `selected: false`. Implement stays disabled in the UI until at least one card is checked, and the API rejects a write with no selected condition. Unchecked cards are omitted from the file and from the diff. Toggling a box is `POST /api/detections/reviews/{id}/selection`, which rebuilds the diff without a model call.

**Ask for changes** (`POST .../revise`) needs feedback text, spends one model call, and appends a revision. It does not write the file. Disable reviews cannot be drafted or revised.

**Implement** (`POST .../implement`):

An unchecked field exception is a normal open review. The page does not treat "nothing selected" as an error. Implement is what refuses that write. Wildcards, duplicate conditions, and fields outside the stored evidence are errors on Implement and warnings or errors on the review when a selected card already has the problem.

- Exceptions: validates the checked cards, appends them to `exception_items`, writes the same path
- Disable: writes a sibling `[disabled]_...` file first, then removes the `[enabled]_...` file, so a failed write leaves the original in place. Sets `rule.enabled` false and `_dac.status` to `disabled`
- Does not close the alert and does not push the rule to Kibana
- If `file_sha256` no longer matches the bytes on disk, the write is refused (409) and the review must be drafted again

**Reject** (`POST .../reject`) archives the review.

### Exception item shape

Each written item (`detection/apply.py`) is a simple included match:

- `item_id`: `sami-{rule_id[:8]}-{sha256 of field=value pairs, 10 hex chars}`
- `list_id`: `sami-{rule_id[:8]}-exceptions`
- `type`: `simple`, `operator`: `included`, entry `type`: `match`
- `namespace_type`: `single`

### What blocks a write

`detection/validation.py` raises before the file is touched when:

- No card is selected
- A selected card has an empty field or value
- A value contains `*` or `?` and that card does not set `allow_wildcard`
- A field was not in the evidence stored with the review
- The same condition is already on the rule, or two checked cards are identical

A single volatile field (`user.name`, or an IP / `source.address` in that list) is a warning only. It does not block Implement.

The draft prompt (`DRAFT_SYSTEM` in `prompts.py`) tells the model to prefer the analyst-selected fields, to avoid inventing names, to avoid wildcards, and to return JSON only. Medium and high confidence cards from the model start selected; low confidence starts unselected.

## HTTP API

All routes are under `/api/detections` and require a signed-in session.

| Method | Path | Effect |
| --- | --- | --- |
| GET, PUT | `/settings` | Read or save `rules_dir`, `findings_hours`, `match_hours` |
| GET | `/findings` | Open alerts. Optional `q`, `hours` |
| GET | `/findings/{alert_id}` | One alert and its fields |
| POST | `/findings/{alert_id}/ask` | `{prompt_id, custom_instruction, entries}` |
| POST | `/findings/{alert_id}/exception` | `{entries, name?}`. Creates the review, does not write |
| POST | `/findings/{alert_id}/suggest` | `{entries}`. Creates a `proposed` review |
| POST | `/findings/{alert_id}/status` | `{status: acknowledged\|closed, entries, note, rule_id}` |
| GET | `/rules` | `q`, `limit` (1..100) |
| GET | `/rules/{rule_id}` | Query, exceptions, description |
| POST | `/rules/{rule_id}/disable` | Creates a disable review |
| GET | `/reviews` | Open Detection as Code reviews |
| GET | `/reviews/{request_id}` | One review, including overview, conditions, warnings, and diff |
| POST | `/reviews/{request_id}/draft` | First model draft |
| POST | `/reviews/{request_id}/revise` | `{feedback}` |
| POST | `/reviews/{request_id}/selection` | `{exceptions: [{selected, allow_wildcard}, ...]}` for every card, in order |
| POST | `/reviews/{request_id}/implement` | Writes the file |
| POST | `/reviews/{request_id}/reject` | Archives |

`DetectionError.status_code` is the HTTP status. A missing rules folder is 409. A missing Elastic cluster is 409 with `No Elastic cluster is configured.`

## UI

`templates/index.html` holds the three panes. `static/detections.js` is `DetectionsManager`. `static/css/detections.css` follows the same tokens as the rest of the console (list pane plus detail, as on Requests).

Findings splits Ask, Exception, and Workflow. Exception copy states that the file is not written until Implement. Close is the danger button. Rules shows query, exceptions, and **Disable through review**. Review shows the rule overview, condition checkboxes, the unified diff (additions and deletions colored), then Implement. Reject sits apart from Implement.

Switching to Review after **Create exception** or **Suggest with AI** does not call Implement. The status line says the file is unchanged.
