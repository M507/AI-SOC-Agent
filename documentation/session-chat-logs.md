# Session chat logs

The chat for a session is **not** in `logs/debug.log`. Each Sessions or Autoruns conversation is one JSON file named after the session id.

## Where the files are

Default storage is `data/ai_controller/sessions/` under the process working directory.

| How you run SamiGPT | Chat files |
| --- | --- |
| systemd `servee` | `/opt/servee/data/ai_controller/sessions/<session-id>.json` |
| `python app.py` from the repo | `<repo>/data/ai_controller/sessions/<session-id>.json` |

`config.json` can change that path with `ai_controller.storage_dir`. The process also honors `SAMI_STORAGE_DIR`. Restart and reinstall keep `data/` (the installer restores it into `/opt/servee`).

Autorun configs live next to sessions, in `autoruns/`. The autorun **chat** is still a session file in `sessions/`; the autorun JSON only stores schedule, command, and the linked `session_id`.

## How to find a specific session

1. In the UI, open **Sessions** or **Autoruns**. The tab label is the session name (often the id).
2. That id is the filename:

```bash
# Live service
ls /opt/servee/data/ai_controller/sessions/
jq '{id, name, session_type, status, n: (.entries|length)}' \
  /opt/servee/data/ai_controller/sessions/<session-id>.json
```

3. Signed-in API (same JSON the UI uses):

```text
GET https://<host>:8081/api/sessions/<session-id>
```

Deleting a session in the UI deletes that JSON file. Token spend for that chat stays in `/var/lib/servee/usage.jsonl` (see Cost).

## What is inside the file

Top level: `id`, `name`, `session_type` (`manual` or `autorun`), `status`, timestamps, `cluster_id`, `entries`.

Each `entries[]` item is one prompt in that chat:

| Field | Meaning |
| --- | --- |
| `command` | What you (or the autorun) typed |
| `timestamp` | When that turn started |
| `status` | `pending`, `running`, `completed`, `failed`, `stopped` |
| `result.output.text` | The assistant reply shown in the terminal |
| `result.output.trace` | Thinking / tool steps when thinking mode was on |
| `result.output.usage` / `usage_footer` | Token counts for that prompt, when recorded |
| `result.error` | Failure text, if any |

A compact read of one chat:

```bash
jq '{name, session_type, entries: [.entries[] | {timestamp, command, reply: .result.output.text, error: .result.error}]}' \
  /opt/servee/data/ai_controller/sessions/<session-id>.json
```

These files can contain investigation text, tool output, and host names. Treat them like case data.

## What is *not* the chat log

| Location | What it actually is |
| --- | --- |
| `logs/debug.log`, `logs/error.log`, `logs/warning.log` | Application logs (requests, LLM rounds, errors). On `servee` this is `/opt/servee/logs/`. |
| `logs/mcp/` | MCP tool traffic |
| `journalctl -u servee` | stdout/stderr of the systemd unit |
| `/var/lib/servee/usage.jsonl` | Token/cost ledger per model round, not the transcript |

To follow a session in those process logs, grep the session id:

```bash
grep '<session-id>' /opt/servee/logs/debug.log
journalctl -u servee --since today | grep '<session-id>'
```
