# Setup

SamiGPT starts in one of two ways. Both use the same console. When `web.password` is empty, the process opens the setup wizard at `/setup` instead of asking for a sign-in. An install that already has an Argon2id password opens the console at sign-in and is not sent through the wizard. After sign-in, **Setup** in the nav reopens the wizard so those values can be edited.

The wizard asks for the console password, then Elastic, case management, EDR, threat intel, knowledge and assets, engineering tickets, and AI with MCP. Each optional step has **Skip for now**. Skip does not blank that section. It leaves the placeholders from `config.json.example`, and a later skip restores that section from the example. **Finish** writes the config. Certificate checks for Elastic, the local TIP, and NetBox are stored off. Settings can turn them on later. The MCP listener binds `0.0.0.0` even when the AI step is skipped.

## Docker Compose

A new container, separate from the production service. The UI is on host port **18081** and MCP is on host port **18082**. It does not bind 8081 or 8082.

```bash
docker compose -p samigpt-onboarding -f onboarding/docker-compose.yml up --build
```

Open `https://127.0.0.1:18081/setup`. The browser warns about the self-signed certificate written in the container on first start. Accept it for this host.

| What | Where |
| --- | --- |
| Config | `/var/lib/samigpt/config.json` in the `onboarding_state` volume |
| Certificates | `/app/certs` in the `onboarding_certs` volume |
| Process ports inside the container | UI 8081, MCP 8082 |

Config and certificates stay across `up`. Stop the stack with:

```bash
docker compose -p samigpt-onboarding -f onboarding/docker-compose.yml down
```

`down -v` deletes those volumes, including the wizard config.

MCP on the host is `http://127.0.0.1:18082` when MCP TLS is off, and `https://127.0.0.1:18082` when it is on. Health, tools, and JSON-RPC are `/health`, `/tools`, and `POST /rpc`. Send `Authorization: Bearer` and the MCP token from the AI step.

## Production service

The `servee` unit is the boot-persistent copy. The installer copies the app to `/opt/servee`, creates a Python 3.10+ venv, and enables the unit (`Restart=always`). It keeps `config.json`, `certs/`, `data/`, and `logs/`.

```bash
sudo ./servee/install.sh
sudo systemctl status servee
journalctl -u servee -f
```

`systemctl restart servee` syncs this source tree into `/opt/servee` before launch. The config, certificates, data, logs, and the virtualenv stay in place. Dependencies are reinstalled when `requirements.txt` changes. A full wipe, including a new virtualenv, is `sudo ./servee/install.sh`.

| What | Where |
| --- | --- |
| UI | `https://<host>:8081` |
| Wizard, only when the password is empty | `https://<host>:8081/setup` |
| MCP | `https://<host>:8082` |
| Config | `/opt/servee/config.json` |

Point the installer at a specific Python 3.10+ binary with `sudo PYTHON_BIN=/path/to/python3.11 ./servee/install.sh`.

## TODOs

- Detection as Code: add a wizard step that stores only a folder path for rule JSON, using the same `detection.rules_dir` field already edited under Settings, General. Behavior of that folder is described in [Detection as Code](detection-as-code.md). SamiGPT reads and, after review, writes that folder itself. The step should be skippable like the other optional steps and should not copy rule files into this tree or the container image.
