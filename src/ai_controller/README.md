# AI Controller

Web-based controller for managing and executing SamiGPT agent commands.

## Setup

```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies (includes websockets for WebSocket support)
pip install -r requirements.txt
```

The `cursor-agent` wrapper script in `venv/bin/cursor-agent` passes commands directly to the Cursor IDE `cursor-agent` binary. When the venv is activated, use:
```bash
# With venv activated - passes through to Cursor IDE cursor-agent
venv/bin/cursor-agent "your prompt here"
venv/bin/cursor-agent --help

# Or add to PATH explicitly
export PATH="venv/bin:$PATH"
cursor-agent "your prompt"
```

**Note:** For the SamiGPT AI Controller web interface, use `python cursor_agent.py --web` (not the wrapper).

## Features

- **Web Interface**: Modern web UI with tabs for managing sessions and autoruns
- **CLI Interface**: Command-line interface for executing commands directly
- **Session Management**: Track and manage agent execution sessions
- **Autorun Support**: Structure ready for scheduled/recurring agent executions
- **Real-time Updates**: WebSocket support for live command output
- **Terminal-like UI**: Terminal-style interface for viewing command results

## Structure

```
src/ai_controller/
├── __init__.py          # Package initialization
├── agent_executor.py    # Command parsing and execution
├── session_manager.py   # Session and autorun storage management
├── cli/
│   ├── __init__.py
│   └── main.py          # CLI entry point
└── web/
    ├── __init__.py
    ├── server.py        # FastAPI web server
    ├── templates/
    │   └── index.html   # Web UI
    └── static/
        ├── app.js       # Frontend JavaScript
        └── css/         # Frontend styles (organized by purpose)
            ├── base.css         # Base styles, reset, body
            ├── layout.css       # Main layout, sidebar, header
            ├── buttons.css      # Button components
            ├── tabs.css         # Tab components
            ├── status.css       # Status badges
            ├── terminal.css     # Terminal display
            ├── autorun.css      # Autorun-specific styles
            ├── modal.css        # Modal dialogs
            ├── settings.css     # Settings page
            └── scrollbar.css   # Custom scrollbar
```

## Usage

### CLI Usage

Execute commands directly from the command line:

```bash
# With venv activated
python cursor_agent.py "run lookup_hash_ti on 973f777723d315e0bee0fb9e81e943bb3440be7d2de7bf582419ae47479bc15d"

# With session tracking
python cursor_agent.py "run get_security_alerts" --session "Alert Check"

# Start web server
python cursor_agent.py --web

# Specify port/host
python cursor_agent.py --web --port 8081 --host 0.0.0.0
```

### Web Interface

```bash
# Start web server (with venv activated)
python cursor_agent.py --web
```

Open browser to `http://localhost:8081` (or configured port).

### Command Format

Commands follow a simple format:

- `run <tool_name> on <value>` - Execute a tool with a single value
- `run <tool_name> with <key>=<value>` - Execute a tool with named parameters
- `run <agent_name> agent on <target>` - Execute an agent (future)
- `run <runbook_name> runbook on <target>` - Execute a runbook (future)

Examples:
- `run lookup_hash_ti on 973f777723d315e0bee0fb9e81e943bb3440be7d2de7bf582419ae47479bc15d`
- `run get_security_alerts`
- `run get_ip_address_report with ip=10.10.10.1`

## Configuration

Add the following to `config.json`:

```json
{
  "ai_controller": {
    "storage_dir": "data/ai_controller",
    "web_port": 8081,
    "web_host": "0.0.0.0"
  }
}
```

## Storage

Sessions and autoruns stored as JSON in `storage_dir`:

- `sessions/` - Session files
- `autoruns/` - Autorun configs

## Future Enhancements

- Autorun scheduling and execution
- Agent and runbook execution support
- Session sharing and collaboration
- Command history and favorites
- Advanced filtering and search

