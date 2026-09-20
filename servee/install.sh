#!/usr/bin/env bash
# Install / reinstall SamiGPT as the systemd service "servee".
# Everything lives under /opt/servee. Re-running this script reinstalls cleanly
# while preserving config.json, certs/, data/, and logs/.
set -euo pipefail

SERVICE_NAME="servee"
INSTALL_DIR="/opt/servee"
UNIT_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/servee.service"
UNIT_DST="/etc/systemd/system/${SERVICE_NAME}.service"

# Repo root = parent of servee/
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo $0" >&2
  exit 1
fi

if [[ ! -f "${REPO_ROOT}/app.py" ]]; then
  echo "Cannot find app.py under ${REPO_ROOT}" >&2
  exit 1
fi

if [[ ! -f "${UNIT_SRC}" ]]; then
  echo "Missing unit file: ${UNIT_SRC}" >&2
  exit 1
fi

echo "==> Installing ${SERVICE_NAME} from ${REPO_ROOT} -> ${INSTALL_DIR}"

# Stop existing service and any stray manual app.py on this machine
if systemctl list-unit-files "${SERVICE_NAME}.service" &>/dev/null; then
  systemctl stop "${SERVICE_NAME}.service" 2>/dev/null || true
fi
pkill -f "${INSTALL_DIR}/venv/bin/python .*app\.py" 2>/dev/null || true
# Also stop a manually-started repo copy that would fight for 8081/8082
pkill -f "${REPO_ROOT}/venv/bin/python .*app\.py" 2>/dev/null || true
sleep 1

# Preserve runtime state across reinstalls
PRESERVE_TMP="$(mktemp -d /tmp/servee-preserve.XXXXXX)"
cleanup_preserve() { rm -rf "${PRESERVE_TMP}"; }
trap cleanup_preserve EXIT

if [[ -d "${INSTALL_DIR}" ]]; then
  echo "==> Preserving config / certs / data / logs"
  for item in config.json certs data logs; do
    if [[ -e "${INSTALL_DIR}/${item}" ]]; then
      cp -a "${INSTALL_DIR}/${item}" "${PRESERVE_TMP}/"
    fi
  done
  echo "==> Removing previous install at ${INSTALL_DIR}"
  rm -rf "${INSTALL_DIR}"
fi

mkdir -p "${INSTALL_DIR}"

echo "==> Syncing application files"
rsync -a \
  --delete \
  --exclude '.git/' \
  --exclude 'venv/' \
  --exclude '__pycache__/' \
  --exclude '.pytest_cache/' \
  --exclude '.cursor/' \
  --exclude 'logs/' \
  --exclude 'data/' \
  --exclude 'certs/' \
  --exclude 'servee/' \
  --exclude '*.pyc' \
  "${REPO_ROOT}/" "${INSTALL_DIR}/"

# Restore preserved state (wins over anything synced)
for item in config.json certs data logs; do
  if [[ -e "${PRESERVE_TMP}/${item}" ]]; then
    rm -rf "${INSTALL_DIR}/${item}"
    cp -a "${PRESERVE_TMP}/${item}" "${INSTALL_DIR}/"
  fi
done

# Seed config if missing
if [[ ! -f "${INSTALL_DIR}/config.json" ]]; then
  if [[ -f "${INSTALL_DIR}/config.json.example" ]]; then
    cp "${INSTALL_DIR}/config.json.example" "${INSTALL_DIR}/config.json"
    echo "==> Seeded config.json from config.json.example — set web.password before first login"
  else
    echo "WARNING: no config.json found; app may refuse to start" >&2
  fi
fi

mkdir -p "${INSTALL_DIR}/certs" "${INSTALL_DIR}/data" "${INSTALL_DIR}/logs"

# Prefer copying current repo config on first install if present in source tree
# (config.json is gitignored; only used when install dir had nothing to preserve)
if [[ ! -f "${PRESERVE_TMP}/config.json" && -f "${REPO_ROOT}/config.json" ]]; then
  cp -a "${REPO_ROOT}/config.json" "${INSTALL_DIR}/config.json"
  echo "==> Copied config.json from source tree"
fi
if [[ ! -d "${PRESERVE_TMP}/certs" && -d "${REPO_ROOT}/certs" ]]; then
  cp -a "${REPO_ROOT}/certs/." "${INSTALL_DIR}/certs/"
fi

echo "==> Creating virtualenv and installing dependencies"

# Prefer modern Python (3.10+). System python3 on Ubuntu 20.04 is often 3.8,
# which breaks current pydantic/fastapi typing. Match the repo's working venv.
pick_python() {
  local candidates=()
  if [[ -n "${PYTHON_BIN:-}" ]]; then
    candidates+=("${PYTHON_BIN}")
  fi
  # Absolute pyenv builds (shims often fail under root without pyenv init)
  local pyenv_root="${PYENV_ROOT:-${HOME}/.pyenv}"
  local verdir
  for verdir in \
    "${pyenv_root}/versions"/3.13.*/bin/python \
    "${pyenv_root}/versions"/3.12.*/bin/python \
    "${pyenv_root}/versions"/3.11.*/bin/python \
    "${pyenv_root}/versions"/3.10.*/bin/python
  do
    [[ -x "${verdir}" ]] && candidates+=("${verdir}")
  done
  # Prefer named binaries / shims before the OS default
  candidates+=(python3.13 python3.12 python3.11 python3.10 python3)
  local cand ver major minor
  for cand in "${candidates[@]}"; do
    if [[ "${cand}" == /* ]]; then
      [[ -x "${cand}" ]] || continue
    elif ! command -v "${cand}" >/dev/null 2>&1; then
      continue
    fi
    ver="$("${cand}" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || true)"
    [[ -z "${ver}" ]] && continue
    major="${ver%%.*}"
    minor="${ver#*.}"
    if (( major > 3 || (major == 3 && minor >= 10) )); then
      echo "${cand}"
      return 0
    fi
  done
  return 1
}

PYTHON_CMD="$(pick_python || true)"
if [[ -z "${PYTHON_CMD}" ]]; then
  echo "Python 3.10+ is required (found only older python3). Install python3.11+ or set PYTHON_BIN." >&2
  exit 1
fi
echo "    using $($PYTHON_CMD -V 2>&1) via ${PYTHON_CMD}"

if ! "${PYTHON_CMD}" -c "import venv" 2>/dev/null; then
  if command -v apt-get >/dev/null; then
    apt-get update -qq
    apt-get install -y -qq python3-venv python3-pip
  else
    echo "python venv module is required for ${PYTHON_CMD}" >&2
    exit 1
  fi
fi

"${PYTHON_CMD}" -m venv "${INSTALL_DIR}/venv"
"${INSTALL_DIR}/venv/bin/pip" install --upgrade pip
"${INSTALL_DIR}/venv/bin/pip" install -r "${INSTALL_DIR}/requirements.txt"

echo "==> Installing systemd unit"
install -m 0644 "${UNIT_SRC}" "${UNIT_DST}"
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}.service"
systemctl restart "${SERVICE_NAME}.service"

sleep 2
if systemctl is-active --quiet "${SERVICE_NAME}.service"; then
  echo "==> ${SERVICE_NAME} is active and enabled"
  systemctl --no-pager --full status "${SERVICE_NAME}.service" | head -n 20 || true
  echo
  echo "Install dir : ${INSTALL_DIR}"
  echo "Service     : systemctl status ${SERVICE_NAME}"
  echo "Logs        : journalctl -u ${SERVICE_NAME} -f"
else
  echo "ERROR: ${SERVICE_NAME} failed to start" >&2
  journalctl -u "${SERVICE_NAME}" -n 40 --no-pager >&2 || true
  exit 1
fi
