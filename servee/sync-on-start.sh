#!/usr/bin/env bash
# Refresh /opt/servee from the source tree recorded at install time.
# systemd runs this before every start, so `systemctl restart servee` picks up
# code changes. config.json, certs/, data/, logs/, and the venv are kept.
set -euo pipefail

INSTALL_DIR="${SERVEE_INSTALL_DIR:-/opt/servee}"
ENV_FILE="/etc/servee/source.env"

if [[ -z "${SERVEE_SOURCE:-}" && -f "${ENV_FILE}" ]]; then
  # shellcheck disable=SC1090
  source "${ENV_FILE}"
fi

SOURCE="${SERVEE_SOURCE:-}"
if [[ -z "${SOURCE}" || ! -f "${SOURCE}/app.py" ]]; then
  echo "servee: source tree not available (${SOURCE:-unset}); keeping the installed copy" >&2
  exit 0
fi

source_real="$(readlink -f "${SOURCE}")"
install_real="$(readlink -f "${INSTALL_DIR}")"
if [[ "${source_real}" == "${install_real}" ]]; then
  exit 0
fi

mkdir -p "${INSTALL_DIR}"

echo "==> Syncing ${source_real} -> ${INSTALL_DIR}"
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
  --exclude 'config.json' \
  --exclude '.source-root' \
  --exclude '.requirements.sha256' \
  --exclude '*.pyc' \
  "${source_real}/" "${INSTALL_DIR}/"

req="${INSTALL_DIR}/requirements.txt"
stamp="${INSTALL_DIR}/.requirements.sha256"
pip="${INSTALL_DIR}/venv/bin/pip"
if [[ -x "${pip}" && -f "${req}" ]]; then
  hash="$(sha256sum "${req}" | awk '{print $1}')"
  old=""
  if [[ -f "${stamp}" ]]; then
    old="$(tr -d '[:space:]' < "${stamp}")"
  fi
  if [[ "${hash}" != "${old}" ]]; then
    echo "==> requirements.txt changed; installing dependencies"
    "${pip}" install --upgrade pip
    "${pip}" install -r "${req}"
    printf '%s\n' "${hash}" > "${stamp}"
  fi
fi

printf '%s\n' "${source_real}" > "${INSTALL_DIR}/.source-root"
echo "==> Sync complete"
