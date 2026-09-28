#!/usr/bin/env bash
# Fixed path systemd calls before start. This host's systemd does not expand
# variables in the ExecStartPre executable path, so the unit points here and
# this script jumps to the source tree recorded in /etc/servee/source.env.
set -euo pipefail

if [[ -f /etc/servee/source.env ]]; then
  # shellcheck disable=SC1091
  source /etc/servee/source.env
fi

target="${SERVEE_SOURCE:-}/servee/sync-on-start.sh"
if [[ ! -x "${target}" ]]; then
  echo "servee: source tree not available (${SERVEE_SOURCE:-unset}); keeping the installed copy" >&2
  exit 0
fi

exec "${target}"
