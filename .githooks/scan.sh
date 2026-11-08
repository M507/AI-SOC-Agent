#!/usr/bin/env bash
# On-demand secret scan (gitleaks + trufflehog via Docker). Prints findings.
set -euo pipefail

hooks_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "${hooks_dir}/common.sh"

usage() {
  cat <<'EOF'
Usage: ./.githooks/scan.sh [options]

Run Docker-based secret scanners and print findings. Does not commit or push.

Options:
  --staged              Scan staged changes only
  --since <ref>         Scan changes since a git ref (e.g. HEAD~5, origin/main)
  --gitleaks-only       Run only gitleaks
  --trufflehog-only     Run only trufflehog
  -h, --help            Show this help

Default (no mode flags): full repository history scan with both tools.

Exit codes:
  0  no secrets found
  1  secrets found, Docker unavailable, or scanner failure
EOF
}

mode="full"
since_ref=""
run_gitleaks=1
run_trufflehog=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --staged)
      mode="staged"
      shift
      ;;
    --since)
      [[ $# -ge 2 ]] || die "--since requires a git ref"
      mode="since"
      since_ref="$2"
      shift 2
      ;;
    --gitleaks-only)
      run_gitleaks=1
      run_trufflehog=0
      shift
      ;;
    --trufflehog-only)
      run_gitleaks=0
      run_trufflehog=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "Unknown option: $1
$(usage)"
      ;;
  esac
done

prepare_scanners

failed=0

case "$mode" in
  staged)
    echo "Manual secret scan: staged changes" >&2
    if [[ "$run_gitleaks" -eq 1 ]]; then
      if ! scan_staged_gitleaks; then
        echo "gitleaks: findings or failure" >&2
        failed=1
      else
        echo "gitleaks: clean" >&2
      fi
    fi
    if [[ "$run_trufflehog" -eq 1 ]]; then
      if ! scan_staged_trufflehog; then
        echo "trufflehog: findings or failure" >&2
        failed=1
      else
        echo "trufflehog: clean" >&2
      fi
    fi
    ;;
  since)
    echo "Manual secret scan: since ${since_ref}" >&2
    if [[ "$run_gitleaks" -eq 1 ]]; then
      if ! scan_range_gitleaks "${since_ref}..HEAD"; then
        echo "gitleaks: findings or failure" >&2
        failed=1
      else
        echo "gitleaks: clean" >&2
      fi
    fi
    if [[ "$run_trufflehog" -eq 1 ]]; then
      if ! scan_range_trufflehog "$since_ref"; then
        echo "trufflehog: findings or failure" >&2
        failed=1
      else
        echo "trufflehog: clean" >&2
      fi
    fi
    ;;
  full)
    echo "Manual secret scan: full repository" >&2
    if [[ "$run_gitleaks" -eq 1 ]]; then
      if ! scan_full_gitleaks; then
        echo "gitleaks: findings or failure" >&2
        failed=1
      else
        echo "gitleaks: clean" >&2
      fi
    fi
    if [[ "$run_trufflehog" -eq 1 ]]; then
      if ! scan_full_trufflehog; then
        echo "trufflehog: findings or failure" >&2
        failed=1
      else
        echo "trufflehog: clean" >&2
      fi
    fi
    ;;
esac

if [[ "$failed" -ne 0 ]]; then
  echo "Secret scan finished with findings or errors." >&2
  exit 1
fi

echo "Secret scan finished: no secrets found." >&2
exit 0
