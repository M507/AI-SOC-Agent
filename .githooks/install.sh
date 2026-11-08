#!/usr/bin/env bash
# Enable Docker-based secret-scan git hooks for this repository.
set -euo pipefail

hooks_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "${hooks_dir}/common.sh"

chmod +x \
  "${hooks_dir}/common.sh" \
  "${hooks_dir}/pre-commit" \
  "${hooks_dir}/pre-push" \
  "${hooks_dir}/scan.sh" \
  "${hooks_dir}/install.sh"

require_docker
ensure_scanner_images

git -C "$REPO_ROOT" config core.hooksPath .githooks

echo "Installed git hooks (core.hooksPath=.githooks)."
echo "Images ready:"
echo "  ${GITLEAKS_IMAGE}"
echo "  ${TRUFFLEHOG_IMAGE}"
echo "Manual scan anytime: ./.githooks/scan.sh [--staged|--since REF]"
