#!/usr/bin/env bash
# Shared helpers for Docker-based gitleaks + trufflehog git hooks.
set -euo pipefail

GITLEAKS_IMAGE="${GITLEAKS_IMAGE:-zricethezav/gitleaks:latest}"
TRUFFLEHOG_IMAGE="${TRUFFLEHOG_IMAGE:-trufflesecurity/trufflehog:latest}"
ZERO_SHA="0000000000000000000000000000000000000000"

hooks_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "$hooks_dir" rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "${REPO_ROOT}" ]]; then
  REPO_ROOT="$(cd "$hooks_dir/.." && pwd)"
fi

die() {
  printf '%s\n' "$*" >&2
  exit 1
}

require_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    die "Secret scan blocked: docker is not installed or not on PATH.
Install Docker, start the daemon, then re-run. Images used:
  ${GITLEAKS_IMAGE}
  ${TRUFFLEHOG_IMAGE}
Or run: ./.githooks/install.sh"
  fi

  if ! docker info >/dev/null 2>&1; then
    die "Secret scan blocked: docker daemon is not reachable.
Start Docker and retry. Or run: ./.githooks/install.sh"
  fi
}

ensure_image() {
  local image="$1"
  if docker image inspect "$image" >/dev/null 2>&1; then
    return 0
  fi
  echo "Pulling ${image}..." >&2
  if ! docker pull "$image"; then
    die "Secret scan blocked: failed to pull ${image}."
  fi
}

ensure_scanner_images() {
  ensure_image "$GITLEAKS_IMAGE"
  ensure_image "$TRUFFLEHOG_IMAGE"
}

gitleaks_config_args() {
  if [[ -f "${REPO_ROOT}/gitleaks.toml" ]]; then
    printf '%s\n' --config=/repo/gitleaks.toml
  fi
}

# Run gitleaks inside Docker. Remaining args are passed to the image entrypoint.
run_gitleaks() {
  local -a config_args=()
  local arg
  while IFS= read -r arg; do
    [[ -n "$arg" ]] && config_args+=("$arg")
  done < <(gitleaks_config_args)

  docker run --rm \
    -v "${REPO_ROOT}:/repo:ro" \
    -w /repo \
    -e GIT_CONFIG_COUNT=1 \
    -e GIT_CONFIG_KEY_0=safe.directory \
    -e GIT_CONFIG_VALUE_0=/repo \
    "$GITLEAKS_IMAGE" \
    "${config_args[@]}" \
    "$@"
}

# Run trufflehog inside Docker. Remaining args are passed after the image name.
run_trufflehog() {
  docker run --rm \
    -v "${REPO_ROOT}:/workdir:ro" \
    -w /workdir \
    -e GIT_CONFIG_COUNT=1 \
    -e GIT_CONFIG_KEY_0=safe.directory \
    -e GIT_CONFIG_VALUE_0=/workdir \
    "$TRUFFLEHOG_IMAGE" \
    "$@"
}

scan_staged_gitleaks() {
  echo "==> gitleaks (staged)" >&2
  run_gitleaks git --pre-commit --staged --redact --verbose .
}

scan_staged_trufflehog() {
  echo "==> trufflehog (staged)" >&2
  # Official Docker pre-commit form.
  docker run --rm \
    -v "${REPO_ROOT}:/workdir:ro" \
    -e TRUFFLEHOG_PRE_COMMIT=1 \
    -e GIT_CONFIG_COUNT=1 \
    -e GIT_CONFIG_KEY_0=safe.directory \
    -e GIT_CONFIG_VALUE_0=/workdir \
    "$TRUFFLEHOG_IMAGE" \
    git file:///workdir
}

scan_range_gitleaks() {
  local log_opts="$1"
  echo "==> gitleaks (range: ${log_opts})" >&2
  run_gitleaks git --redact --verbose --log-opts="${log_opts}" .
}

scan_range_trufflehog() {
  local since_commit="${1:-}"
  echo "==> trufflehog (since: ${since_commit:-beginning})" >&2
  if [[ -n "$since_commit" && "$since_commit" != "$ZERO_SHA" ]]; then
    run_trufflehog git file:///workdir \
      --since-commit "$since_commit" \
      --results=verified,unknown \
      --fail \
      --trust-local-git-config
  else
    run_trufflehog git file:///workdir \
      --results=verified,unknown \
      --fail \
      --trust-local-git-config
  fi
}

scan_full_gitleaks() {
  echo "==> gitleaks (full repo)" >&2
  run_gitleaks git --redact --verbose .
}

scan_full_trufflehog() {
  echo "==> trufflehog (full repo)" >&2
  run_trufflehog git file:///workdir \
    --results=verified,unknown \
    --fail \
    --trust-local-git-config
}

prepare_scanners() {
  require_docker
  ensure_scanner_images
}
