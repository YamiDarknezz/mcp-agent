#!/usr/bin/env bash
set -euo pipefail
umask 077

# Install outside the checkout and bind this command to one SSH key.
if [[ $# -ne 2 || ! ${SSH_ORIGINAL_COMMAND:-} =~ ^deploy\ ([0-9a-f]{40})$ ]]; then
  printf '%s\n' 'Only deploy COMMIT is accepted by this key.' >&2
  exit 64
fi
sha="${BASH_REMATCH[1]}"
repo_dir="$1"
deploy_dir="$2"

# Do not accept scripts or paths from the SSH client. Load only origin/main.
git -C "$repo_dir" fetch --no-tags origin refs/heads/main
[[ "$(git -C "$repo_dir" rev-parse FETCH_HEAD)" == "$sha" ]] || {
  printf '%s\n' 'The commit is not the tip of origin/main.' >&2
  exit 1
}
payload="$(mktemp "$deploy_dir/.deploy-script.XXXXXXXX")"
trap 'rm -f -- "$payload"' EXIT
git -C "$repo_dir" show "$sha:scripts/deploy.sh" > "$payload"
bash "$payload" "$sha" "$repo_dir" "$deploy_dir" </dev/null
