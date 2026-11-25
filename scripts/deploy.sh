#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf '%s\n' "$*" >&2
  exit 1
}

[[ $# -eq 3 ]] || fail 'Usage: deploy.sh COMMIT REPO_DIR DEPLOY_DIR'
sha="$1"
repo_dir="$2"
deploy_dir="$3"
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || fail 'Expected a full commit SHA.'
env_file="$deploy_dir/.env"
[[ -f "$env_file" && -r "$env_file" ]] || fail 'Deployment .env is not readable.'

exec 9> "$deploy_dir/.deploy.lock"
flock -n 9 || fail 'Another deployment is in progress.'

[[ "$(git -C "$repo_dir" symbolic-ref --quiet --short HEAD)" == main ]] \
  || fail 'The deployment checkout must be on main.'
[[ -z "$(git -C "$repo_dir" status --porcelain)" ]] \
  || fail 'The deployment checkout contains local changes.'
git -C "$repo_dir" fetch --no-tags origin refs/heads/main
[[ "$(git -C "$repo_dir" rev-parse FETCH_HEAD)" == "$sha" ]] \
  || fail 'This tested commit is no longer the tip of origin/main.'
git -C "$repo_dir" merge --ff-only "$sha"
[[ "$(git -C "$repo_dir" rev-parse HEAD)" == "$sha" ]] \
  || fail 'The deployment checkout does not match the tested commit.'

export MCP_IMAGE="mcp-agent:$sha"
compose=(
  docker compose --env-file "$env_file"
  -f "$repo_dir/compose.yaml" -f "$repo_dir/compose.prod.yaml"
)
"${compose[@]}" config --quiet
"${compose[@]}" build api
"${compose[@]}" run --rm --no-deps --interactive=false -T migrate
"${compose[@]}" run --rm --no-deps --interactive=false -T migrate python -m server.migrate --check
"${compose[@]}" up -d --no-build --wait --wait-timeout 90 api

origin="$("${compose[@]}" exec -T api python -c 'from server.settings import public_url; print(public_url())')"
for route in health ready; do
  curl --fail --silent --show-error --output /dev/null \
    --max-time 10 --retry 6 --retry-all-errors --retry-max-time 120 "$origin/$route"
done
printf 'Deployed %s; HTTPS checks passed.\n' "$sha"
