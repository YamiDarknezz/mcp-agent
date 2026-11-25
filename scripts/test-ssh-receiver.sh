#!/usr/bin/env bash
set -euo pipefail
receiver="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/ssh-receiver.sh"
temp="$(mktemp -d)"
trap 'rm -rf -- "$temp"' EXIT
source_repo="$temp/source"
checkout="$temp/checkout"
deploy_dir="$temp/deploy"

mkdir -p "$source_repo/scripts" "$deploy_dir"
git -C "$source_repo" init -q -b main
cat > "$source_repo/scripts/deploy.sh" <<'EOF'
set -euo pipefail
cat >/dev/null
printf 'deployment reached the final step\n'
EOF
git -C "$source_repo" add scripts/deploy.sh
git -C "$source_repo" -c user.name=CI -c user.email=ci@example.invalid \
  -c commit.gpgsign=false commit -qm 'Add a test deployment'
sha="$(git -C "$source_repo" rev-parse HEAD)"
git clone -q --branch main -- "$source_repo" "$checkout"

if SSH_ORIGINAL_COMMAND='sh' bash "$receiver" "$checkout" "$deploy_dir"; then
  exit 1
fi
output="$(printf 'untrusted stdin' | SSH_ORIGINAL_COMMAND="deploy $sha" \
  bash "$receiver" "$checkout" "$deploy_dir")"
test "$output" = 'deployment reached the final step'
