#!/bin/bash
# Point every installer/upgrader/update-check URL at your GitHub account.
#   tools/set-github-user.sh <github-user>
# The repository on GitHub must be named "cyberpanel" (the scripts clone into and
# rename a directory of that name). Commit the result and push.
set -euo pipefail
new_user="${1:-}"
if [[ ! "$new_user" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,38})$ ]]; then
  echo "usage: $0 <github-user>" >&2
  exit 1
fi
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"
mapfile -t files < <(git grep -l 'YOUR_GITHUB_USER' -- . ':!tools/set-github-user.sh' || true)
if [[ ${#files[@]} -eq 0 ]]; then
  echo "No YOUR_GITHUB_USER placeholders left; already set?"
  exit 0
fi
sed -i "s/YOUR_GITHUB_USER/$new_user/g" "${files[@]}"
echo "Updated ${#files[@]} files to use github.com/$new_user/cyberpanel"
