#!/bin/bash
# Re-embed universal/compat.sh into the standalone installer and upgrader.
# The block sits between the "# >>> universal-compat >>>" and "# <<< universal-compat <<<"
# markers; if the markers are missing it is inserted before the anchor function.
set -euo pipefail
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
compat="$repo_root/universal/compat.sh"

embed() {
  local target="$1" anchor="$2"
  python3 - "$compat" "$target" "$anchor" <<'PY'
import sys
compat, target, anchor = sys.argv[1:]
block = open(compat).read().rstrip('\n') + '\n'
text = open(target).read()
start, end = '# >>> universal-compat >>>', '# <<< universal-compat <<<'
if start in text:
    head, rest = text.split(start, 1)
    tail = rest.split(end, 1)[1].lstrip('\n')
    text = head + block + '\n' + tail
else:
    if anchor not in text:
        sys.exit('anchor %r not found in %s' % (anchor, target))
    text = text.replace(anchor, block + '\n' + anchor, 1)
open(target, 'w').write(text)
PY
  echo "embedded universal/compat.sh into ${target#$repo_root/}"
}

embed "$repo_root/cyberpanel.sh" "Set_Default_Variables() {"
embed "$repo_root/cyberpanel_upgrade.sh" "Check_CSF_Migration() {"
