#!/bin/sh

# raw.githubusercontent.com intermittently answers HTTP 429 (rate limit). Executing
# that error page as a shell script produces confusing failures, so every download
# below is validated before use.

# Universal: upgrades track the fork's main branch (the other branches mirror upstream).
BRANCH_NAME="${CYBERPANEL_BRANCH:-main}"
case "$BRANCH_NAME" in
  ""|*[!A-Za-z0-9._/-]*) BRANCH_NAME="main" ;;
esac

UPGRADE_URL="https://raw.githubusercontent.com/Er-DhruvMishra/cyberpanel/$BRANCH_NAME/cyberpanel_upgrade.sh"

rm -f /usr/local/cyberpanel_upgrade.sh

ATTEMPT=1
while [ "$ATTEMPT" -le 3 ]; do
    HTTP_CODE=$(curl -s -o /usr/local/cyberpanel_upgrade.sh -w "%{http_code}" "$UPGRADE_URL" 2>/dev/null)
    if [ "$HTTP_CODE" = "200" ] && head -n 1 /usr/local/cyberpanel_upgrade.sh | grep -q '^#!'; then
        chmod 700 /usr/local/cyberpanel_upgrade.sh
        export CYBERPANEL_BRANCH="$BRANCH_NAME"
        exec /usr/local/cyberpanel_upgrade.sh
    fi
    echo "Failed to download upgrade script from GitHub (HTTP ${HTTP_CODE:-unknown}), attempt $ATTEMPT of 3."
    if [ "$HTTP_CODE" = "429" ]; then
        echo "GitHub is rate limiting downloads (HTTP 429 Too Many Requests). Waiting before retry..."
    fi
    ATTEMPT=$((ATTEMPT + 1))
    [ "$ATTEMPT" -le 3 ] && sleep 15
done

rm -f /usr/local/cyberpanel_upgrade.sh
echo ""
echo "Failed to download the upgrade script from GitHub (last response: HTTP ${HTTP_CODE:-unknown})."
echo "This is usually a temporary GitHub rate limit. Please retry the upgrade later."
exit 1
