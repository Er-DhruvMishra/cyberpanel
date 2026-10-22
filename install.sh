#!/bin/sh
# CyberPanel Universal bootstrap installer.
#
#   sh <(curl -fsSL https://raw.githubusercontent.com/Er-DhruvMishra/cyberpanel/main/install.sh)
#
# Unlike upstream, this does not whitelist distributions: cyberpanel.sh maps any
# apt- or dnf/yum-based system onto the nearest supported profile (universal/compat.sh).
# Installs track the fork's main branch. Pass -b <version> (e.g. -b 3.0.8) for a specific branch.

GIT_USER="${CYBERPANEL_GIT_USER:-Er-DhruvMishra}"

if [ "$(id -u)" != "0" ]; then
        echo "Please run this installer as root."
        exit 1
fi

if command -v apt-get >/dev/null 2>&1 ; then
        DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wget curl ca-certificates >/dev/null
elif command -v dnf >/dev/null 2>&1 ; then
        dnf install -y curl wget ca-certificates >/dev/null 2>&1
elif command -v yum >/dev/null 2>&1 ; then
        yum install -y curl wget ca-certificates >/dev/null 2>&1
else
        echo "Unsupported system: neither apt nor dnf/yum was found."
        exit 1
fi

if [ -r /etc/os-release ]; then
        . /etc/os-release
        echo "Detected ${PRETTY_NAME:-$ID $VERSION_ID}"
fi

INSTALL_BRANCH="${CYBERPANEL_BRANCH:-main}"
EXPECT_BRANCH=0
for argument do
        if [ "$EXPECT_BRANCH" -eq 1 ]; then
                INSTALL_BRANCH="$argument"
                EXPECT_BRANCH=0
        elif [ "$argument" = "-b" ]; then
                EXPECT_BRANCH=1
        fi
done

case "$INSTALL_BRANCH" in
        ""|*[!A-Za-z0-9._/-]*) INSTALL_BRANCH="main" ;;
        [0-9]*) INSTALL_BRANCH="v$INSTALL_BRANCH" ;;
esac

rm -f cyberpanel.sh install.tar.gz
INSTALLER_URL="https://raw.githubusercontent.com/$GIT_USER/cyberpanel/$INSTALL_BRANCH/cyberpanel.sh"
if ! curl --fail --location --silent --show-error -o cyberpanel.sh "$INSTALLER_URL" ; then
        echo "Unable to download $INSTALLER_URL"
        exit 1
fi
chmod +x cyberpanel.sh
CYBERPANEL_GIT_USER="$GIT_USER" CYBERPANEL_BRANCH="$INSTALL_BRANCH" ./cyberpanel.sh "$@"
