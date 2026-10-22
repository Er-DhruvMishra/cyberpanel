# >>> universal-compat >>>
# CyberPanel Universal compatibility layer.
#
# Canonical copy: universal/compat.sh. It is embedded verbatim in cyberpanel.sh and
# cyberpanel_upgrade.sh (they are downloaded and run standalone); after editing it run
# tools/sync-compat.sh. The mapping table must match cyberpanel_os_profile.py.
#
# What it does:
#   * maps any distro onto the nearest OS profile upstream supports (Server_OS /
#     Server_OS_Version), so the rest of the scripts keep using their existing branches;
#   * picks a Python 3.9-3.12 interpreter for the panel virtualenvs, installing one from
#     the distro when the system python3 is too old (CentOS 8: 3.6) or too new;
#   * wires lscpd/lswsgi to that interpreter and records features disabled on this host.

Universal_Log_File="/var/log/cyberpanel_universal.log"
Universal_Profile_File="/etc/cyberpanel/os_profile"
Universal_Features_File="/etc/cyberpanel/disabled_features"
Universal_Min_Python="3.9"
Universal_Max_Python="3.12"
Universal_Python_Changed="No"
# Installs and upgrades track this branch of the fork (the other branches mirror upstream).
# CYBERPANEL_BRANCH overrides it; -b <version> still selects a specific vX.Y.Z branch.
Universal_Release_Branch="${CYBERPANEL_BRANCH:-main}"

Universal_Log() {
  echo -e "[universal] $*"
  echo "[$(date '+%F %T')] $*" >> "$Universal_Log_File" 2>/dev/null || true
}

# Print "<Server_OS> <Server_OS_Version> <family> <native 0|1>" for an os-release file.
Universal_Map_Profile() {
  local release_file="$1"
  local os_id like version codename major
  os_id=$( . "$release_file" 2>/dev/null; echo "${ID:-}" | tr '[:upper:]' '[:lower:]')
  like=$( . "$release_file" 2>/dev/null; echo " ${ID_LIKE:-} " | tr '[:upper:]' '[:lower:]')
  version=$( . "$release_file" 2>/dev/null; echo "${VERSION_ID:-}")
  codename=$( . "$release_file" 2>/dev/null; echo "${UBUNTU_CODENAME:-}" | tr '[:upper:]' '[:lower:]')
  major="${version%%.*}"
  [[ "$major" =~ ^[0-9]+$ ]] || major=""

  case "$os_id" in
    openeuler)
      if [[ "$major" = "20" ]]; then echo "openEuler 20 openeuler 1"
      elif [[ "$major" = "22" ]]; then echo "openEuler 22 openeuler 1"
      else echo "openEuler 22 openeuler 0"; fi
      return 0 ;;
    centos|rhel|almalinux|rocky|cloudlinux|ol|eurolinux|navy|miraclelinux|circle|virtuozzo|scientific)
      Universal_Map_EL "$os_id" "$major"; return $? ;;
    fedora)
      Universal_Map_Fedora "$major"; return $? ;;
    amzn)
      if [[ -n "$major" && "$major" -ge 2022 ]]; then echo "CentOS 9 rhel 0"; else echo "CentOS 7 rhel 0"; fi
      return 0 ;;
    ubuntu)
      [[ -n "$major" ]] || return 1
      local lts=$(( major % 2 == 0 ? major : major - 1 ))
      (( lts < 18 )) && lts=18
      (( lts > 26 )) && lts=26
      local native=0
      case "$major" in 18|20|22|24|26) native=1 ;; esac
      echo "Ubuntu $lts debian $native"
      return 0 ;;
  esac

  if [[ "$like" = *" rhel "* || "$like" = *" centos "* ]]; then
    Universal_Map_EL "$os_id" "$major"; return $?
  fi
  if [[ "$like" = *" fedora "* ]]; then
    Universal_Map_Fedora "$major"; return $?
  fi
  if [[ "$like" = *" ubuntu "* ]]; then
    case "$codename" in
      bionic) echo "Ubuntu 18 debian 0" ;;
      focal) echo "Ubuntu 20 debian 0" ;;
      noble) echo "Ubuntu 24 debian 0" ;;
      resolute) echo "Ubuntu 26 debian 0" ;;
      *) echo "Ubuntu 22 debian 0" ;;
    esac
    return 0
  fi
  if [[ "$os_id" = "debian" || "$like" = *" debian "* ]]; then
    # Debian 11 ~ Ubuntu 20.04, 12 ~ 22.04, 13+ ~ 24.04 (closest library baselines).
    if [[ -z "$major" ]]; then echo "Ubuntu 22 debian 0"
    elif (( major <= 11 )); then echo "Ubuntu 20 debian 0"
    elif (( major == 12 )); then echo "Ubuntu 22 debian 0"
    else echo "Ubuntu 24 debian 0"; fi
    return 0
  fi
  return 1
}

Universal_Map_EL() {
  local os_id="$1" major="$2" profile native=0
  [[ -n "$major" ]] && (( major >= 7 )) || return 1
  profile="$major"
  (( profile > 10 )) && profile=10
  case "$os_id:$major" in
    centos:7|centos:8|cloudlinux:7|cloudlinux:8|almalinux:8|almalinux:9|almalinux:10|rocky:8|rhel:8|rhel:9) native=1 ;;
  esac
  echo "CentOS $profile rhel $native"
}

Universal_Map_Fedora() {
  local major="$1"
  [[ -n "$major" ]] || return 1
  # Fedora feeds the next RHEL major: 28 -> EL8, 34 -> EL9, 40 -> EL10.
  if (( major >= 40 )); then echo "CentOS 10 rhel 0"
  elif (( major >= 34 )); then echo "CentOS 9 rhel 0"
  else echo "CentOS 8 rhel 0"; fi
}

# Sets Server_OS, Server_OS_Version, Universal_Family, Universal_Native and the Real_OS_*
# variables, and records the profile for the Python side. CYBERPANEL_OS_PROFILE="CentOS 8"
# forces a profile.
Universal_Detect_OS() {
  local release_file="${UNIVERSAL_OS_RELEASE:-/etc/os-release}"
  local mapped
  if [[ ! -f "$release_file" ]]; then
    echo -e "Unable to detect the operating system: $release_file not found\n"
    return 1
  fi
  Real_OS_ID=$( . "$release_file"; echo "${ID:-unknown}")
  Real_OS_Name=$( . "$release_file"; echo "${PRETTY_NAME:-${NAME:-unknown}}")
  Real_OS_Version=$( . "$release_file"; echo "${VERSION_ID:-}")

  if [[ -n "${CYBERPANEL_OS_PROFILE:-}" ]]; then
    read -r Server_OS Server_OS_Version <<< "$CYBERPANEL_OS_PROFILE"
    case "$Server_OS" in
      CentOS) Universal_Family="rhel" ;;
      Ubuntu) Universal_Family="debian" ;;
      openEuler) Universal_Family="openeuler" ;;
      *) echo "Invalid CYBERPANEL_OS_PROFILE: $CYBERPANEL_OS_PROFILE"; return 1 ;;
    esac
    Universal_Native=0
  elif mapped=$(Universal_Map_Profile "$release_file"); then
    read -r Server_OS Server_OS_Version Universal_Family Universal_Native <<< "$mapped"
  elif command -v apt-get >/dev/null 2>&1; then
    Server_OS="Ubuntu"; Server_OS_Version="22"; Universal_Family="debian"; Universal_Native=0
  elif command -v dnf >/dev/null 2>&1; then
    Server_OS="CentOS"; Server_OS_Version="9"; Universal_Family="rhel"; Universal_Native=0
  elif command -v yum >/dev/null 2>&1; then
    Server_OS="CentOS"; Server_OS_Version="7"; Universal_Family="rhel"; Universal_Native=0
  else
    echo -e "Unsupported system: $Real_OS_Name has neither apt nor dnf/yum.\n"
    return 1
  fi

  if [[ "$Universal_Native" = "1" ]]; then
    Universal_Log "Detected $Real_OS_Name (natively supported profile $Server_OS $Server_OS_Version)"
  else
    Universal_Log "Detected $Real_OS_Name - using compatibility profile $Server_OS $Server_OS_Version"
  fi
  if [[ -z "${UNIVERSAL_DRY_RUN:-}" ]]; then
    mkdir -p "$(dirname "$Universal_Profile_File")" 2>/dev/null
    cat > "$Universal_Profile_File" 2>/dev/null <<EOF
FAMILY=$Universal_Family
PROFILE_OS=$Server_OS
PROFILE_VERSION=$Server_OS_Version
REAL_ID=$Real_OS_ID
REAL_VERSION=$Real_OS_Version
NATIVE=$Universal_Native
EOF
  fi
  return 0
}

# True when $1 is a Python interpreter in [Universal_Min_Python, Universal_Max_Python]
# with a working venv module.
Universal_Python_Usable() {
  local candidate="$1"
  [[ -x "$candidate" ]] || return 1
  env -u PYTHONHOME -u PYTHONPATH "$candidate" - "$Universal_Min_Python" "$Universal_Max_Python" <<'PY' >/dev/null 2>&1
import sys
low = tuple(int(x) for x in sys.argv[1].split('.'))
high = tuple(int(x) for x in sys.argv[2].split('.'))
if not (low <= sys.version_info[:2] <= high):
    sys.exit(1)
import venv, ensurepip  # noqa: F401  (Debian splits these into python3-venv)
PY
}

Universal_Find_Python() {
  local candidate
  for candidate in "${CyberPanel_Python:-}" /usr/bin/python3 /usr/bin/python3.12 /usr/bin/python3.11 \
      /usr/bin/python3.10 /usr/bin/python3.9 /usr/local/bin/python3.12 /usr/local/bin/python3.11; do
    [[ -n "$candidate" ]] || continue
    if Universal_Python_Usable "$candidate"; then
      echo "$candidate"
      return 0
    fi
  done
  return 1
}

# Choose CyberPanel_Python. Keeps upstream's choice when it is usable; otherwise installs
# the newest supported interpreter the distro offers (CentOS 8 -> python39).
Universal_Select_Python() {
  local found pkg minor
  if [[ -n "${CyberPanel_Python:-}" ]] && Universal_Python_Usable "$CyberPanel_Python"; then
    Universal_Log "Using Python $CyberPanel_Python for the panel virtualenvs"
    return 0
  fi

  Universal_Log "System Python is outside $Universal_Min_Python-$Universal_Max_Python; looking for a compatible interpreter"
  if ! found=$(Universal_Find_Python); then
    if [[ "$Universal_Family" = "debian" ]]; then
      DEBIAN_FRONTEND=noninteractive apt-get update -y >/dev/null 2>&1
      for minor in 12 11 10 9; do
        if apt-cache show "python3.$minor" >/dev/null 2>&1; then
          DEBIAN_FRONTEND=noninteractive apt-get install -y "python3.$minor" "python3.$minor-venv" "python3.$minor-dev" \
            && break
        fi
      done
      if ! Universal_Find_Python >/dev/null && grep -qi '^ID=ubuntu' /etc/os-release; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y software-properties-common
        add-apt-repository -y ppa:deadsnakes/ppa && DEBIAN_FRONTEND=noninteractive apt-get update -y
        DEBIAN_FRONTEND=noninteractive apt-get install -y python3.12 python3.12-venv python3.12-dev
      fi
    else
      local manager=yum
      command -v dnf >/dev/null 2>&1 && manager=dnf
      # EL8 ships python3.11/python3.12 from 8.8 and python39 everywhere; EL9+ python3.11/3.12.
      for pkg in python3.12 python3.11 python39; do
        if "$manager" -y install "$pkg" "$pkg-devel" "$pkg-pip" >/dev/null 2>&1 \
            || "$manager" -y install "$pkg" "$pkg-devel" >/dev/null 2>&1; then
          Universal_Find_Python >/dev/null && break
        fi
      done
    fi
    found=$(Universal_Find_Python) || found=""
  fi

  if [[ -z "$found" ]]; then
    echo -e "\nERROR: CyberPanel needs Python $Universal_Min_Python-$Universal_Max_Python and none could be installed."
    echo -e "Install one (for example python3.11 with its venv and dev packages) and re-run.\n"
    Universal_Log "No usable Python found or installable"
    return 1
  fi
  CyberPanel_Python="$found"
  Universal_Python_Changed="Yes"
  Universal_Log "Using Python $CyberPanel_Python for the panel virtualenvs"
  return 0
}

# Create a virtualenv at $1 on CyberPanel_Python.
Universal_Create_Venv() {
  local target="$1"
  mkdir -p "$target"
  if env -u PYTHONHOME -u PYTHONPATH "$CyberPanel_Python" -m venv "$target"; then
    return 0
  fi
  env -u PYTHONHOME -u PYTHONPATH "$CyberPanel_Python" -m pip install --upgrade virtualenv >/dev/null 2>&1
  env -u PYTHONHOME -u PYTHONPATH "$CyberPanel_Python" -m virtualenv -p "$CyberPanel_Python" "$target"
}

# True when the venv at $1 runs a Python inside the supported range.
Universal_Venv_Usable() {
  Universal_Python_Usable "$1/bin/python"
}

# Point lscpd's embedded Python (lswsgi) at the panel virtualenv. Used whenever the panel
# runs on an interpreter other than the system python3, where upstream's
# "PYTHONHOME=/usr + mirror requirements into system Python" approach cannot work.
Universal_Configure_LSCPD_Env() {
  local runtime_root="${1:-/usr/local/CyberCP}"
  local environment_file="${LSCPD_PYTHON_ENV_FILE:-/usr/local/lscp/conf/pythonenv.conf}"
  local home sites
  home=$(env -u PYTHONHOME -u PYTHONPATH "$runtime_root/bin/python" -c 'import sys; print(sys.base_prefix)' 2>/dev/null) || return 1
  sites=$(env -u PYTHONHOME -u PYTHONPATH "$runtime_root/bin/python" -c 'import site; print(":".join(dict.fromkeys(site.getsitepackages())))' 2>/dev/null) || return 1
  mkdir -p "$(dirname "$environment_file")"
  printf 'PYTHONHOME=%s\nPYTHONPATH=.:%s:%s\n' "$home" "$runtime_root" "$sites" > "$environment_file"
  Universal_Log "lscpd Python environment: PYTHONHOME=$home PYTHONPATH=.:$runtime_root:$sites"
}

# Record (for the admin and for support) which upstream features are switched off on this
# host because they conflict with it. The code paths themselves enforce this:
#   custom_ols         - prebuilt OpenLiteSpeed/ModSecurity overlays exist only for upstream's
#                        distro list; other hosts keep stock OLS (installCyberPanel/upgrade
#                        detectPlatform -> 'skip').
#   high_availability  - highAvailability/haManager.py only implements Ubuntu.
Universal_Record_Disabled_Features() {
  local -a disabled=()
  [[ "$Universal_Native" != "1" ]] && disabled+=("custom_ols")
  [[ "$Real_OS_ID" != "ubuntu" ]] && disabled+=("high_availability")
  [[ -n "${UNIVERSAL_DRY_RUN:-}" ]] && { printf '%s\n' "${disabled[@]}"; return 0; }
  mkdir -p "$(dirname "$Universal_Features_File")" 2>/dev/null
  printf '%s\n' "${disabled[@]}" | sed '/^$/d' > "$Universal_Features_File" 2>/dev/null
  Universal_Log "Features disabled on this host: ${disabled[*]:-none}"
}
# <<< universal-compat <<<
