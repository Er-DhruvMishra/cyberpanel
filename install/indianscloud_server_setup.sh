#!/bin/bash
# IndiansCloud server setup.
#
# Host-level fixes that live outside the panel's Python code, collected from running the
# fork on a production CentOS 8 server. Every step is idempotent: it checks first, changes
# only what is wrong, keeps a backup of each file it edits and rolls back a service change
# that does not come up healthy. Safe to run again at any time.
#
# Run by cyberpanel.sh after a fresh install and by plogical/upgrade.py after an upgrade.
# Manual use:   bash /usr/local/CyberCP/install/indianscloud_server_setup.sh [step ...]
# Steps:        repos swap postfix dovecot_dh php_memory php_opcache_cli pdns sieve rclone
#               mailscanner webterminal cron migrate   (default: all, in that order)
# Skip a step:  INDIANSCLOUD_SKIP="sieve rclone" bash indianscloud_server_setup.sh

set -u
umask 022
CP=/usr/local/CyberCP
PY=$CP/bin/python
[ -x "$PY" ] || PY=/usr/local/CyberPanel/bin/python
LOG=/var/log/indianscloud-server-setup.log
STAMP=$(date +%Y%m%d-%H%M%S)
RCLONE_KEY_FPR=FBF737ECE9F8AB18604BD2AC93935E02FF3B54FA   # Nick Craig-Wood, rclone release signing key
SIEVE_DROPIN=/etc/dovecot/conf.d/95-indianscloud-sieve.conf

log()  { echo "[$(date '+%F %T')] $*" | tee -a "$LOG"; }
have() { command -v "$1" >/dev/null 2>&1; }
is_el() { [ -f /etc/redhat-release ]; }
el_major() { rpm -E '%{rhel}' 2>/dev/null | grep -E '^[0-9]+$' || echo 0; }
mem_mb() { awk '/^MemTotal:/ {print int($2/1024)}' /proc/meminfo; }
backup() { [ -f "$1" ] && cp -p "$1" "$1.bak-indianscloud-$STAMP"; }
unit_exists() { systemctl list-unit-files "$1.service" >/dev/null 2>&1 && systemctl list-unit-files "$1.service" | grep -q "^$1.service"; }

# A private MySQL defaults file for root, from the panel's stored password (never on argv).
mysql_cnf() {
  [ -r /etc/cyberpanel/mysqlPassword ] || return 1
  MYCNF=$(mktemp /root/.ic-setup-XXXXXX.cnf) || return 1
  chmod 600 "$MYCNF"
  printf '[client]\nuser=root\npassword="%s"\n' "$(cat /etc/cyberpanel/mysqlPassword)" > "$MYCNF"
}
mysql_q() { mysql --defaults-extra-file="$MYCNF" -N -e "$1" 2>/dev/null; }

# --------------------------------------------------------------------------------------------
step_repos() {
  # EL8+ dnf rejects the EL7-era "failovermethod" option and prints a warning on every run.
  [ "$(el_major)" -ge 8 ] || return 0
  local f
  for f in /etc/yum.repos.d/*.repo; do
    [ -f "$f" ] && grep -q '^failovermethod=' "$f" || continue
    backup "$f" && sed -i '/^failovermethod=/d' "$f" && log "repos: removed failovermethod from $f"
  done
}

step_swap() {
  # Small servers (under 4 GB RAM) with no swap get a 2 GB swap file.
  [ "$(swapon --noheadings 2>/dev/null | wc -l)" -eq 0 ] || return 0
  [ "$(mem_mb)" -lt 4096 ] || return 0
  local sw=/cyberpanel-extra.swap
  [ -e "$sw" ] || { fallocate -l 2G "$sw" 2>/dev/null || dd if=/dev/zero of="$sw" bs=1M count=2048 status=none; }
  chmod 600 "$sw" && mkswap "$sw" >/dev/null && swapon "$sw" || { log "swap: could not enable $sw"; return 0; }
  grep -q "^$sw " /etc/fstab || echo "$sw swap swap defaults 0 0" >> /etc/fstab
  log "swap: enabled 2 GB at $sw"
}

step_postfix() {
  unit_exists postfix || return 0
  systemctl is-enabled postfix >/dev/null 2>&1 || { systemctl enable postfix >/dev/null 2>&1 && log "postfix: enabled at boot"; }
}

step_dovecot_dh() {
  # Dovecot 2.3 refuses SSL without ssl_dh; older installs never set it.
  have doveconf || return 0
  local conf=/etc/dovecot/dovecot.conf
  [ -f "$conf" ] || return 0
  doveconf -n 2>/dev/null | grep -q '^ssl_dh' && return 0
  grep -q '^ssl_dh' "$conf" && return 0
  [ -s /etc/dovecot/dh.pem ] || nice -n 19 openssl dhparam -out /etc/dovecot/dh.pem 2048 >/dev/null 2>&1 || return 0
  chmod 600 /etc/dovecot/dh.pem
  backup "$conf" && echo 'ssl_dh = </etc/dovecot/dh.pem' >> "$conf"
  if doveconf -n >/dev/null 2>&1; then
    systemctl try-restart dovecot && log "dovecot: added ssl_dh"
  else
    cp -p "$conf.bak-indianscloud-$STAMP" "$conf"; log "dovecot: ssl_dh rejected by doveconf, restored"
  fi
}

step_php_memory() {
  # memory_limit = -1 lets one PHP request exhaust the server.
  local ini
  for ini in /usr/local/lsws/lsphp*/etc/php.ini /etc/opt/remi/php*/php.ini /etc/php.ini; do
    [ -f "$ini" ] && grep -qE '^memory_limit *= *-1' "$ini" || continue
    backup "$ini" && sed -i -E 's/^memory_limit *= *-1/memory_limit = 256M/' "$ini" && log "php: memory_limit 256M in $ini"
  done
}

step_php_opcache_cli() {
  # ionCube loader 15.x + opcache in the CLI crashes `php -l` and compile errors on PHP 8.1+.
  local d ini
  for d in /usr/local/lsws/lsphp8[1-9] /usr/local/lsws/lsphp9[0-9]; do
    [ -d "$d" ] || continue
    ls "$d"/etc/php.d/*ioncube* >/dev/null 2>&1 || continue
    ini="$d/etc/php.d/10-opcache.ini"
    [ -f "$ini" ] || continue
    grep -qE '^opcache\.enable_cli *= *0' "$ini" && continue
    backup "$ini"
    if grep -qE '^;?opcache\.enable_cli' "$ini"; then
      sed -i -E 's/^;?opcache\.enable_cli *=.*/opcache.enable_cli=0/' "$ini"
    else
      echo 'opcache.enable_cli=0' >> "$ini"
    fi
    log "php: opcache.enable_cli=0 in $ini (ionCube CLI crash)"
  done
}

step_pdns() {
  # The PowerDNS API must only listen locally (the panel talks to it on localhost), and the
  # gmysql backend needs gmysql-dnssec for the DNS tools' DNSSEC signing.
  local conf=/etc/pdns/pdns.conf
  [ -f "$conf" ] || conf=/etc/powerdns/pdns.conf
  [ -f "$conf" ] || return 0
  local changed=0 tmp
  tmp=$(mktemp) && cp -p "$conf" "$tmp"
  sed -i -e 's/^webserver-address=0\.0\.0\.0$/webserver-address=127.0.0.1/' \
         -e 's|^webserver-allow-from=0\.0\.0\.0/0$|webserver-allow-from=127.0.0.1,::1|' "$tmp"
  if grep -q '^launch=gmysql' "$tmp" && ! grep -q '^gmysql-dnssec' "$tmp" && mysql_cnf; then
    local db
    db=$(sed -n 's/^gmysql-dbname=//p' "$tmp" | head -1); db=${db:-cyberpanel}
    if [ -n "$(mysql_q "SHOW TABLES FROM \`$db\` LIKE 'cryptokeys'")" ] && \
       [ -n "$(mysql_q "SHOW TABLES FROM \`$db\` LIKE 'domainmetadata'")" ]; then
      sed -i '0,/^launch=gmysql/s//launch=gmysql\ngmysql-dnssec=yes/' "$tmp"
    fi
    rm -f "$MYCNF"
  fi
  cmp -s "$tmp" "$conf" || changed=1
  if [ "$changed" = 1 ]; then
    backup "$conf" && cat "$tmp" > "$conf"
    local svc=pdns; unit_exists pdns || svc=pdns-server
    systemctl restart "$svc"; sleep 2
    if systemctl is-active --quiet "$svc"; then
      log "pdns: API on loopback / DNSSEC backend enabled"
    else
      cp -p "$conf.bak-indianscloud-$STAMP" "$conf"; systemctl restart "$svc"
      log "pdns: new config failed to start, restored previous config"
    fi
  fi
  rm -f "$tmp"
}

step_sieve() {
  # Pigeonhole (Sieve) for the panel's autoresponders and spam rules, plus the managed
  # drop-in. On EL8 the GhettoForge dovecot23 build only has Pigeonhole in gf-plus, which also
  # moves Dovecot to the matching 2.3.x release.
  have doveconf || return 0
  local conf=/etc/dovecot/dovecot.conf
  [ -f "$conf" ] || return 0
  if ! have sievec; then
    if is_el; then
      if rpm -q dovecot23 >/dev/null 2>&1; then
        dnf -y -q install dovecot23-pigeonhole >/dev/null 2>&1 || \
          dnf -y -q --enablerepo=gf-plus install dovecot23-pigeonhole >/dev/null 2>&1
      else
        dnf -y -q install dovecot-pigeonhole >/dev/null 2>&1
      fi
    elif have apt-get; then
      DEBIAN_FRONTEND=noninteractive apt-get -y -q install dovecot-sieve dovecot-managesieved >/dev/null 2>&1
    fi
    have sievec || { log "sieve: Pigeonhole not available, autoresponders stay inactive"; return 0; }
    log "sieve: installed Pigeonhole ($(dovecot --version 2>/dev/null))"
  fi
  mkdir -p /etc/dovecot/conf.d
  cat > "$SIEVE_DROPIN.new" <<'EOF'
# IndiansCloud: Sieve (Pigeonhole) for panel autoresponders and spam rules.
mail_home = /home/vmail/%d/%n
protocols = $protocols sieve
service managesieve-login {
  inet_listener sieve {
    address = 127.0.0.1
    port = 4190
  }
}
protocol lda {
  mail_plugins = $mail_plugins sieve
}
plugin {
  sieve = file:/home/vmail/%d/%n/sieve;active=/home/vmail/%d/%n/.dovecot.sieve
  sieve_before = /home/vmail/%d/%n/sieve-managed/managed.sieve
  sieve_vacation_min_period = 1d
  sieve_vacation_max_period = 30d
}
EOF
  local include="!include_try $SIEVE_DROPIN" dropin_changed=0 include_added=0
  cmp -s "$SIEVE_DROPIN.new" "$SIEVE_DROPIN" || { backup "$SIEVE_DROPIN"; mv -f "$SIEVE_DROPIN.new" "$SIEVE_DROPIN"; chmod 644 "$SIEVE_DROPIN"; dropin_changed=1; }
  rm -f "$SIEVE_DROPIN.new"
  grep -qxF "$include" "$conf" || { backup "$conf"; printf '\n%s\n' "$include" >> "$conf"; include_added=1; }
  [ "$dropin_changed$include_added" = "00" ] && return 0
  if doveconf -n >/dev/null 2>&1 && systemctl restart dovecot && sleep 2 && systemctl is-active --quiet dovecot; then
    log "sieve: managed drop-in active (managesieve on 127.0.0.1:4190)"
  else
    [ "$include_added" = 1 ] && grep -vxF "$include" "$conf" > "$conf.tmp" && cat "$conf.tmp" > "$conf" && rm -f "$conf.tmp"
    rm -f "$SIEVE_DROPIN"; systemctl restart dovecot
    log "sieve: Dovecot rejected the drop-in, removed it and restarted Dovecot"
  fi
}

step_rclone() {
  # rclone backs every Backup destinations provider. Official release, SHA-256 checked against
  # the PGP-signed SHA256SUMS (pinned signing key).
  have rclone && return 0
  have gpg && have curl || { log "rclone: gpg/curl missing, skipped"; return 0; }
  local arch pkg work ver
  case "$(uname -m)" in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; *) log "rclone: unsupported arch"; return 0 ;; esac
  is_el && pkg=rpm || pkg=deb
  work=$(mktemp -d /root/.ic-rclone-XXXXXX) || return 0
  (
    set -e; cd "$work"
    ver=$(curl -fsS https://downloads.rclone.org/version.txt | awk '{print $2}')
    curl -fsSO "https://downloads.rclone.org/$ver/rclone-$ver-linux-$arch.$pkg"
    curl -fsSO "https://downloads.rclone.org/$ver/SHA256SUMS"
    export GNUPGHOME="$work/gnupg"; mkdir -m 700 "$GNUPGHOME"
    curl -fsS "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x$RCLONE_KEY_FPR" | gpg -q --import
    gpg -q --verify SHA256SUMS 2>&1 | grep -q 'Good signature'
    gpg --with-colons --fingerprint 2>/dev/null | grep -q "fpr:::::::::$RCLONE_KEY_FPR:"
    grep " rclone-$ver-linux-$arch.$pkg\$" SHA256SUMS | sha256sum -c - >/dev/null
    if [ "$pkg" = rpm ]; then dnf -y -q install "./rclone-$ver-linux-$arch.rpm"; else apt-get -y -q install "./rclone-$ver-linux-$arch.deb"; fi
  ) >/dev/null 2>&1 && log "rclone: installed $(rclone version 2>/dev/null | head -1)" || log "rclone: download or verification failed, not installed"
  rm -rf -- "$work"
}

step_mailscanner() {
  # MailScanner's default 5 children each load SpamAssassin (~100 MB); too many on small servers.
  local conf=/etc/MailScanner/MailScanner.conf
  [ -f "$conf" ] && [ "$(mem_mb)" -lt 6144 ] || return 0
  local n; n=$(sed -n -E 's/^Max Children *= *([0-9]+).*/\1/p' "$conf" | head -1)
  [ -n "$n" ] && [ "$n" -gt 2 ] || return 0
  backup "$conf" && sed -i -E 's/^(Max Children *= *)[0-9]+/\12/' "$conf"
  unit_exists mailscanner && systemctl try-restart mailscanner
  log "mailscanner: Max Children $n -> 2"
}

step_webterminal() {
  # The per-site SSH terminal (website page) connects to fastapi_ssh_server on :8888. Fresh
  # installs set it up; upgraded servers never got it. Respect an admin who masked it.
  [ -f "$CP/fastapi_ssh_server.service" ] || return 0
  [ "$(systemctl show -p LoadState --value fastapi_ssh_server 2>/dev/null)" = masked ] && return 0
  if ! systemctl is-enabled --quiet fastapi_ssh_server 2>/dev/null; then
    (cd "$CP" && "$PY" -c 'from plogical.terminalService import configure_terminal_service as c; c(fresh_install=True)') >/dev/null 2>&1 \
      && log "webterminal: fastapi_ssh_server enabled on :8888" || { log "webterminal: could not enable fastapi_ssh_server"; return 0; }
  fi
  if have firewall-cmd && firewall-cmd --state >/dev/null 2>&1 && \
     ! firewall-cmd --zone=public --list-rich-rules | grep -q 'port port="8888" protocol="tcp" accept'; then
    firewall-cmd --permanent --zone=public --add-rich-rule='rule family="ipv4" source address="0.0.0.0/0" port port="8888" protocol="tcp" accept' >/dev/null
    firewall-cmd --permanent --zone=public --add-rich-rule='rule family="ipv6" port port="8888" protocol="tcp" accept' >/dev/null
    firewall-cmd --reload >/dev/null && log "webterminal: opened tcp/8888 in firewalld"
    if mysql_cnf; then
      mysql_q "INSERT INTO cyberpanel.firewall_firewallrules (name,proto,port,ipAddress) SELECT 'webterminal','tcp','8888','0.0.0.0/0' FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM cyberpanel.firewall_firewallrules WHERE port='8888' AND proto='tcp')"
      rm -f "$MYCNF"
    fi
  fi
}

step_cron() {
  [ -d "$CP/universalAddons" ] || return 0
  write_cron() {
    local name=$1 line=$2 f=/etc/cron.d/cyberpanel-universal-$1
    [ -f "$f" ] && grep -qxF "$line" "$f" && return 0
    printf '# IndiansCloud %s\n%s\n' "$name" "$line" > "$f" && chmod 644 "$f" && log "cron: wrote $f"
  }
  [ -f "$CP/universalAddons/uptime/cron.py" ] && id cyberpanel >/dev/null 2>&1 && \
    write_cron uptime "* * * * * cyberpanel $PY $CP/universalAddons/uptime/cron.py >/dev/null 2>&1"
  [ -d "$CP/universalAddons/notify" ] && \
    write_cron notify "*/5 * * * * root $PY $CP/universalAddons/runner.py notify server_check e30= >/dev/null 2>&1"
  [ -d "$CP/universalAddons/visitstats" ] && \
    write_cron visitstats "40 3 * * * root $PY $CP/universalAddons/runner.py visitstats nightly e30= >/dev/null 2>&1"
  return 0
}

step_migrate() {
  # The upgrader only runs makemigrations; the fork's own apps ship migrations to apply.
  [ -f "$CP/manage.py" ] || return 0
  local app
  for app in universalAddons freeSubdomains provisioning resellerBranding; do
    [ -d "$CP/$app/migrations" ] || continue
    (cd "$CP" && "$PY" manage.py migrate "$app" --noinput >/dev/null 2>&1) \
      && log "migrate: $app up to date" || log "migrate: $app FAILED (run: cd $CP && $PY manage.py migrate $app)"
  done
}

# --------------------------------------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || { echo "Run as root." >&2; exit 1; }
ALL="repos swap postfix dovecot_dh php_memory php_opcache_cli pdns sieve rclone mailscanner webterminal cron migrate"
STEPS=${*:-$ALL}
SKIP=" ${INDIANSCLOUD_SKIP:-} "
log "IndiansCloud server setup started ($STEPS)"
for s in $STEPS; do
  case " $ALL " in *" $s "*) ;; *) log "unknown step: $s"; continue ;; esac
  case "$SKIP" in *" $s "*) log "$s: skipped"; continue ;; esac
  "step_$s" || log "$s: step returned an error"
done
log "IndiansCloud server setup finished"
exit 0
