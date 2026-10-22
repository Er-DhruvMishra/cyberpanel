#!/usr/bin/env sh
# acme.sh DNS-01 hook for CyberPanel Universal.
# Writes _acme-challenge TXT records straight into the panel's PowerDNS database through the
# panel's own DNS models. It never enables or uses the PowerDNS HTTP API.

dns_cpuniversal_add() {
  /usr/local/CyberCP/bin/python /usr/local/CyberCP/universalAddons/sslv2/dnshook.py add "$1" "$2"
}

dns_cpuniversal_rm() {
  /usr/local/CyberCP/bin/python /usr/local/CyberCP/universalAddons/sslv2/dnshook.py rm "$1" "$2"
}
