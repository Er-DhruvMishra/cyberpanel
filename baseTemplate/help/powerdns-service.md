# PowerDNS service

PowerDNS is the DNS server that answers for the zones you manage in the panel. Administrators control it under **Server > PowerDNS** (`/manageservices/managePowerDNS`).

## Turning it on or off

Use **Enable/Disable PowerDNS** and click **Save changes**. Turn it off only if all your domains use external DNS; the DNS pages are unavailable while it is off.

## Function modes

- **Default**: a single DNS server. Use this unless you run several DNS servers.
- **MASTER**: this server holds the zones and sends them to up to three slave servers. Enter each slave's hostname and IP.
- **SLAVE**: this server copies zones from a master. Enter this slave's hostname and the master's IP.

## Common problems

- **Port 53 closed**: open TCP and UDP port 53 in the firewall, and in your provider's firewall.
- **Zone transfers fail** between master and slave: check that each server's IP is entered correctly on both sides and that port 53/TCP is open between them.
- After a broken configuration, use **Reset DNS Configurations**; see [DNS management](/base/help/dns-management).
