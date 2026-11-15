# DNS management

The panel runs its own DNS server (PowerDNS). If a domain's nameservers point to this server, you manage its records here. If DNS is hosted elsewhere (registrar, Cloudflare), add the records there instead.

## 1. Nameservers (once per server)

- **Server > Nameservers** (`/dns/createNameserver`): enter your main domain and two nameservers with their IPs, for example `ns1.example.com` and `ns2.example.com`. Then register these as "glue" or "child nameservers" at the domain's registrar.
- **Server > Default Nameservers** (`/dns/configureDefaultNameServers`): the two to four nameservers added to every new zone.

## 2. Zones and records

1. A zone is created automatically with each website. To add one manually, open **Server > DNS Zones** and **Create DNS Zone**, entering the domain without `http://` or `www`.
2. Open **Add/Delete Records** (`/dns/addDeleteDNSRecords`) and **Select Domain**.
3. Choose the record type tab (A, AAAA, CNAME, MX, TXT, SPF, NS, SOA, SRV, CAA), fill in **Name**, **TTL** and the value, and click add.
4. Existing records are listed below; edit or delete them there.
5. At the registrar, set the domain's nameservers to your nameservers. Changes can take up to 24-48 hours to propagate.

## Cloudflare

The Cloudflare page manages records in a Cloudflare account through its API (**CloudFlare Email** and **API Token**), and can sync local records to Cloudflare.

## Reset

**Reset DNS Configurations** restores the default PowerDNS settings. Zones and records are kept.

## Common problems

- **PowerDNS is disabled**: turn it on under **Server > PowerDNS**; see [PowerDNS service](/base/help/powerdns-service).
- **Records do not resolve**: check with `dig @<server-ip> example.com`. If that works, the registrar's nameservers are not pointing here yet.
- For email, add MX, SPF, [DKIM](/base/help/dkim) and DMARC records. The [Email Debugger](/addons/email-debugger/) checks them.
