# Apache Manager

By default sites are served by OpenLiteSpeed with LSPHP. A site that needs full Apache behaviour (all `.htaccess` directives, Apache modules) can be served by Apache httpd with PHP-FPM, with OpenLiteSpeed in front.

## Recommended: the Apache Manager add-on

Open [Apache Manager](/addons/apache/) in Universal Add-ons.

1. Under **Prerequisites**, click **Install / configure prerequisites** (Apache and PHP-FPM; needs about 600 MB of free RAM).
2. In **Sites**, choose Apache for a site and click **Preview** to see the change.
3. Click **Apply, reload and health-check**. If the site answers differently afterwards, the change is rolled back automatically.

OpenLiteSpeed keeps ports 80 and 443, TLS and Let's Encrypt; it proxies the site to Apache on 127.0.0.1. Each site gets its own PHP-FPM pool running as the site user. Backups of changed files are kept in `/var/lib/cyberpanel-universal/apache-backups`.

## The per-site page

On servers without a paid CyberPanel licence, the website's Apache Manager button opens the add-on for that site instead.


The website's **Apache Manager** page shows whether the site uses pure OpenLiteSpeed or Apache as a reverse proxy. For Apache sites you can edit the Apache configuration and tune PHP-FPM (`pm.max_children`, `pm.start_servers`, `pm.min_spare_servers`, `pm.max_spare_servers`).

## Common problems

- **Not enough memory**: Apache plus PHP-FPM uses more RAM than LSPHP. Lower `pm.max_children` on small servers.
- Sites on LiteSpeed Enterprise do not need Apache: Enterprise reads `.htaccess` natively.
