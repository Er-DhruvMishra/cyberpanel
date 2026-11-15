# Web Terminal

The Web Terminal opens a shell in your browser as the website's own Linux user, in the site's home directory. Use it for `composer`, `wp-cli`, `npm`, `git` and similar tools.

## Opening a terminal

- From a website's page, click **Open Terminal**, or
- open [Web Terminal](/addons/terminal/) in Universal Add-ons, choose the **Website** and click **Connect**.

Administrators may also open a **root shell** there.

## First-time setup (administrator)

On the Web Terminal add-on page, choose which site carries the connections and click **Set up / refresh**. The terminal service listens on 127.0.0.1 only; OpenLiteSpeed forwards `wss://<site>/cp-webterm/ws` to it over the site's existing HTTPS, so no new port is opened. Use the switches to allow website owners (resellers and users) to open terminals for their own sites.

## Limits

Sessions end after 15 minutes without input or after 2 hours. Starts and stops are logged; keystrokes are not.

## Common problems

- **Terminal does not connect**: the carrying site needs a valid SSL certificate, and you should open the panel by hostname, not by IP address.
- **Command not found**: the site user has a minimal `PATH`; use full paths such as `/usr/local/lsws/lsphp81/bin/php`.
