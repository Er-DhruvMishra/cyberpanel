# Rewrite rules

Rewrite rules redirect or rewrite URLs, for example to force HTTPS or to give an application clean URLs. OpenLiteSpeed reads them from the site's `.htaccess` file.

## Editing rules

1. Open the website's page and, under **Configurations**, click **Rewrite Rules**.
2. The current contents of `/home/<domain>/public_html/.htaccess` are loaded (for a child domain, the `.htaccess` in its document root).
3. Optionally pick a ready-made template from the list, then edit the rules.
4. Click **Save Rewrite Rules**. The panel writes the file and restarts OpenLiteSpeed gracefully so the rules take effect.

## Example: force HTTPS

```
RewriteEngine On
RewriteCond %{HTTPS} !=on
RewriteRule ^(.*)$ https://%{HTTP_HOST}/$1 [R=301,L]
```

## What OpenLiteSpeed supports

OpenLiteSpeed applies `RewriteEngine`, `RewriteCond` and `RewriteRule` from `.htaccess`. Other Apache directives (such as `php_value`, `Header` or `Require`) are ignored. For those:

- [.htaccess for OpenLiteSpeed](/addons/htaccess/) translates many Apache directives into OpenLiteSpeed configuration;
- [Apache Manager](/addons/apache/) serves the site through Apache for full `.htaccess` support.

## Common problems

- **Rules seem to have no effect**: edits made directly to `.htaccess` (by FTP or a plugin) need an OpenLiteSpeed restart; saving here does that for you.
- **Redirect loop**: check that a CDN or proxy in front of the site does not already redirect to HTTPS.
