# Creating a website

A website in this panel is a domain with its own Linux user, home directory `/home/<domain>/`, document root `/home/<domain>/public_html` and OpenLiteSpeed virtual host.

## Steps

1. Open **Websites > Create Website** (`/websites/createWebsite`).
2. **Select Package**: the package sets disk, bandwidth, database, email and FTP limits.
3. **Select Owner**: the panel user (admin, reseller or user) who will manage the site.
4. **Domain Name**: enter `example.com` without `http://` or `www`.
5. **Email**: the contact address of the site owner.
6. **Select PHP Version**.
7. Optional: tick **Create Mail Domain** to prepare email for the domain, and **OpenLiteSpeed + Apache (Backend)** if the site needs Apache (see [Apache Manager](/base/help/apache-manager)).
8. Click **Create Website** and wait for **Website successfully created**.

## After creation

- Point the domain's A record (and `www`) at the server. If DNS is hosted here, see [DNS management](/base/help/dns-management).
- Issue SSL from **Security > Manage SSL**; see [SSL for websites](/base/help/ssl-manager).
- Upload files with the [File Manager](/base/help/file-manager), [FTP](/base/help/ftp) or [SFTP](/base/help/ssh-manager), or deploy [WordPress](/base/help/wordpress-deploy).

## Common problems

- **Invalid Domain**: remove `http://`, `https://`, paths and trailing dots.
- **Package limit reached**: the owner's package allows no more websites; change the package under **Users & Plans**.
- The site shows the default placeholder page until you replace `public_html/index.html`.
