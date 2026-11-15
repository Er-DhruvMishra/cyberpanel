# Deploying WordPress

You can create a new website with WordPress in one step, or install WordPress into an existing website.

## New WordPress site

1. Open **WordPress > Deploy WordPress** (`/websites/createWordpress`).
2. Enter the **Domain Name**, **Site Title**, **Package** and **Owner**.
3. Fill in the administrator account: **Admin Username**, **Admin Email** and **Admin Password** (use **Generate** for a strong one).
4. Choose the **WordPress Version** and optionally a **Plugin/Theme Bundle**.
5. Set **Update Settings** for core, plugin and theme updates.
6. Click deploy and wait for **WordPress site has been successfully deployed**.

The panel creates the website, database, and WordPress install, and the site is listed under **WordPress > WordPress Sites**.

## Into an existing website

On the website's page, open the **Application Installer** and choose WordPress. Enter **Blog Title**, **Login User**, **Login Password**, **Email** and optionally a **Path** such as `blog` (no leading slash). Leave the path empty to install in the document root, which should be empty.

## More tools

On servers without a paid CyberPanel licence, **Deploy WordPress** and **WordPress Sites** open [WordPress Manager Pro](/addons/wordpress/) from Universal Add-ons instead. It also adds cloning, staging, push to production, safe auto-updates and hardening.

## Common problems

- **Installation failed**: the target folder is not empty, or the package has no database left.
- Issue SSL for the domain and then set the WordPress address to `https://` under **Settings > General** in WordPress.
