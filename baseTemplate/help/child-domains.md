# Managing a child domain

Each sub or addon domain has its own management page, opened from **Websites > Sub / Addon Domains**. Its master (parent) website is shown at the top.

## What you can do

- **Resource cards**: storage, bandwidth, databases and FTP accounts. Usage counts against the parent website's package.
- **Logs**: load the access and error logs of the child domain.
- **Configurations**: edit the **vHost Conf**, open the [Apache Manager](/base/help/apache-manager), edit [Rewrite Rules](/base/help/rewrite-rules), **Add SSL** (paste your own certificate and key) and **Change PHP**.
- **Files**: open the File Manager, create or delete FTP accounts, and turn **open_basedir Protection** on or off.
- **Application Installer**: install WordPress, Prestashop or attach a Git repository.
- **Manage Git** and **Sync to Master** in the quick actions bar.

## Common problems

- **SSL shows the parent certificate**: issue SSL for the child domain itself under **Security > Manage SSL**.
- **open_basedir errors** after moving files outside the document root: keep files inside the child's path, or disable protection.
