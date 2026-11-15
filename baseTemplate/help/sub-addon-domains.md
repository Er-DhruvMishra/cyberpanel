# Sub-domains and addon domains

Sub and addon domains (also called child domains) are extra domains that belong to an existing website and share its Linux user and package.

- **Sub Domain**: a name under the website's domain, for example `shop.example.com`.
- **Addon Domain**: a different domain, for example `example.net`, served from the same account.

## Steps

1. Create the parent website first.
2. Open **Websites > Create Sub / Addon Domain** (`/websites/CreateNewDomain`).
3. Choose the **Domain Type** and **Select Website** (the parent).
4. Enter the **Domain Name**.
5. **Document Root Path**: the folder under `/home/<parent>/` that will hold the files, for example `/home/example.com/shop`.
6. **Select PHP Version**, optionally tick **OpenLiteSpeed + Apache (Backend)**, and click **Create Domain**.

## Managing them

All child domains are listed under **Websites > Sub / Addon Domains**. Open one to manage it; see [Child domains](/base/help/child-domains).

## Common problems

- **You need to create a website before creating Sub/Addon domains**: create the parent site first.
- The new domain needs its own DNS record (A or CNAME) pointing at the server, and its own SSL certificate.
