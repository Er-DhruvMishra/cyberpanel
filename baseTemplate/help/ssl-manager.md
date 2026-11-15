# SSL for websites

Every website can get a free Let's Encrypt certificate. Certificates renew automatically before they expire.

## Issue a certificate

1. Point the domain (and `www`) to this server and wait until DNS resolves.
2. Open **Security > Manage SSL** (`/manageSSL/manageSSL`).
3. **Select Website**. The page shows the current certificate: status, issuer, expiry date and days remaining.
4. Click **Issue SSL** and keep the page open; it can take a few minutes.

You can also paste your own certificate and private key with **Add SSL** on the website's page.

## Wildcards and DNS validation

[SSL V2](/addons/ssl/) in Universal Add-ons issues wildcard and DNS-01 certificates, lists all certificates and monitors renewals.

## Common problems

- **Cannot issue SSL**: the domain does not resolve to this server, port 80 is closed, or a CDN/proxy answers instead of this server. Pause the proxy while issuing, or use DNS validation in SSL V2.
- **Rate limited**: Let's Encrypt limits repeated failures; fix the cause and wait an hour.
- After issuing, make the site redirect to HTTPS; see [Rewrite rules](/base/help/rewrite-rules).
