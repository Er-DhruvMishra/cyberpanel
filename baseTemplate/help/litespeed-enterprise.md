# Switching to LiteSpeed Enterprise

The panel runs on the free OpenLiteSpeed web server. LiteSpeed Enterprise is a paid web server from LiteSpeed Technologies with native `.htaccess` support and other features. Containerization in this panel also requires Enterprise.

## Before you switch

- You need a LiteSpeed Enterprise licence key, or you can use a 15-day trial.
- **You cannot switch back to OpenLiteSpeed** from the panel. If you do not buy a licence after the trial, the web server stops working. Test on a separate server first.
- A licence must include the CyberPanel bundle; the status page warns when it does not.

## Steps

1. Open **Server > LiteSpeed Status** (`/serverstatus/litespeedStatus`).
2. Under **Upgrade to LiteSpeed Enterprise**, enter the licence key, or click **Get 15 Days Trial**.
3. Click **Switch to Enterprise** and follow the **Installation Progress**.

On Enterprise, the same page has a **License Manager** to view, change or refresh the licence.

## Alternatives on OpenLiteSpeed

For Apache-style `.htaccess` without Enterprise, use [.htaccess for OpenLiteSpeed](/addons/htaccess/) or [Apache Manager](/addons/apache/).
