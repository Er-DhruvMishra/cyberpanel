# Email Delivery (CyberMail): setup

**Email > Email Delivery** (`/emailDelivery/`) connects this server to CyberMail, an external SMTP relay service run by the CyberPanel vendor. When the relay is on, outgoing mail leaves through their servers instead of directly from your IP. It is optional: the panel's own mail server works without it.

Using it sends your outgoing mail and account details to that third-party service. Decide whether that suits you and your clients before connecting.

## Steps

1. Open **Email Delivery** and click **Get Started Free** to connect an account.
2. On the **Domains** tab, **Add Domain** for each sending domain.
3. Publish the SPF, DKIM and DMARC records the service shows. If the domain's DNS zone is on this server, the panel can add them for you through PowerDNS; otherwise add them at your DNS provider.
4. Verify the domain and wait until it shows as verified.
5. Continue with [Email Delivery: daily use](/base/help/cybermail-guide) to enable the relay.

## Without an external relay

To improve deliverability with your own server, check DNS, reverse DNS, blocklists and TLS with the [Email Debugger](/addons/email-debugger/), and add [DKIM](/base/help/dkim).
