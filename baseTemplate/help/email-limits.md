# Email limits

Email limits cap how many messages a domain or mailbox may send, which stops a hacked mailbox or script from sending spam from your IP.

## Recommended: the Email Limits add-on

Open [Email Limits](/addons/email-limits/) in Universal Add-ons.

- Limits are enforced by the policy daemon `cpecs` when Postfix accepts a message.
- Set a **Monthly** and **Hourly** limit per domain and per mailbox, and use **Apply to all mailboxes** to copy a domain's values.
- A mailbox is limited only while both its own limit and its domain's limit are on.
- Counters reset every hour and on the first of each month. The **Health** panel checks the daemon and can **Repair cron entries** for the counter resets.
- The administrator can let resellers and users manage limits of their own domains.

## Built-in pages

On servers without a paid CyberPanel licence, **Email > Email Limits** opens the add-on above instead.


- **Email > Email Limits** (`/email/EmailLimits`): choose a website and mailbox, then set **Number of Emails** per **Duration**.
- The **Email Policy Server** (`/emailPremium/emailPolicyServer`) must be on for limits to be enforced; the domain list (`/emailPremium/listDomains`) shows monthly limits and usage per domain.

## Common problems

- **Limits not applied**: the policy server is off, or Postfix is not configured to call it. The add-on's **Health** check shows which.
- **"A saved rate limit could not be read"**: the stored value is damaged; save the limit again.
- Panel upgrades can replace the policy daemon; re-check **Health** after an upgrade.
