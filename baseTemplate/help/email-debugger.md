# Email Debugger

When mail is not sent, not received or lands in spam, the Email Debugger finds the cause.

## The Email Debugger add-on

Open [Email Debugger](/addons/email-debugger/) in Universal Add-ons. Its tabs:

- **DNS & reputation**: checks MX, mail host, SPF, DKIM, DMARC, reverse DNS and major blocklists for a domain.
- **Ports & TLS**: connects to ports 25, 465, 587, 993, 995, 143 and 110, either on this server or its public IP, negotiates TLS and inspects each certificate. This is also the SMTP connection test.
- **Message trace**: searches the Postfix log by status (sent, deferred, bounced, expired) and address.
- **Queue**: shows what is waiting; flush or delete it under **Email > Mail Queue**.
- **Spam score**: paste a full message source to score it with Rspamd or SpamAssassin.
- **Send test**: sends one message through local Postfix and follows it in the log.

## The built-in page

On servers without a paid CyberPanel licence, this menu entry opens the add-on above instead.


**Email > Email Debugger** (`/emailPremium/EmailDebugger`) runs server-level checks (mail server SSL and ports), can **Reset Server wide Email Configurations**, and offers **Fix Now** / **Force Fix** for one website's mail settings.

## Typical findings

- Port 25 outbound closed: ask your provider to unblock it.
- Missing SPF, DKIM or DMARC: add them; see [DKIM](/base/help/dkim) and [DNS management](/base/help/dns-management).
- IP on a blocklist: stop the source of spam, then request delisting from that list.
