# Email on this server

Email uses **Postfix** to send and receive (SMTP) and **Dovecot** for mailboxes (IMAP and POP3). Mailboxes belong to a website's domain.

## Turning email on

Administrators enable the mail service under **Server > Postfix** (`/manageservices/managePostfix`). The email pages show "Postfix is disabled" until it is on.

## Getting a domain ready

1. Create the website, ticking **Create Mail Domain**.
2. Create mailboxes; see [Email accounts](/base/help/email-accounts).
3. Add DNS records: MX pointing to the mail hostname, an SPF TXT record, [DKIM](/base/help/dkim) and a DMARC record.
4. Install a certificate for the mail hostname; see [Mail server SSL](/base/help/mail-server-ssl).
5. Make sure reverse DNS (PTR) of the server IP matches the hostname.

## Ports

- SMTP 25, submission 587 (STARTTLS), SMTPS 465
- IMAP 143 / 993 (SSL), POP3 110 / 995 (SSL)
- Sieve 4190 (filters)

Many cloud providers block outbound port 25 by default; ask them to open it.

## Panel notification mail

The **Server Mail** page (`/serverlogs/serverMail`) chooses how the panel itself sends notifications and error emails: **Default (System Mail)** or **SMTP (Custom Server)** with host, port, username and password.

## Tools

- [Email Debugger](/addons/email-debugger/) for DNS, ports, TLS, queue and log tracing.
- [Email Limits](/addons/email-limits/) to cap outbound mail.
- [Mail queue](/base/help/email-queue) and [SpamAssassin](/base/help/spamassassin).
