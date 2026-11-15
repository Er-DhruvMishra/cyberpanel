# Mail server SSL

Postfix and Dovecot need a trusted certificate for the mail hostname, otherwise Outlook, Thunderbird and phones show "self-signed certificate" warnings.

## Steps

1. Make sure the mail hostname (for example `mail.example.com` or the server hostname) has an A record pointing to this server, and that a website exists for it.
2. Open **Security > Mail Server SSL** (`/manageSSL/sslForMailServer`).
3. **Select Website** for that hostname and click **Issue SSL**.
4. Wait for "SSL Issued, your mail server now uses Lets Encrypt!". Postfix and Dovecot are reconfigured to use it.

The [setup wizard](/base/help/onboarding) does this for the server hostname, and is the preferred way on new servers. On **Email > Email Accounts**, **Fix SSL Now** repairs the mail SSL configuration when the page warns about it.

## Mail client settings

Use the same hostname the certificate was issued for as the incoming and outgoing server in the client. Using the IP address or another domain causes a name mismatch warning.

## Common problems

- **Issue fails**: port 80 must be reachable and DNS must already resolve to this server.
- **Warning persists**: restart the mail client; some clients cache the old certificate. Check ports and certificates with the [Email Debugger](/addons/email-debugger/) **Ports & TLS** test.
