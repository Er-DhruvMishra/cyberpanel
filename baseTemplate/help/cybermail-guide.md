# Email Delivery (CyberMail): daily use

After you have connected an account and verified domains ([setup](/base/help/cybermail-setup)), the **Email Delivery** dashboard has these tabs:

- **Domains**: sending domains, their verification state and DNS records.
- **SMTP**: create SMTP credentials for applications, rotate their passwords or delete them.
- **Relay**: turn the Postfix relay on or off. When on, all outgoing mail from this server is routed through the service; when off, the server delivers directly again.
- **Logs** and **Stats**: delivery events, bounces and per-domain statistics.

The header shows your plan and monthly usage. **Refresh** reloads the data; **Disconnect** removes the connection.

## Common problems

- **Mail stops when the plan limit is reached**: turn the relay off to send directly again, or reduce volume.
- **Domain not verified**: the DNS records are missing or not propagated yet.
- Before blaming the relay, test the local side with the [Email Debugger](/addons/email-debugger/) **Send test**.
