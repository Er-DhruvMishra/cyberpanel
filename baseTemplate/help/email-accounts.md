# Email accounts

## Create a mailbox

1. Open **Email > Create Email** (`/email/createEmailAccount`).
2. **Select Website** (the mail domain).
3. Enter the **Email Username** (the part before `@`) and a **Password**, or click **Generate** and **Use This Password**.
4. Click create. Save the password somewhere safe.

## Manage mailboxes

**Email > Email Accounts** (`/email/listEmails`) lists the mailboxes of a domain with their disk usage. From there you can **Change Password** or **Delete** a mailbox (this deletes all its mail and cannot be undone).

## Mail client settings

The same page shows the settings for Outlook, Thunderbird or phones:

- Incoming IMAP: port 993 (SSL) or 143 (STARTTLS); POP3: 995 (SSL) or 110
- Outgoing SMTP: port 587 (STARTTLS) or 465 (SSL), with authentication
- Username: the full email address

Users can also read mail in **Webmail** (`/webmail/`).

## Common problems

- **Certificate warning in the mail client**: the mail server uses a self-signed certificate. Click **Fix SSL Now** on the list page or see [Mail server SSL](/base/help/mail-server-ssl).
- **Mail goes to spam or is not delivered**: run the [Email Debugger](/addons/email-debugger/).
