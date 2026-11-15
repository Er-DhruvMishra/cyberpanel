# Mail queue

Messages Postfix cannot deliver right away wait in the queue and are retried. A large or growing queue usually means a delivery problem, or spam leaving a hacked account.

## Using the queue page

Open **Email > Mail Queue** (`/emailPremium/mailQueue`).

- **Refresh** shows the current queue: queue name, size, sender and recipients.
- **View Message** shows a queued message with its headers and the last delivery error.
- **Flush Queue** retries delivery of all messages now.
- **Delete Deferred** removes only messages that are waiting for a retry.
- **Delete All** empties the whole queue. This cannot be undone.

## Reading the cause

- **Connection timed out on port 25**: your provider blocks outbound SMTP.
- **Blocked / listed / 5.7.1**: the server IP is on a blocklist, or SPF, DKIM or reverse DNS is missing.
- **Thousands of messages from one sender**: that mailbox or a website script is sending spam. Change the password, clean the site, and set [Email limits](/base/help/email-limits).

## Tools

The [Email Debugger](/addons/email-debugger/) **Queue** and **Message trace** tabs follow a message through the Postfix log, and its **DNS & reputation** tab checks blocklists.
