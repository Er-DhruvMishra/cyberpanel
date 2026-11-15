# Email forwarding

Forwarding copies incoming mail of a mailbox to another address, or passes it to a program.

## Steps

1. Open **Email > Forwarding** (`/email/emailForwarding`).
2. **Select Website**, then **Select Email Account**.
3. Choose **Forward to email** or **Pipe to program**.
4. Enter the **Destination**: an email address, or the full path of the program (for example a ticket system script).
5. Click **Add Forwarding**. Existing forwardings are listed below with a **Delete** button.

Related pages under **Email**: **Catch-All** (receive mail for unknown addresses of a domain) and **Pattern Forwarding** (rule-based forwarding).

## Common problems

- **Forwarded mail to Gmail or Outlook bounces or lands in spam**: forwarding keeps the original sender, which may fail SPF and DMARC at the destination. Prefer collecting mail by IMAP, or keep forwarding volume low.
- **Pipe does nothing**: the program must be executable and accept the message on standard input.
- Check delivery in the [Email Debugger](/addons/email-debugger/) message trace.
