# SpamAssassin

SpamAssassin scores incoming mail and marks likely spam so mailboxes and filters can move it away from the inbox.

## Install

Open **Email > SpamAssassin** (`/emailPremium/SpamAssassin`). If it is not installed, click **Install Now** and wait for the page to reload.

## Settings

- **Report Safe**: wrap spam in an attachment instead of changing the original message.
- **Required Hits** / **Required Score**: the score from which a message counts as spam. The default 5 is a good start; lower it to catch more spam (with more false positives).
- **Rewrite Header**: text added to the subject of spam, for example `***SPAM***`.

Click **Save Changes** after editing.

## Alternatives

[Rspamd Manager](/addons/rspamd/) is a faster, modern filter with Bayes learning, DKIM signing, greylisting and statistics. Use one filter, not both.

## Common problems

- **Good mail marked as spam**: raise the required score slightly, and make sure the sender has SPF and DKIM.
- To see why a message scored high, paste it into the **Spam score** tab of the [Email Debugger](/addons/email-debugger/).
