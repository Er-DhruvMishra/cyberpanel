# DKIM

DKIM signs outgoing mail with a private key; receivers check the signature with the public key published in DNS. It improves deliverability and prevents spoofing.

## Steps

1. Open **Email > DKIM Manager** (`/email/dkimManager`).
2. If you see **OpenDKIM is not installed**, click **Install OpenDKIM Now** and wait for the page to reload.
3. **Select Website**. If no keys exist, click **Generate DKIM Keys**.
4. The **Public Key** must be published as a TXT record named `default._domainkey.<domain>`. If the domain's DNS zone is on this server, the panel adds or updates that record for you.
5. If DNS is hosted elsewhere, copy the public key into a TXT record named `default._domainkey` at your DNS provider.

Keep the **Private Key** secret; never put it in DNS.

## Check it

Send a message to a Gmail address and look for `dkim=pass` in "Show original", or use the DNS checks of the [Email Debugger](/addons/email-debugger/).

## Common problems

- **dkim=fail**: the DNS record is truncated or has extra quotes or spaces; paste it again in one piece.
- **No signature at all**: OpenDKIM is not running or the domain has no keys; generate them again.
