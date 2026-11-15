# Onboarding and initial configuration

The setup wizard sets the server hostname, issues a Let's Encrypt certificate for it and prepares the mail server. Run it once on a new server, before you create websites.

## Before you start

- Pick a hostname such as `server.example.com` and create an **A record** for it that points to this server's IP address.
- If this server will send or receive email, ask your hosting provider to set the **reverse DNS (PTR)** of the IP address to the same hostname.

## Steps

1. Open **Settings > Setup Wizard** (`/base/onboarding`).
2. Enter the **Hostname**.
3. Tick **Skip rDNS/PTR Check** only if you will not use email on this server.
4. Click **Start Configurations** and wait for the progress log to finish.
5. Click **Restart CyberPanel**, wait a minute, then reload the page so the browser picks up the new certificate.

After this the panel is reachable at `https://your-hostname:8090` (or the port you set under **Server > Change Port**).

## Common problems

- **rDNS check fails**: the PTR record does not match the hostname yet. Fix it with your provider, or skip the check if you do not need mail.
- **Certificate not issued**: the hostname's A record must resolve publicly to this server and port 80 must be open.
- The older **Hostname SSL** and **Mail Server SSL** pages do the same jobs individually; see [Hostname SSL](/base/help/hostname-ssl).
