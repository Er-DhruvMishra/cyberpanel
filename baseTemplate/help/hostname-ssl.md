# Hostname SSL (panel certificate)

The panel is served at `https://<hostname>:8090`. A Let's Encrypt certificate for the hostname removes browser warnings and is needed for the Web Terminal.

## Preferred: setup wizard

The [setup wizard](/base/help/onboarding) sets the hostname and issues its certificate in one go.

## Hostname SSL page

1. Create a website for the hostname (for example `server.example.com`) and make sure its A record points to this server.
2. Open **Security > Hostname SSL** (`/manageSSL/sslForHostName`).
3. **Select Website** and click **Issue SSL**.
4. When it finishes, open the panel at `https://<hostname>:8090`.

## Common problems

- **Still a warning**: you are opening the panel by IP address. Certificates cover names, not IPs; use the hostname.
- **Issue fails**: port 80 must be open and the hostname must resolve publicly to this server.
- If you changed the panel port under **Server > Change Port**, use that port instead of 8090.
