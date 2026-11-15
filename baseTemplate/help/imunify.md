# Imunify360 and ImunifyAV

Imunify360 (paid, from CloudLinux) is a security suite with a web application firewall, malware scanning and patching. ImunifyAV is its free malware scanner.

## Install

- **Security > Imunify 360** (`/firewall/imunify`): enter your **Imunify Key** (licence) and click install.
- **Security > ImunifyAV** (`/firewall/imunifyAV`): click **Install Now**. No key is needed.

## Use

After installation the page shows **Access Now**. It opens the Imunify interface; sign in with the server's **root** user and password.

## Re-install

If the interface stops working, use the re-install form on the same page. It runs Imunify's deploy script again (`i360deploy.sh` or `imav-deploy.sh`). If that still fails, run those commands yourself on the server as root, replacing `YOUR_KEY` with your licence key.

## Common problems

- **Not available**: Imunify360 needs a valid licence; the page says so when it is missing.
- Imunify360 adds noticeable memory use; on small servers ImunifyAV may be the better fit.
- The [AI Scanner](/aiscanner/) and ModSecurity are other ways to protect sites; see [ModSecurity](/base/help/modsecurity).
