# IndiansCloud WHMCS provisioning module

Sells IndiansCloud hosting from WHMCS. It creates, suspends, unsuspends, terminates and changes
accounts on an IndiansCloud panel. It also syncs disk and bandwidth usage and logs clients and
administrators in with single sign-on. It uses the panel's provisioning API v2
(`https://<panel>:8090/api/v2/`) with a personal API token. Compatible with PHP 7.4 and 8.x.

## Files

| File | Purpose |
| --- | --- |
| `indianscloud.php` | The module (all WHMCS functions) |
| `templates/overview.tpl` | Client area overview: domain, username, usage, SSO button |
| `tests/run_tests.php` | Self-contained tests: `php tests/run_tests.php` |

No hooks are needed.

## 1. Prepare the panel

1. Log in to the panel as the account WHMCS will act as: an administrator, or a reseller that
   sells only its own accounts.
2. As an administrator, go to **Users > API Access** and enable API access for that account.
   Tokens of accounts without API access are refused.
3. As that account, open **Users & Plans > API Tokens** (`/apitokens/`) and create a token:
   - Name: `WHMCS`
   - Scope: **Provisioning**
   - Allowed IP addresses: your WHMCS server's public IP (recommended)
   - Expiry: optional
4. Copy the token (`ictk_…`). It is shown only once.
5. Make sure the WHMCS server can reach TCP port 8090 on the panel.
6. Create the panel packages you want to sell (**Packages > Create Package**). Note their
   exact names. Packages created by a reseller are named `reseller_Name`.

## 2. Install the module

Copy this folder to your WHMCS installation:

```
<whmcs>/modules/servers/indianscloud/
    indianscloud.php
    templates/overview.tpl
```

The `tests/` folder and this README are optional on the WHMCS server.

## 3. Add the server

In **System Settings > Servers > Add New Server**:

| Field | Value |
| --- | --- |
| Name | anything, for example `IndiansCloud 1` |
| Hostname | the panel hostname, for example `server.indianscloud.com`. The TLS certificate must match it |
| Module | **IndiansCloud** |
| Username | the panel account that owns the token (optional; Test Connection checks it) |
| Password | the token `ictk_…` (preferred: WHMCS stores it encrypted) |
| Access Hash | leave empty, or use it for options (see below) |
| Secure | ticked (the module always uses HTTPS) |
| Port | 8090 (the default; use "Override with Custom Port" for another port) |

Click **Test Connection**. It confirms that the token works, belongs to the username given and
has the Provisioning scope.

### TLS options (Access Hash)

TLS verification is on by default. For a panel with a self-signed certificate, put key=value
lines into the Access Hash:

```
allow_self_signed=1
```

`allow_self_signed=1` turns off certificate checks for this server; use it only for testing.
To trust a private CA instead, use `ca_file=/path/to/ca.pem`. You can also keep the token here
as `token=ictk_…`; a token in the Password field takes precedence.

## 4. Create a product

In **Products/Services > Create a New Product**, choose the type (Shared Hosting or Reseller
Hosting). On the **Module Settings** tab, select **IndiansCloud** and the server group, then
fill in:

| # | Option | Meaning |
| --- | --- | --- |
| 1 | Package Name | The panel package. Use the exact name, for example `admin_Starter`. A reseller token may also use the short name (`Starter` becomes `<reseller>_Starter`) |
| 2 | PHP Version | PHP of the first website |
| 3 | Reseller Account | Tick to create a reseller (ACL `reseller`) |
| 4 | ACL | Panel ACL name. Empty means `user`, or `reseller` when option 3 is ticked |
| 5 | Websites Limit | How many websites the account may create |

A configurable option or custom field named **Package** overrides option 1 per order.

Set **Automatically setup the product** as you prefer, and require a domain for shared hosting.

## How WHMCS maps to the panel

| WHMCS | Panel |
| --- | --- |
| Service username | Panel account username: lowercase letters, digits, `_ . -`, 3–50 characters. If WHMCS left it empty or invalid, the module derives one from the domain and writes it back to the service |
| Service password | Account password (sent base64-encoded so `$ ; \|` survive the panel's request filter) |
| Client email, first and last name | Account email and name |
| Service domain | The account's first website (`www.` is stripped). Reseller products may have no domain |
| Product option 1, or the "Package" option | Website package |
| Owner | The token's account. A reseller token creates accounts owned by that reseller |

Errors come back as WHMCS expects: `success`, or the panel's message, such as
`Username already exists: shop1 (HTTP 409)`.

## Module functions

| Function | Panel endpoint | Notes |
| --- | --- | --- |
| TestConnection | `verify` | checks the token owner and scope |
| CreateAccount | `accounts/create` | creates the account and its first website. If the website cannot be started, the account is removed again |
| SuspendAccount | `accounts/suspend` | suspends every website of the account and blocks panel login (it also logs the account out). Suspending a reseller also suspends its accounts |
| UnsuspendAccount | `accounts/unsuspend` | restores only the websites the suspension took down. A site suspended on its own stays suspended |
| TerminateAccount | `accounts/terminate` | deletes the websites, then the account. It refuses a reseller that still owns accounts. An account that is already gone counts as success, so retries are safe |
| ChangePassword | `accounts/password` | |
| ChangePackage | `accounts/package` | moves every website of the account to the new package |
| UsageUpdate | `accounts/usage` | runs from the WHMCS daily cron. Writes `diskusage`, `disklimit`, `bwusage`, `bwlimit` (MB) per service, matched by username, then by domain. Values are the panel's last measurement |
| ServiceSingleSignOn | `sso` | "Log in to IndiansCloud" for the client |
| AdminSingleSignOn | `sso` | logs the WHMCS admin in as the token's own account |
| ClientArea | `accounts/usage` | overview template with usage and an SSO button |
| AdminServicesTabFields | `accounts/info` | shows the panel account's ACL, state and websites |

## Single sign-on

`sso` returns a one-time URL: `https://<panel>:8090/api/v2/sso/redeem?ticket=…`.

- The ticket is valid for **60 seconds** and can be used once. Only its SHA-256 digest is stored.
- Redeeming it starts a normal panel session bound to the browser's IP address.
- SSO never logs into another administrator account, nor into a suspended account.
- SSO skips the target account's own 2FA. It is authorised by the provisioning token instead.

## Security notes

- **Tokens and 2FA.** A personal token replaces both the password and the two-factor code. It is
  a 256-bit possession factor that can only be created from a logged-in panel session (which
  already passed 2FA). It can be limited by scope, expiry and source IP, and revoked at any time.
  Password logins to the API keep requiring the OTP for accounts with 2FA.
- Tokens are stored as SHA-256 digests and compared in constant time. After 20 failed attempts
  in 5 minutes, an IP address is refused for a while.
- The IP allowlist checks the TCP peer address. Forwarded headers are ignored, so they cannot be
  used to spoof it.
- A reseller token can act only on the reseller's own accounts and websites. An administrator
  token can act on all.
- The module masks passwords and the token in the WHMCS module log.

## Testing the module

```
php tests/run_tests.php
```

The tests stub WHMCS and the HTTP transport. They check field mapping, error strings, TLS
defaults, SSO, usage rows and the client area.

## Troubleshooting

| Message | Cause |
| --- | --- |
| `Could not reach the panel …` | Firewall on port 8090, wrong hostname, or a TLS certificate that does not match. Use `allow_self_signed=1` only for testing |
| `This API token is not allowed from this IP address` | Add the WHMCS server's IP to the token's allowlist |
| `API access is not enabled for this account` | Users > API Access |
| `This API token lacks the 'provisioning' scope` | Create a Provisioning token |
| `Package not found` | Option 1 must match the panel package name |
