# ModSecurity

ModSecurity is a web application firewall for OpenLiteSpeed. With a rule set it blocks common attacks such as SQL injection and cross-site scripting.

## Install and configure

1. Open **Security > ModSecurity** (`/firewall/modSecurity`). If it is not installed, click **Install ModSecurity**.
2. Turn on **ModSecurity Status** (the engine) and **Rule Engine**.
3. Optionally turn on the **Audit Engine** to log blocked requests, and pick a **Debug Log Level** (keep it low in production).
4. Click **Save Configuration**.

## Rule sets

Open **Security > Rule Packs** (`/firewall/modSecRulesPacks`) and install the **OWASP ModSecurity Core Rules**. Use **Configure** to turn individual rule files on or off. **ModSec Rules** lets you add your own rules.

## Common problems

- **A site breaks (403 errors) after enabling rules**: check **Server > ModSec Audit** for the rule ID that blocked the request, then disable that rule file or add an exception.
- WordPress admin and REST requests trigger some OWASP rules; test after enabling.
