# Cron jobs

Cron jobs run commands on a schedule, for example a WordPress cron or a backup script. Jobs run as the website's Linux user, not as root.

## Steps

1. Open the website's page and click **Cron Jobs** (or **Add new Cron Job**).
2. Click **Fetch Current Cron Jobs** to see the existing jobs.
3. Click **Add Cron** and choose a **Pre defined** schedule (every minute, every 5 minutes, hourly, daily...) or fill in **Minute**, **Hour**, **Day of Month**, **Month** and **Day of Week** yourself.
4. Enter the **Command**, then save. Edit or delete existing jobs from the same list and click **Save Edits**.

## Examples

```
*/5 * * * * /usr/local/lsws/lsphp81/bin/php /home/example.com/public_html/wp-cron.php
0 3 * * * /home/example.com/scripts/cleanup.sh >/dev/null 2>&1
```

Use full paths: cron has a short `PATH`. Pick the PHP binary that matches the site's PHP version (`/usr/local/lsws/lsphpXX/bin/php`).

## Common problems

- **Job does not run**: test the command first in the [Web Terminal](/addons/terminal/) as the site user.
- **Too many emails**: add `>/dev/null 2>&1` to silence output.
- Very frequent jobs (every minute) add load; use the longest interval that works.
