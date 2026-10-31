# Changelog

## Unreleased

### Added
- **Attack request details**: each detected attack now stores the HTTP request that triggered it: method, protocol,
  User-Agent, all headers, cookies and the request body (from ModSecurity audit log sections B and C/I, serial or
  JSON format). Stored once per request (`AttackRequest`) and shared by all rules it triggered. A Method column was
  added to the attacks pages and the details window shows the full request (loaded on demand).
- Owc Setting: `AttackStoreRequestBody`, `AttackStoreCookies`, `AttackMaxBodyBytes` (default: store both, 16 KB body).
- Syslog attack events include the method and User-Agent (body and cookies are never forwarded).

### Fixed
- Attacks stopped being stored when saving the request details failed (e.g. a NUL byte in the body, rejected by
  PostgreSQL, or a missing migration): the error was swallowed and the whole attack dropped. Request details are now
  best effort, NUL bytes are stripped, store errors are logged, and when the tables are out of date the task logs
  that a migration is required and keeps its checkpoint so the attacks are stored once `migrate` is run.

- Repeated attacks were never stored again: duplicates were detected by content (IP, URI, rule, status...) with no
  time limit, so the same attack sent again (e.g. the same URL from Firefox, then curl) was silently skipped.
  Duplicates are now detected by ModSecurity's `unique_id` + rule (new `Attack.txn_id`), so re-read log entries are
  still ignored while every new request is stored.

- error.log fallback (used when no audit log is readable) stored nothing on nginx: its regex lost the unique_id, so
  the client IP could not be found. Error lines are now grouped by unique_id with the full ModSecurity text kept, the
  client IP is read from `[client ...]` / `client:`, and on nginx the method and Host come from `request:`/`host:`.
- nginx installer: the audit log file is created writable by the nginx worker user; otherwise libmodsecurity writes
  nothing and attacks have no request details.

- Attacks only appeared after restarting the services: Celery task time limits were set as `CELERYD_TASK_*`,
  which Celery ignores with the `CELERY` namespace, so a stuck task (e.g. `lsof` in the per-minute stats script)
  held a worker slot forever and starved the attack parser. Now `CELERY_TASK_TIME_LIMIT`/`SOFT_TIME_LIMIT` apply,
  per-minute beat tasks expire after 55s instead of piling up, the stats/server-detection scripts have timeouts,
  `lsof` is replaced by `/proc/sys/fs/file-nr`, and the parser lock is a kernel `flock` (released when the process
  ends, and on any error) instead of a `/tmp` marker file that blocked runs for 15 minutes after a crash.
- `CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP` was also set under an ignored name.

- Saving configuration in the panel returned 403: the panel itself is served through nginx/Apache with
  ModSecurity + CRS, and config text (`proxy_pass http://...`, `/var/log/...`, `SecRule`, `<VirtualHost>`) is
  flagged as SSRF / file access / command injection. New `scripts/panel_waf_exclusions.sh` (also run by the
  installers) skips the WAF only for POSTs to the panel's editing endpoints, and only inside the panel's vhost.
- Apache installer did not run at all (stray quote, bash syntax error).

### Security
- Fixed stored XSS on the attacks pages: the attacker-controlled URI was placed inside a JavaScript template literal
  in the "Copy" buttons.
- WAF bypass on protected sites: the dashboard exclusions (ids 1500010/1500011) were written into the global CRS
  REQUEST-900 file as `REQUEST_URI` rules, so any request to `/crs/rules/save/...` or `/dashboard/crs/settings/...`
  on *any* site behind the WAF ran with ModSecurity turned off. They are now panel-only and removed from the global
  file by the script, the installers, the CRS update and the CRS version switch.
- Apache: the panel exclusions file moved to `/etc/modsecurity/wafcontrol/panel.conf` (the script migrates the old
  `/etc/modsecurity/wafcontrol-panel.conf`). Debian's stock `security2.conf` includes `/etc/modsecurity/*.conf` for
  every site, which would have made the panel-only exclusions global.

### Changed
- `CELERY_BROKER_URL` / `CELERY_RESULT_BACKEND` can be set in `.env` or the environment (default
  `redis://localhost:6379/0`), so Redis can run as a separate service or container.
- `scripts/panel_waf_exclusions.sh` reloads nginx/Apache without systemd when it is not available (containers), and
  `WAFC_NO_RELOAD=1` only validates the config (used by installers and image builds).

### Upgrade notes
Run once on existing servers: `sudo bash scripts/panel_waf_exclusions.sh` (fixes 403 on panel saves and removes the
global exclusions).
New table and column: run `python manage.py makemigrations wafinstaller && python manage.py migrate`, then restart
the panel and Celery. The request body is only available if `SecAuditLogParts` includes `C` (or `I` on ModSecurity 2).

## v1.1.0

### Added
- **Nginx Config**: list, view, create and edit `/etc/nginx/conf.d/*.conf` from the panel (shown when nginx is installed).
- **Apache Config**: same for Apache (`/etc/apache2/sites-available` on Debian/Ubuntu with enable on create, `/etc/httpd/conf.d` on RHEL).
  Every change is validated with the server config test and rolled back on failure, then the server is reloaded.
- **Users Management**: list, create, edit, enable/disable and delete panel administrators, set passwords and reset 2FA.
  An admin cannot delete or disable their own account, and the last active admin is protected.
- **Syslog Config**: forward WAF attacks and user actions (audit log, login/logout, failed login/2FA) to a syslog / SIEM
  server over UDP or TCP, RFC 5424 or RFC 3164, with enable/disable, per-event toggles and a test message.
  Passwords, OTP codes and file contents are never sent.
- **IP Lists**: named allow/deny lists of IPv4/IPv6 addresses and CIDR ranges, published as include files for nginx
  (`/etc/nginx/wafcontrol/iplists/`) and Apache (`/etc/apache2/wafcontrol/iplists/`), with a usage guide for each server.
- **Geo Lists**: allow/deny lists by country (plus optional extra IPs), built from the bundled GeoLite2-Country database.
  nginx uses its built-in `geo` module (`$wafc_geo_<name>` variable, fast even for large countries); Apache gets the
  countries expanded into `Require ip` ranges. A "Refresh Geo Lists" button re-generates them after a GeoIP update.

### Fixed
- App signals were never connected (`WafinstallerConfig.ready()` was defined outside the class).
- CRS "Latest Version: None": versions are now fetched right away on a fresh install instead of waiting for the
  12-hour schedule, and Force Fetch reports the real error (no network, GitHub rate limit...) instead of always
  claiming success. Optional `GITHUB_TOKEN` in `.env` raises GitHub's rate limit.
- Force Fetch CRS Versions now requires login and CSRF protection.
- CRS version switch: download errors are now reported (was a silent `wget -q`), and a failed config test
  rolls back `main.conf` / the Apache `current` link instead of leaving the server pointing at a broken version.

### Upgrade notes
A database update is required (IP Lists / Geo Lists). After updating the code:

```bash
python manage.py makemigrations wafinstaller
python manage.py migrate
```

Then restart the panel and Celery services.

## v1.0.0
- Initial release.
