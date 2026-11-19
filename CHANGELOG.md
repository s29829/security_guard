# Changelog - Security Guard

Plugin version numbers: 1.00, 1.01, 1.02 … (+0.01 for every change). The current version is in `security_guard.yaml`.

## [1.08] - 2026-11-19
- Options page: fixed a script error that stopped the section status (Recommended / Custom / Low) and Reset from appearing; the boxes Deletion approvals and Upload quarantine show the status of their settings

## [1.07] - 2026-11-19
- Options page: status of every settings box against the recommended settings (Recommended, Custom when stronger, Low when below the recommendation), fields below the recommendation outlined with the recommended value, recommended choices marked in the lists; Reset button per box (recommended values) that turns into Undo until the settings are saved

## [1.06] - 2026-11-19
- Options page redesign: top bar with the main switch (blue button), pause for a chosen time (15 min - 24 h, switches on again by itself) and the Configurator button; two columns - settings on the left (recommended settings and collapsible Advanced settings that depend on the system), status on the right (quarantine, deletion approvals, configuration check, collapsible log, server configuration, emergency switch, reset); configurator with three protection levels (Basic, Recommended, High) shown on the first start

## [1.05] - 2026-11-18
- Login page for local accounts: a separate page with user name and password (link with a secret key or an own address with an nginx / Apache rule, optional address list); optional enforcing - login.php and the API login accept passwords only from this page.

## [1.04] - 2026-11-13
- Upload verification: allowed file types (groups images, video, documents, audio + own extensions, exclusions), advanced checks (content against the extension, programs, scripts, PHP code, active SVG/PDF content, Office/OpenDocument macros, encrypted files, private keys and sensitive files, suspicious names, EICAR), optional ClamAV scan; quarantine of doubtful files with approval by an administrator (four eyes, approval by SHA-256 for a set time, download for analysis, automatic deletion), modes off/log/enforce, notifications (type Uploads).

## [1.03] - 2026-11-13
- Documentation: installation on Apache (Ubuntu/Debian and the RHEL family) – user and group that run PHP (mod_php / PHP-FPM), permissions, no directory listings (Options -Indexes), SELinux; Apache equivalents of the nginx rules (ServerTokens, SimpleSAMLphp, hidden files, mod_remoteip, limits).

## [1.02] - 2026-11-13
- Security incident notifications to chosen users and user groups: ResourceSpace notification and/or e-mail, choice of incident types (blocked attacks, login attacks, deletion of many resources, detections without blocking, changes of Security Guard), throttling (per rule and address and per hour), test notification, changed settings in the log; entry in the configuration check.

## [1.01] - 2026-11-13
- Deletion protection: enforced trash ($resource_deletion_state), deletion limits per user and time window (from resource_log) for the API, deleting collections with their resources and batch edit to the Deleted state, permanent deletion in the browser within the limit or blocked, above the limit approval by another administrator (four eyes, notifications, approval in advance, withdrawing approvals); share policy: password required, proposed random password with a minimum length, default and maximum expiry enforced on the server, optionally without changing the date and without "Never".

## [1.00] - 2026-11-13
- First version: virtual patches (report dates only as numbers, redirect after login only to this site, one source of the function name in the API, API login lockout, session only from the cookie, optionally one session per account), SimpleSAMLphp (hide error details, local login panel: open/allowlist/block, attempt limit), light firewall (trusted proxies, blocked addresses, admin pages and API keys only from listed IPs, scanner blocking, attack patterns: log/block), headers (no X-Powered-By, Permissions-Policy), security log for fail2ban, configuration check, nginx/fail2ban templates, emergency switches, Reset plugin.
