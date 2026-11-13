# Security Guard – documentation

**English** | [Polski](README.pl.md)

Documentation for plugin version **1.01** (ResourceSpace 11).
*(since X.YY)* marks the plugin version in which a feature first appeared. Features without
a mark have been available since 1.00. Change history (in Polish): [CHANGELOG.md](CHANGELOG.md).

The plugin protects ResourceSpace against known weaknesses until they are fixed in ResourceSpace
itself (**virtual patches**) and works as a **light application firewall**: IP allow and block
lists, scanner blocking, login limits for the API and SimpleSAMLphp, attack patterns in
parameters, and a security log that fail2ban can use to ban addresses in the system firewall.
It also protects against **deleting many resources at once** (approval by another administrator)
and enforces a **share policy** (password, generated passwords, expiry) *(since 1.01)*.

**Where:** System > Plugins > Security Guard > **Options**. Only administrators (permission `a`)
can open this page.

**What a plugin cannot do:** it only sees requests that reach ResourceSpace's PHP code. Static
files, the web server itself and the network are outside its reach – the options page contains
templates for nginx and fail2ban for those parts. Virtual patches do not replace updates: keep
ResourceSpace up to date and report weaknesses to the ResourceSpace team.

---

## How it works and performance

The checks run in the `initialise` hook at the end of `include/boot.php` – on every page, on the
API and on SimpleSAMLphp pages (when SimpleSAMLphp loads ResourceSpace, see below), **before** the
page code and before authentication. The plugin is always loaded for every user
(`disable_group_select`) and runs first (`default_priority: 1`).

It is built to cost almost nothing:

- a normal request: a few string comparisons and one include of the settings file (a PHP array
  that OPcache keeps in memory) – no database query, nothing written to disk,
- the database is used only for logins through the API (one query) and for requests that delete
  resources (two or three small queries) *(since 1.01)*, the disk only when a request is blocked or
  logged and for posts to the SimpleSAMLphp login form (a small counter file),
- no APCu or other extension needed.

## Patches for known weaknesses

Each patch can be switched off separately.

| Option | Weakness | What the plugin does |
|---|---|---|
| Report dates only as numbers | SQL injection in the date parameters of reports (`pages/team/team_report.php`, also used by analytics graphs and report e-mails) | `from-y`, `from-m`, `from-d`, `to-y`, `to-m`, `to-d` (and `period_days`) must contain only digits, otherwise the request is blocked (400). |
| Redirect after login only to this site | Open redirect: `login.php?url=//other-site` sent the user to another site after login | The `url` parameter of `login.php` and `pages/terms.php` must be a path on this site or start with `$baseurl`; otherwise it is replaced with `index.php` and logged. |
| API: one source of the function name | `api/index.php` decided about authentication with a different copy of `function` than the one it executed – `function=login` outside `query` skipped the authentication | A `function` parameter outside `query` must be the same as the function in `query`, otherwise 403. The browser interface (`authmode=native`) does not send such a parameter. |
| API login lockout | Brute force through the API: `function=login` was not limited, only `login.php` checked the lockouts | Login through the API is refused (429) while ResourceSpace locks the IP address or the user name (`$max_login_attempts_per_ip`, `$max_login_attempts_per_username`, `$max_login_attempts_wait_minutes`), exactly like `login.php`. |
| Session only from the cookie | The session hash was accepted in the URL (`?user=…`) and could end up in logs and browser history | `user` is removed from the URL parameters outside the API (there `user` is the user name). ResourceSpace 10.7 never builds such links. |
| One session per account (off by default) | Session fixation: without `$randomised_session_hash` the session hash depends only on the password and the day | Sets `$randomised_session_hash = true`: a new random session at every login. **Logging in on a second device ends the session on the first.** |

## SimpleSAMLphp

When SimpleSAMLphp reads its configuration from ResourceSpace (`$simplesaml_rsconfig`, settings in
`$simplesamlconfig` in `config.php`), its autoloader loads ResourceSpace, so the plugin also runs
on SimpleSAMLphp pages. Then:

- **Hide error details** – sets `showerrors` and `errorreporting` to `false`: error pages without
  stack traces and server paths.
- **Local login form and admin pages** (`module.php/core/loginuserpass`, `core/login`,
  `core/frontpage`, `admin`): *open*, *allowlist* (only the addresses in "Admin pages only from")
  or *blocked*. SSO itself (`module.php/saml/...`) is never blocked.
- **Login attempts per IP** – at most N posts to the local login form per address in M minutes
  (default 10 in 10 minutes), then 429.

**Verify after activation** (the behaviour depends on the SimpleSAMLphp version in ResourceSpace
11): open the local login page from an address outside the allowlist – it should answer "Request
blocked". If it does not, SimpleSAMLphp does not load ResourceSpace on your server: use the nginx
template from the options page instead.

## Firewall

Lists take one address (`192.0.2.10`, `2001:db8::1`) or network (`192.0.2.0/24`) per line; text
after `#` is a comment. An empty list switches the rule off.

- **Trusted proxies** – addresses of a load balancer or reverse proxy. Only for requests from
  them the client address is taken from `X-Forwarded-For` (the last address that is not a trusted
  proxy). Without this list the plugin uses `REMOTE_ADDR`.
- **Blocked addresses** – no access to ResourceSpace at all.
- **Admin pages only from** + **Admin pages** – the admin areas (default `pages/admin/`,
  `pages/team/`, `plugins/*/pages/`) only from these addresses. The options page refuses to save a
  list that does not contain your own address.
- **API key access only from** – calls with API keys only from these addresses. The browser
  interface (`authmode=native`) is not affected.
- **Block scanners** – User-Agent contains e.g. `sqlmap`, `nikto`, `nuclei`, `wpscan` (editable
  list). It stops automated noise, not a careful attacker.
- **Attack patterns in parameters** – *off*, *log only* (default) or *block*: typical SQL
  injection (`union select`, `sleep(`, `information_schema`, `' or 1=1`), XSS (`<script`,
  `javascript:`, `onerror=`) and path traversal (`../../`, `/etc/passwd`). Paths in the list below
  it are not checked (editors that post code, e.g. Custom CSS). Start with *log only*, check the
  log for false alarms, then switch to *block*.

Blocked requests get only a short answer with a reference number; the reason is in the log
(rule, address, path, reference).

## Response headers

- **Remove X-Powered-By** – hides the PHP version.
- **Permissions-Policy** – default `camera=(), microphone=(), geolocation=(), payment=(), usb=()`;
  empty = not sent.

Other headers (HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy) and
`server_tokens off` belong to nginx.

## Deletion protection *(since 1.01)*

Protects against losing many resources at once – by mistake, by a script running in a user's
session or with a stolen account. ResourceSpace has no hook that could stop a permanent deletion
before the files are removed, so the plugin checks the requests that delete, before the page code:

- the API functions `delete_resource`, `delete_resources_in_collection` and
  `delete_alternative_file` (the interface deletes resources this way: "Delete" on the resource
  page, "Delete all resources" in the collection actions),
- `pages/collection_manage.php` – deleting a collection together with its resources,
- batch edit of a collection that sets the "Deleted" state.

Options:

- **Always move to "Deleted" first** – when `$resource_deletion_state` is not set, deleting would
  remove the files at once; the plugin sets it to 3 ("Deleted"), so deleted resources can be
  restored. Only deleting a resource that is already in "Deleted" removes it permanently.
- **Limits per user and time window** (default 50 resources moved to "Deleted" and 10 deleted
  permanently in 60 minutes; 0 permanent = every permanent deletion needs approval). The plugin
  counts the user's deletions in the ResourceSpace log (`resource_log`) plus the resources of the
  request.
- **Permanent deletion in the browser**: *allowed within the limit* or *blocked* (then only an
  administrator on the server can purge "Deleted" resources, e.g. with
  `pages/tools/purge_deleted_resources.php`).

**Additional authorization – approval ("four eyes"):** above a limit the deletion is stopped, the
user sees "needs the approval of another administrator (request #N)" and the administrators get
a ResourceSpace notification. In the box **Deletion approvals** an administrator approves the
request for a set time (default 60 minutes); the user repeats the deletion and the approval is
used up resource by resource. With **Four eyes** (default) nobody can approve their own request.
Administrators can also **approve in advance** (user name, number of resources, minutes) before a
planned clean-up, and withdraw an active approval.

Why approval by another person: re-entering the password does not work for SSO users (they have no
ResourceSpace password) and does not help against a stolen session; e-mail codes need working
mail and go to the same person. A second administrator is independent of the login method.

Not covered: scripts run on the server (command line) and files deleted directly on the disk – use
backups and snapshots of the filestore and the database for that.

## Share policy *(since 1.01)*

Rules for external shares (links with access keys) – in the share and e-mail forms of resources
and collections and for upload shares. Off by default; switch on "Share policy is on".

- **Password required** – sets `$share_password_required`, which ResourceSpace checks on the server.
- **Propose a generated password** – the password field is filled with a random password of the
  minimum length (letters, digits, symbols, without ambiguous characters such as 0/O, 1/l) and is
  visible, so the user can copy it for the recipient; "New password" generates another one. The
  user may type their own password.
- **Minimum password length** (default 12) – shorter passwords are refused on the server.
- **Expiry** – default number of days (14) and maximum (30). The expiry list offers only dates up
  to the maximum; on the server the date is corrected to the limits (shares sent with another date
  get the nearest allowed one, logged as `share_expiry`).
- **Users may change the expiry date** – off = every share expires after the default number of
  days (the list shows only that date).
- **Allow "Never"** – shares without an expiry date (only when users may change the date).

Existing shares are not changed; the policy applies when a share is created or edited.

## Security log and fail2ban

Every event is one line in `<filestore>/security_guard/data_<key>/events.log`, e.g.:

```
2026-11-13T10:00:00+01:00 [security_guard] action=block rule=api_confusion ip=192.0.2.7 ref=3f9a1c2b7d method=POST path="/api/index.php" detail="..."
```

`action=block` – the request was stopped, `action=fix` – a parameter was corrected (redirect,
session in the URL), `action=log` – only logged (attack patterns in *log only* mode). The options
page shows the newest 200 events and can delete the log; when it exceeds the set size it is
renamed to `events.log.1`.

The options page contains a ready **fail2ban** filter and jail with the real log path: addresses
blocked 5 times in 10 minutes are banned for an hour by the system firewall. Behind a proxy or
load balancer the server only sees the proxy's address – ban there instead.

## Configuration check

A list of ResourceSpace and PHP settings that matter for security (OK / WARN / INFO):
random session hash, `$ip_forwarded_for` (a client can forge `X-Forwarded-For` and bypass the
login lockout per IP), HTTPS, debug log, password length, login lockouts, idle sessions, remote
API, `display_errors`, `expose_php`, APCu, the TinyMCE version bundled with ResourceSpace,
SimpleSAMLphp and the emergency switch.

## Disable from the server (emergency)

If the plugin blocks something it should not – e.g. after a ResourceSpace update – and the options
page cannot be reached, use one of these (fastest first; the options page shows them with the real
paths of your server):

```bash
# 1. switch off all checks; the plugin stays active (delete the file to switch on again)
sudo -u www-data mkdir -p <filestore>/security_guard
sudo -u www-data touch <filestore>/security_guard/disabled
sudo rm <filestore>/security_guard/disabled               # on again

# 2. or a line in <RS_ROOT>/include/config.php
$security_guard_disable = true;

# 3. remove the code - ResourceSpace skips a plugin without files, the settings stay in the filestore
sudo mv <RS_ROOT>/plugins/security_guard /root/security_guard.off
sudo mv /root/security_guard.off <RS_ROOT>/plugins/security_guard   # back

# 4. deactivate in the database (like System > Plugins > Deactivate)
mysql <database> -e "UPDATE plugins SET inst_version = NULL WHERE name = 'security_guard';"
sudo rm -f <filestore>/tmp/querycache/plugins_*   # query cache of the plugin list ($tempdir/querycache if set)
```

- 1 and 2 work immediately and keep the settings. 2 also works when the filestore is not
  writable.
- 3 helps even when the plugin code itself causes an error (e.g. a newer PHP version).
- After an update of ResourceSpace: open the options page, check the log for unexpected `block`
  lines and test login, SSO, the API and reports. A fault inside the plugin never stops a page –
  errors are caught and only written to the debug log.

## Installation and files on the server

### Download and installation

The plugin is distributed as a `security_guard-<version>.zip` archive on the releases page:
<https://github.com/s29829/security_guard/releases>. The archive contains the folder `security_guard/` with the code,
license and documentation. Below, `<RS_ROOT>` is the ResourceSpace installation folder (e.g.
`/var/www/resourcespace`) and `www-data` is the web server user (e.g. `apache` on other systems).

**In the browser:** Plugin Manager > Upload a plugin > choose the `.zip` file > Upload (when
updating: **Overwrite**).

**From the command line (CLI)** – download, unpack and set the permissions:

```bash
VER=<version>                    # version number from the releases page, e.g. 1.00
cd /tmp
curl -fLO https://github.com/s29829/security_guard/releases/download/v$VER/security_guard-$VER.zip
sudo rm -rf <RS_ROOT>/plugins/security_guard        # only when updating (the plugin data is in the filestore)
sudo unzip -q security_guard-$VER.zip -d <RS_ROOT>/plugins/
sudo chown -R www-data:www-data <RS_ROOT>/plugins/security_guard
sudo find <RS_ROOT>/plugins/security_guard -type d -exec chmod 755 {} \;
sudo find <RS_ROOT>/plugins/security_guard -type f -exec chmod 644 {} \;
```

**With git:** the repository <https://github.com/s29829/security_guard> contains the complete plugin folder:

```bash
sudo git clone https://github.com/s29829/security_guard <RS_ROOT>/plugins/security_guard
sudo chown -R www-data:www-data <RS_ROOT>/plugins/security_guard
```

Update: `sudo git -C <RS_ROOT>/plugins/security_guard pull`.

Finally: System > Plugins, activate "Security Guard" and click **Options**. With the default
settings all patches except "One session per account" are on, the firewall lists are empty and
attack patterns are only logged – check the log in the first days. Deletion protection is on with
the limits above; the share policy is off until you switch it on *(since 1.01)*.

### Files on the server

Everything the plugin stores is in `<filestore>/security_guard/`:

- `data_<key>/settings.php` – settings (the key derives from `scramble_key`, so the files cannot be
  read by guessing the address),
- `data_<key>/events.log`, `events.log.1` – security log,
- `data_<key>/rate/` – login attempt counters (old ones are removed automatically),
- `data_<key>/deletion.json` – deletion requests and approvals *(since 1.01)*,
- `disabled` – the emergency switch, only when you create it.

`<filestore>` is ResourceSpace's `$storagedir` (default `<RS_ROOT>/filestore`). Updating or removing
the plugin code never deletes these files. **The plugin creates its folders itself** when it first
saves something; it only needs write access to the filestore, which ResourceSpace requires anyway.

## Reset plugin

The box is collapsed – click its title to open it; it opens by itself after a failed reset.

**Reset plugin** (after typing `RESET`) deletes `<filestore>/security_guard`: settings, log,
counters, deletion requests and approvals, and the emergency switch file. The default settings apply afterwards. ResourceSpace data
is not changed. This cannot be undone.

## License

- The plugin is licensed under the **PolyForm Noncommercial License 1.0.0** (file
  [LICENSE](LICENSE)).
- It is **free** for private and noncommercial use, and for noncommercial organizations
  (education, public institutions, charities). You may change and share it for these purposes,
  keeping the license text.
- **Commercial use** (a company, services for clients, a paid product) requires the author's
  written permission: <https://github.com/s29829>. Details: `LICENSE-COMMERCIAL.md` in the
  repository.
