# Security Guard – documentation

**English** | [Polski](README.pl.md)

Documentation for plugin version **1.04** (ResourceSpace 11).
*(since X.YY)* marks the plugin version in which a feature first appeared. Features without
a mark have been available since 1.00. Change history: [CHANGELOG.md](CHANGELOG.md).

The plugin protects ResourceSpace against known weaknesses until they are fixed in ResourceSpace
itself (**virtual patches**) and works as a **light application firewall**: IP allow and block
lists, scanner blocking, login limits for the API and SimpleSAMLphp, attack patterns in
parameters, and a security log that fail2ban can use to ban addresses in the system firewall.
It also protects against **deleting many resources at once** (approval by another administrator)
and enforces a **share policy** (password, generated passwords, expiry) *(since 1.01)*, and notifies
chosen users and user groups about **security incidents** *(since 1.02)*. Uploaded files are checked
(**allowed file types**, content against the extension, dangerous content) and doubtful files go to a
**quarantine** that needs an administrator's approval *(since 1.04)*.

**Where:** System > Plugins > Security Guard > **Options**. Only administrators (permission `a`)
can open this page.

**What a plugin cannot do:** it only sees requests that reach ResourceSpace's PHP code. Static
files, the web server itself and the network are outside its reach – the options page contains
templates for nginx and fail2ban for those parts (Apache: see "Apache instead of nginx"). Virtual patches do not replace updates: keep
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
template from the options page (Apache: "Apache instead of nginx") instead.

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
the server banner belong to the web server (nginx: `server_tokens off`; Apache: `ServerTokens Prod`,
`ServerSignature Off` – see "Apache instead of nginx").

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

## Upload verification *(since 1.04)*

Checks every uploaded file before ResourceSpace processes it:

- the upload in the interface (`pages/upload_batch.php`: new resources, replaced files, alternative
  files, uploads through a share) – the complete file is checked in the temporary folder (hook
  `modify_upload_file`); file types that are not allowed are refused already when the upload starts,
- files sent as form data (`$_FILES`): API `upload_multipart`, forms of other pages.

Not checked here: files taken from the server or a URL (API `upload_file` with a path,
`upload_file_by_url`, `create_resource` with a URL) – ResourceSpace limits them with
`$valid_upload_paths` and `$api_upload_urls` – and the pages in "Not checked (paths)" (default Plugin
Manager and the Custom CSS import, which upload code on purpose).

**Modes:** *off*, *log only* (default – everything is checked and logged, nothing is blocked) and
*enforce* (file types that are not allowed are refused, doubtful files go to the quarantine). Start
with *log only*, look at the `upload_*` lines of the security log, then switch to *enforce*.

**1. Allowed file types** – groups with a starting list:

| Group | Extensions |
|---|---|
| Images | jpg, jpeg, jpe, png, gif, tif, tiff, bmp, webp, heic, heif, avif, psd, psb, svg, eps, ai, RAW (cr2, cr3, nef, nrw, arw, dng, orf, raf, rw2, pef, srw) |
| Video | mp4, m4v, mov, qt, avi, mkv, webm, wmv, mpg, mpeg, mts, m2ts, 3gp, mxf |
| Documents | pdf, doc, docx, xls, xlsx, ppt, pptx, odt, ods, odp, rtf, txt, csv, indd, idml |
| Audio (off by default) | mp3, wav, aac, m4a, flac, ogg, aif, aiff |

"Also allow" adds extensions (e.g. `zip`), "Do not allow" removes them from the groups (e.g. `svg`).
Extensions banned by ResourceSpace (`$banned_extensions`: php, exe, js …) are never allowed. On the
admin pages only the content is checked, not the file type (administrators import CSV, XML …).

**2. Advanced checks** (option, on by default) – a file is doubtful when:

- its **content does not match the extension** (file signatures, e.g. a program or a ZIP archive
  named `.jpg`, a PDF named `.png`),
- it contains **executable content**: Windows / Linux / macOS programs, scripts (`#!/`), **PHP code**
  (also hidden in images), HTML / JavaScript in binary files,
- it has **active content**: SVG with scripts, event handlers, `javascript:`, external entities; PDF
  with `/JavaScript`, `/JS`, `/Launch`, embedded files or rich media; **macros** in Office files
  (VBA) and OpenDocument files,
- it is **encrypted** and cannot be checked (password-protected PDF, Office file or ZIP),
- it contains **sensitive data**: private keys, cloud access keys (text files), or is a key /
  password file by its name (`id_rsa`, `.env`, `.pem`, `.p12`, `.kdbx` …),
- its **name** hides a program extension (`photo.php.jpg`) or contains control / right-to-left
  characters (`invoice[RLO]fdp.exe`),
- it is the **EICAR test file** (to test the quarantine safely).

Documents are scanned completely up to the set size (default 25 MB), images and videos at the
beginning and the end. Content in compressed parts of a file (e.g. compressed PDF streams) is not
unpacked – for that use the **virus scan with ClamAV** (option): the command (default
`clamdscan --no-summary --fdpass`) runs for every uploaded file; ClamAV must be installed and the
user that runs PHP must be allowed to use it.

**3. Quarantine and approval:** a doubtful file is moved to
`<filestore>/security_guard/data_<key>/quarantine/` and the upload is refused with the reasons and a
request number. The administrators get a notification ("Notify administrators", and the recipients of
the incident notifications with the type "Uploads"). In the box **Upload quarantine** an
administrator can download the file for analysis (always as a download, never displayed), approve or
reject it. **Approve** allows the same file (same SHA-256 checksum) for that user for the set time
(default 24 hours) – the user uploads it again; the quarantined copy is deleted after the decision.
With **Four eyes** nobody approves a file they uploaded themselves. Files that wait longer than the
set time (default 30 days) are deleted automatically.

The checks run only for requests that upload files; normal requests are not affected.

## Incident notifications *(since 1.02)*

Security incidents are sent to the chosen **users** (user names) and to all active members of the
chosen **user groups**:

- **ResourceSpace notification** (the bell / messages) with a link to the options page,
- **e-mail** to the address of the user account (accounts with an address marked as invalid are
  skipped; ResourceSpace must be able to send e-mail).

Incident types (each can be switched on separately):

| Type | Events |
|---|---|
| Blocked attacks | blocked addresses, scanners, admin pages / API keys from other addresses, API "function" confusion, report parameters, attack patterns in "block" mode, SimpleSAMLphp panel |
| Login attacks | API login lockout, SimpleSAMLphp login limit |
| Deletion of many resources | approval requests (also to the administrators when "Notify administrators" is on), blocked permanent deletion, approvals given |
| Detections without blocking | attack patterns in "log only" mode, corrected login redirect, session hash in the URL |
| Uploads *(since 1.04)* | file types that are not allowed, quarantined files (also to the administrators when "Notify administrators" is on), approvals |
| Changes of Security Guard | settings saved (with the changed options), protection switched off, log cleared, plugin reset, test notification |

Against floods: one notification per rule and address in N minutes (default 15) and at most M
notifications per hour (default 30); the security log keeps every event. Notifications are sent only
when something happens – normal requests stay free of database queries.

"Send test notification" sends a test to the saved recipients with the saved channels. Users whose
ResourceSpace preferences send every notification also by e-mail may get two e-mails – then leave
only one channel on.

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

## Apache instead of nginx

The checks of the plugin do not depend on the web server. The server rules from the options page
(written for nginx) look like this in Apache – modules `headers` and `remoteip`
(`sudo a2enmod headers remoteip` on Ubuntu / Debian, loaded by default on the RHEL family):

```apache
# Server banner - /etc/apache2/conf-available/security.conf (RHEL: /etc/httpd/conf.d/security.conf)
ServerTokens Prod
ServerSignature Off

# VirtualHost of ResourceSpace
<Directory <RS_ROOT>>
    Options -Indexes +FollowSymLinks
</Directory>

# SimpleSAMLphp: local login form and admin pages only from these addresses (SSO stays open)
<LocationMatch "^/plugins/simplesaml/lib/(public|www)/(admin|module\.php/(admin|core/(login|loginuserpass|frontpage)))">
    Require ip 192.0.2.10
</LocationMatch>

# no access to hidden and backup files
<LocationMatch "/\.(?!well-known)">
    Require all denied
</LocationMatch>
<FilesMatch "\.(bak|old|orig|sql|swp|log)$">
    Require all denied
</FilesMatch>

# behind a load balancer / reverse proxy: the real client address in REMOTE_ADDR
RemoteIPHeader X-Forwarded-For
RemoteIPTrustedProxy 192.0.2.1
```

- With `mod_remoteip` Apache already passes the real client address – leave "Trusted proxies" in
  the plugin empty. Without it, enter the proxy addresses there.
- Apache has no built-in equivalent of nginx `limit_req`. The plugin's own limits (API login lockout,
  SimpleSAMLphp login limit) work anyway; for more use fail2ban (the jail from the options page reads
  the plugin's log, so it is the same for Apache) and optionally `mod_evasive` or ModSecurity.
- The `X-Powered-By` header is removed by the plugin; HSTS and the other headers can be set with
  `Header always set ...` (mod_headers).
- Emergency switch with Apache on the RHEL family: `sudo -u apache touch <filestore>/security_guard/disabled`.
- Check and reload: `sudo apachectl configtest`, then `sudo systemctl reload apache2` (RHEL: `httpd`).

## Installation and files on the server

### Download and installation

The plugin is distributed as a `security_guard-<version>.zip` archive on the releases page:
<https://github.com/s29829/security_guard/releases>. The archive contains the folder `security_guard/` with the code,
license and documentation. Below, `<RS_ROOT>` is the ResourceSpace installation folder (e.g.
`/var/www/resourcespace`) and `www-data:www-data` is the user and group that run PHP – with Apache on RHEL, Rocky, Alma or
Fedora `apache:apache` (see "nginx or Apache" below).

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

### nginx or Apache

The plugin works the same with both web servers. Only the user that runs PHP, the service names
and a few server settings differ – use the user and group from the table in the commands above:

| | nginx + PHP-FPM (Ubuntu / Debian) | Apache (Ubuntu / Debian) | Apache (RHEL, Rocky, Alma, Fedora) |
|---|---|---|---|
| User:group that runs PHP | `www-data:www-data` | `www-data:www-data` | `apache:apache` |
| Reload after an update | `sudo systemctl restart php8.3-fpm` | mod_php: `sudo systemctl reload apache2`; PHP-FPM: `sudo systemctl restart php8.3-fpm` | mod_php: `sudo systemctl reload httpd`; PHP-FPM: `sudo systemctl restart php-fpm` |

- **Who runs PHP:** with Apache and mod_php the Apache user; with PHP-FPM (nginx or Apache) the user
  of the PHP-FPM pool (`user =` / `group =` in `/etc/php/<version>/fpm/pool.d/www.conf`, on the RHEL
  family `/etc/php-fpm.d/www.conf`). Check: `ps -o user= -C php-fpm8.3,php-fpm,apache2,httpd | sort -u`.
- **Permissions:** folders `755`, files `644`, owner = that user and group (commands above). The plugin
  files only need to be readable; `<filestore>` must be writable for that user – exactly as
  ResourceSpace itself requires.
- **No directory listings (Apache):** Apache on Ubuntu / Debian allows listings under `/var/www`
  (`Options Indexes` in `apache2.conf`). The plugin keeps its settings in
  `<filestore>/<plugin>/data_<key>/`, and a listing would show the folder name. Switch listings off for
  ResourceSpace (VirtualHost or `apache2.conf` / `httpd.conf`) and reload Apache:

  ```apache
  <Directory <RS_ROOT>>
      Options -Indexes +FollowSymLinks
  </Directory>
  ```

  nginx shows no listings unless `autoindex on` is set.
- **SELinux (RHEL family):** after unpacking restore the file labels:
  `sudo restorecon -R <RS_ROOT>/plugins/security_guard`. The filestore needs the writable label (usually set when
  ResourceSpace was installed): `sudo semanage fcontext -a -t httpd_sys_rw_content_t "<filestore>(/.*)?"`
  and `sudo restorecon -R <filestore>`.
- **Server rules** (rate limits, hidden files, SimpleSAMLphp panel, server banner): the options page
  shows nginx templates; the Apache equivalents are in "Apache instead of nginx" below.

Finally: System > Plugins, activate "Security Guard" and click **Options**. With the default
settings all patches except "One session per account" are on, the firewall lists are empty and
attack patterns are only logged – check the log in the first days. Deletion protection is on with
the limits above; the share policy is off until you switch it on *(since 1.01)*.

### Files on the server

Everything the plugin stores is in `<filestore>/security_guard/`:

- `data_<key>/settings.php` – settings (the key derives from `scramble_key`, so the files cannot be
  read by guessing the address),
- `data_<key>/events.log`, `events.log.1` – security log,
- `data_<key>/rate/` – login attempt and notification counters (old ones are removed automatically),
- `data_<key>/deletion.json` – deletion requests and approvals *(since 1.01)*,
- `data_<key>/upload.json`, `data_<key>/quarantine/` – quarantined files and approvals *(since 1.04)*,
- `disabled` – the emergency switch, only when you create it.

`<filestore>` is ResourceSpace's `$storagedir` (default `<RS_ROOT>/filestore`). Updating or removing
the plugin code never deletes these files. **The plugin creates its folders itself** when it first
saves something; it only needs write access to the filestore, which ResourceSpace requires anyway.

## Reset plugin

The box is collapsed – click its title to open it; it opens by itself after a failed reset.

**Reset plugin** (after typing `RESET`) deletes `<filestore>/security_guard`: settings, log,
counters, deletion requests and approvals, the upload quarantine and the emergency switch file. The default settings apply afterwards. ResourceSpace data
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
