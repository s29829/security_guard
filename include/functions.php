<?php
// Security Guard - functions of the options page (not loaded on normal requests).
require_once __DIR__ . '/guard.php';

// Text area (one entry per line, "#" comments allowed) -> list
function security_guard_lines($text)
{
    $out = array();
    foreach (preg_split('/\r\n|\r|\n|,/', (string) $text) as $line) {
        $line = trim(preg_replace('/#.*$/', '', $line));
        if ($line !== '' && !in_array($line, $out, true)) {
            $out[] = $line;
        }
    }
    return $out;
}

// Valid IPv4 / IPv6 address or network (CIDR)?
function security_guard_valid_cidr($cidr)
{
    $parts = explode('/', (string) $cidr, 2);
    $bin = inet_pton($parts[0]);
    if ($bin === false) {
        return false;
    }
    return count($parts) === 1 || (ctype_digit($parts[1]) && (int) $parts[1] <= strlen($bin) * 8);
}

// Stores the settings as a PHP file (read by OPcache on every request)
function security_guard_save_settings(array $new)
{
    $dir = security_guard_data_dir();
    if (!security_guard_mkdir($dir)) {
        return false;
    }
    $defaults = security_guard_defaults();
    $clean = array();
    foreach ($defaults as $k => $v) {
        if (array_key_exists($k, $new) && gettype($new[$k]) === gettype($v)) {
            $clean[$k] = $new[$k];
        }
    }
    $file = security_guard_settings_file();
    $tmp = $file . '.tmp' . getmypid();
    $php = "<?php\n// Security Guard settings - written by the options page\nreturn " . var_export($clean, true) . ";\n";
    if (file_put_contents($tmp, $php, LOCK_EX) === false || !rename($tmp, $file)) {
        if (is_file($tmp)) {
            unlink($tmp);
        }
        return false;
    }
    if (function_exists('opcache_invalidate')) {
        opcache_invalidate($file, true);
    }
    return true;
}

// Last lines of the security log (newest first)
function security_guard_log_tail($max = 200)
{
    $file = security_guard_log_file();
    if (!is_file($file) || !is_readable($file)) {
        return array();
    }
    $size = filesize($file);
    $fh = fopen($file, 'r');
    if ($fh === false) {
        return array();
    }
    $read = min($size, 256 * 1024);
    fseek($fh, $size - $read);
    $text = (string) fread($fh, $read);
    fclose($fh);
    $lines = array_values(array_filter(explode("\n", $text), 'strlen'));
    if ($read < $size) {
        array_shift($lines); // first line may be cut
    }
    return array_reverse(array_slice($lines, -$max));
}

// "2026-01-01T10:00:00+01:00 [security_guard] action=block rule=x ip=1.2.3.4 ..." -> fields
function security_guard_log_parse($line)
{
    $out = array('time' => '', 'action' => '', 'rule' => '', 'ip' => '', 'ref' => '', 'method' => '', 'path' => '', 'detail' => '');
    if (preg_match('/^(\S+) \[security_guard\] (.*)$/', $line, $m)) {
        $out['time'] = $m[1];
        preg_match_all('/(\w+)=("([^"]*)"|\S+)/', $m[2], $kv, PREG_SET_ORDER);
        foreach ($kv as $p) {
            if (array_key_exists($p[1], $out)) {
                $out[$p[1]] = isset($p[3]) && $p[3] !== '' ? $p[3] : trim($p[2], '"');
            }
        }
    }
    return $out;
}

function security_guard_clear_log()
{
    $ok = true;
    foreach (array(security_guard_log_file(), security_guard_log_file() . '.1') as $f) {
        if (is_file($f)) {
            $ok = unlink($f) && $ok;
        }
    }
    return $ok;
}

function security_guard_rrmdir($dir)
{
    if (!is_dir($dir)) {
        return true;
    }
    foreach (array_diff((array) scandir($dir), array('.', '..')) as $f) {
        $p = $dir . '/' . $f;
        if (is_dir($p) && !is_link($p)) {
            security_guard_rrmdir($p);
        } else {
            unlink($p);
        }
    }
    return rmdir($dir);
}

// Removes <filestore>/security_guard (settings, log, counters - also the emergency switch file)
function security_guard_reset()
{
    $ok = security_guard_rrmdir(security_guard_base_dir());
    if (function_exists('opcache_invalidate')) {
        opcache_invalidate(security_guard_settings_file(), true);
    }
    return $ok;
}

// Version of the TinyMCE bundled with ResourceSpace ('' if unknown)
function security_guard_tinymce_version()
{
    $f = dirname(__FILE__, 4) . '/lib/tinymce/tinymce.min.js';
    if (!is_file($f) || !is_readable($f)) {
        return '';
    }
    $fh = fopen($f, 'r');
    if ($fh === false) {
        return '';
    }
    $head = (string) fread($fh, 300);
    fclose($fh);
    return preg_match('/TinyMCE version ([0-9.]+)/', $head, $m) ? $m[1] : '';
}

// Configuration checks: list of [status ok|warn|info, title, text]
function security_guard_checklist(array $s)
{
    $g = $GLOBALS;
    $c = array();
    $add = function ($status, $title, $text) use (&$c) {
        $c[] = array($status, $title, $text);
    };

    $random = !empty($g['randomised_session_hash']) || $s['force_random_session'];
    $add($random ? 'ok' : 'warn', 'Random session hash',
        $random ? 'Every login gets a new random session hash.'
            : '$randomised_session_hash is false: the session hash depends only on the password and the day (session fixation). '
              . 'Set it to true in config.php or turn on "One session per account" below (one active session per account).');

    $add(!empty($g['ip_forwarded_for']) ? 'warn' : 'ok', 'Client address used by ResourceSpace',
        !empty($g['ip_forwarded_for'])
            ? '$ip_forwarded_for is true: ResourceSpace takes the address from X-Forwarded-For, which a client can forge - the login lockout per IP can be bypassed. '
              . 'Use it only when the proxy overwrites the header (nginx: proxy_set_header X-Forwarded-For $remote_addr).'
            : 'ResourceSpace uses REMOTE_ADDR. Behind a proxy or load balancer enter its addresses in "Trusted proxies".');

    $add(substr((string) ($g['baseurl'] ?? ''), 0, 8) === 'https://' ? 'ok' : 'warn', 'HTTPS', '$baseurl: ' . (string) ($g['baseurl'] ?? ''));

    $add(!empty($g['debug_log']) ? 'warn' : 'ok', 'Debug log', !empty($g['debug_log']) ? '$debug_log is on - turn it off on production.' : '$debug_log is off.');

    $min = (int) ($g['password_min_length'] ?? 0);
    $add($min >= 12 ? 'ok' : 'info', 'Password length', '$password_min_length = ' . $min . ' (12 or more recommended; SSO users are not affected).');

    $add('info', 'Login lockouts', sprintf('%d attempts per IP, %d per user name, %d minutes wait ($max_login_attempts_*). With "API login lockout" they also apply to the API.',
        (int) ($g['max_login_attempts_per_ip'] ?? 0), (int) ($g['max_login_attempts_per_username'] ?? 0), (int) ($g['max_login_attempts_wait_minutes'] ?? 0)));

    $add(!empty($g['session_autologout']) ? 'ok' : 'warn', 'Idle sessions',
        sprintf('$session_length = %d minutes, $session_autologout = %s.', (int) ($g['session_length'] ?? 0), !empty($g['session_autologout']) ? 'true' : 'false'));

    $add('info', 'Remote API', !empty($g['enable_remote_apis'])
        ? '$enable_remote_apis is true. If no external system uses API keys, set it to false (the browser interface keeps working), or enter allowed addresses in "API key access".'
        : '$enable_remote_apis is false: only the browser interface uses the API.');

    $add(ini_get('display_errors') && ini_get('display_errors') !== 'Off' ? 'warn' : 'ok', 'PHP display_errors', 'display_errors = ' . var_export(ini_get('display_errors'), true));
    $add(ini_get('expose_php') && ini_get('expose_php') !== 'Off' ? 'info' : 'ok', 'PHP expose_php',
        'expose_php = ' . var_export(ini_get('expose_php'), true) . ($s['remove_powered_by'] ? ' (the X-Powered-By header is removed by this plugin)' : ''));
    $add(function_exists('apcu_fetch') ? 'ok' : 'info', 'APCu', function_exists('apcu_fetch') ? 'Installed.' : 'Not installed (ResourceSpace system status reports it; this plugin does not need it).');

    $tiny = security_guard_tinymce_version();
    if ($tiny !== '') {
        $add('info', 'TinyMCE ' . $tiny, 'Bundled with ResourceSpace (lib/tinymce). Known vulnerabilities are fixed by updating ResourceSpace; check the version after each update.');
    }

    if (is_dir(dirname(__FILE__, 4) . '/plugins/simplesaml')) {
        $add($s['saml_panel'] !== 'open' ? 'ok' : 'warn', 'SimpleSAMLphp local login',
            $s['saml_panel'] !== 'open' ? 'Local login and admin pages: ' . $s['saml_panel'] . '.'
                : 'The local login form and admin pages of SimpleSAMLphp are open to everyone. Choose "allowlist" or "block" below, or restrict them in nginx (snippet below).');
        $add('info', 'SimpleSAMLphp error pages', 'Hidden by the plugin when SimpleSAMLphp reads its configuration from ResourceSpace ($simplesaml_rsconfig). '
            . 'Otherwise set showerrors / errorreporting to false in its config.php.');
    }

    $state = $g['resource_deletion_state'] ?? null;
    $add($state !== null ? 'ok' : 'warn', 'Deleting resources',
        $state !== null ? 'Deleted resources first go to the state ' . (int) $state . ' ("Deleted") and can be restored; permanent deletion: '
            . ($s['del_perm_mode'] === 'block' ? 'off in the browser.' : 'limited, above the limit with approval.')
            : '$resource_deletion_state is not set: deleting removes files at once. Turn on "Always move to Deleted first" below.');

    $add(!empty($g['share_password_required']) ? 'ok' : 'warn', 'External shares',
        (!empty($g['share_password_required']) ? 'Password required' : 'No password required ($share_password_required)')
        . sprintf(', at most %d days, "Never" %s.', (int) ($g['resource_share_expire_days'] ?? 0), !empty($g['resource_share_expire_never']) ? 'allowed' : 'not allowed')
        . ($s['share_enabled'] ? ' (share policy of this plugin is on)' : ' Turn on the share policy below to enforce it.'));

    $add($s['up_mode'] === 'enforce' ? 'ok' : ($s['up_mode'] === 'log' ? 'info' : 'warn'), 'Upload verification',
        $s['up_mode'] === 'enforce' ? 'On: file types are checked' . ($s['up_inspect'] ? ', doubtful files go to the quarantine' : '') . ($s['up_clamav'] ? ', virus scan with ClamAV' : '') . '.'
            : ($s['up_mode'] === 'log' ? 'Log only: uploads are checked and logged but not blocked. Check the log, then switch to "enforce".'
                : 'Off - uploaded files are only checked by ResourceSpace ($banned_extensions).'));

    $add($s['notify_enabled'] && ($s['notify_users'] || $s['notify_groups']) ? 'ok' : 'info', 'Incident notifications',
        $s['notify_enabled'] ? sprintf('On: %d user name(s), %d user group(s), incidents: %s.', count($s['notify_users']), count($s['notify_groups']), implode(', ', $s['notify_events']) ?: 'none')
            : 'Off - incidents are only written to the security log. Turn on "Incident notifications" below.');

    $add(is_file(security_guard_kill_file()) || !empty($g['security_guard_disable']) ? 'warn' : 'ok', 'Emergency switch',
        is_file(security_guard_kill_file()) ? 'The file ' . security_guard_kill_file() . ' exists - all checks are OFF.'
            : (!empty($g['security_guard_disable']) ? '$security_guard_disable is set in config.php - all checks are OFF.' : 'Not used.'));
    return $c;
}

// nginx snippet for the parts a plugin cannot see (static files, rate limits before PHP)
function security_guard_nginx_snippet(array $s)
{
    $allow = '';
    foreach ($s['admin_ips'] as $ip) {
        $allow .= '        allow ' . $ip . ";\n";
    }
    if ($allow === '') {
        $allow = "        allow 192.0.2.10;                 # example - your office / VPN address\n";
    }
    return "# Template - adjust the PHP lines (fastcgi_pass, includes) to your main PHP location.\n"
        . "# --- http { } block (e.g. /etc/nginx/conf.d/security_guard.conf) ---\n"
        . "server_tokens off;                                   # no nginx version in headers and error pages\n"
        . "limit_req_zone \$binary_remote_addr zone=rs_login:10m rate=10r/m;\n\n"
        . "# --- server { } block of ResourceSpace ---\n"
        . "location = /login.php {\n        limit_req zone=rs_login burst=10 nodelay;\n        include snippets/fastcgi-php.conf;  # same lines as your main PHP location\n        fastcgi_pass unix:/run/php/php8.3-fpm.sock;\n}\n"
        . "location = /api/index.php {\n        limit_req zone=rs_login burst=60 nodelay;\n        include snippets/fastcgi-php.conf;\n        fastcgi_pass unix:/run/php/php8.3-fpm.sock;\n}\n"
        . "# SimpleSAMLphp: local login form and admin pages only from these addresses (SSO stays open)\n"
        . "location ~ ^/plugins/simplesaml/lib/(public|www)/(admin|module\\.php/(admin|core/(login|loginuserpass|frontpage))) {\n"
        . $allow
        . "        deny all;\n        limit_req zone=rs_login burst=5 nodelay;\n        fastcgi_split_path_info ^(.+?\\.php)(/.*)\$;\n        include snippets/fastcgi-php.conf;\n        fastcgi_pass unix:/run/php/php8.3-fpm.sock;\n}\n"
        . "# no access to hidden and backup files\n"
        . "location ~ /\\.(?!well-known) { deny all; }\n"
        . "location ~* \\.(bak|old|orig|sql|swp|log)\$ { deny all; }\n";
}

// fail2ban filter and jail reading the security log
function security_guard_fail2ban_snippet()
{
    $log = security_guard_log_file();
    return "# /etc/fail2ban/filter.d/resourcespace-security-guard.conf\n"
        . "[Definition]\n"
        . "failregex = ^\\S+ \\[security_guard\\] action=block rule=\\S+ ip=<HOST> \n"
        . "ignoreregex =\n\n"
        . "# /etc/fail2ban/jail.d/resourcespace-security-guard.conf\n"
        . "[resourcespace-security-guard]\n"
        . "enabled  = true\n"
        . "port     = http,https\n"
        . "filter   = resourcespace-security-guard\n"
        . "logpath  = " . $log . "\n"
        . "maxretry = 5\n"
        . "findtime = 600\n"
        . "bantime  = 3600\n"
        . "# then: sudo systemctl reload fail2ban; sudo fail2ban-client status resourcespace-security-guard\n"
        . "# Behind a proxy / load balancer the server only sees the proxy address: ban there instead.\n";
}

// ---- Deletion approvals (options page, since 1.01) -------------------------------------------

// ['requests' => newest first, 'grants' => active approvals]
function security_guard_deletion_data()
{
    $file = security_guard_deletion_file();
    $data = is_file($file) && is_readable($file) ? json_decode((string) file_get_contents($file), true) : null;
    $data = is_array($data) ? $data + array('requests' => array(), 'grants' => array()) : array('requests' => array(), 'grants' => array());
    $grants = array();
    foreach ((array) $data['grants'] as $user => $g) {
        if (is_array($g) && (int) $g['until'] >= time()) {
            $grants[(int) $user] = $g;
        }
    }
    return array('requests' => array_reverse((array) $data['requests']), 'grants' => $grants);
}

// Approves or rejects a request; returns '' or an error message
function security_guard_deletion_decide($id, $approve, array $admin, $minutes, $four_eyes)
{
    $minutes = max(5, min(1440, (int) $minutes));
    $res = security_guard_deletion_update(function (array &$d) use ($id, $approve, $admin, $minutes, $four_eyes) {
        foreach ($d['requests'] as $i => $r) {
            if ((int) $r['id'] !== (int) $id) {
                continue;
            }
            if ($r['status'] !== 'pending') {
                return 'Request #' . (int) $id . ' was already decided.';
            }
            if ($approve && $four_eyes && (int) $r['user'] === (int) $admin['ref']) {
                return 'Request #' . (int) $id . ' is your own - another administrator must approve it ("four eyes").';
            }
            $d['requests'][$i]['status']  = $approve ? 'approved' : 'rejected';
            $d['requests'][$i]['by']      = $admin['username'];
            $d['requests'][$i]['decided'] = time();
            if ($approve) {
                $k = (string) (int) $r['user'];
                $prev = (isset($d['grants'][$k]) && (int) $d['grants'][$k]['until'] >= time()) ? (int) $d['grants'][$k]['remaining'] : 0;
                $d['grants'][$k] = array('username' => $r['username'], 'remaining' => $prev + (int) $r['soft'] + (int) $r['perm'],
                    'until' => time() + $minutes * 60, 'by' => $admin['username'], 'time' => time());
            }
            return '';
        }
        return 'Request #' . (int) $id . ' not found.';
    });
    if ($res === null) {
        return 'The approvals could not be stored (check write access to ' . security_guard_data_dir() . ').';
    }
    if ($res === '') {
        security_guard_log($approve ? 'allow' : 'log', $approve ? 'delete_request_approved' : 'delete_request_rejected', 'request #' . (int) $id . ' by ' . $admin['username']);
    }
    return $res;
}

// Approval given without a request (e.g. before a planned clean-up); returns '' or an error
function security_guard_deletion_grant($username, $count, $minutes, array $admin, $four_eyes)
{
    $username = trim((string) $username);
    $count    = max(1, min(1000000, (int) $count));
    $minutes  = max(5, min(1440, (int) $minutes));
    $rows = $username !== '' ? ps_query('SELECT ref, username FROM user WHERE username = ? LIMIT 1', array('s', $username)) : array();
    if (empty($rows)) {
        return 'User "' . $username . '" not found.';
    }
    $ref = (int) $rows[0]['ref'];
    if ($four_eyes && $ref === (int) $admin['ref']) {
        return 'You cannot approve deletions for yourself - another administrator must do it ("four eyes").';
    }
    $ok = security_guard_deletion_update(function (array &$d) use ($ref, $rows, $count, $minutes, $admin) {
        $d['grants'][(string) $ref] = array('username' => (string) $rows[0]['username'], 'remaining' => $count,
            'until' => time() + $minutes * 60, 'by' => $admin['username'], 'time' => time());
        return true;
    });
    if (!$ok) {
        return 'The approval could not be stored (check write access to ' . security_guard_data_dir() . ').';
    }
    security_guard_log('allow', 'delete_grant', $count . ' resource(s) for ' . $rows[0]['username'] . ', ' . $minutes . ' min, by ' . $admin['username']);
    return '';
}

function security_guard_deletion_revoke($user, array $admin)
{
    security_guard_deletion_update(function (array &$d) use ($user) {
        unset($d['grants'][(string) (int) $user]);
        return true;
    });
    security_guard_log('log', 'delete_grant_revoked', 'user ' . (int) $user . ' by ' . $admin['username']);
}

// ---- Incident notifications (options page, since 1.02) ---------------------------------------

// User groups: [ref => name]
function security_guard_usergroups()
{
    $out = array();
    try {
        foreach (ps_query('SELECT ref, name FROM usergroup ORDER BY name', array()) as $g) {
            $name = function_exists('i18n_get_translated') ? i18n_get_translated((string) $g['name']) : (string) $g['name'];
            $out[(int) $g['ref']] = $name;
        }
    } catch (Throwable $e) {
        return array();
    }
    return $out;
}

// User names that do not exist
function security_guard_unknown_users(array $names)
{
    if (!$names) {
        return array();
    }
    $params = array();
    foreach ($names as $n) {
        $params[] = 's';
        $params[] = $n;
    }
    $found = array_map('strtolower', (array) ps_array('SELECT username value FROM user WHERE username IN (' . implode(',', array_fill(0, count($names), '?')) . ')', $params));
    return array_values(array_filter($names, function ($n) use ($found) {
        return !in_array(strtolower($n), $found, true);
    }));
}

// Names of the settings that changed (for the log / "admin" notifications)
function security_guard_settings_changes(array $old, array $new)
{
    $out = array();
    foreach ($new as $k => $v) {
        if (!array_key_exists($k, $old) || $old[$k] === $v) {
            continue;
        }
        $out[] = is_bool($v) ? $k . '=' . ($v ? 'on' : 'off') : (is_array($v) ? $k : $k . '=' . (is_scalar($v) ? (string) $v : ''));
    }
    return array_slice($out, 0, 25);
}

// ---- Upload quarantine (options page, since 1.04) ---------------------------------------------

// ['items' => newest first, 'approved' => active approvals by checksum]
function security_guard_upload_data()
{
    require_once __DIR__ . '/upload.php';
    $file = security_guard_upload_file();
    $data = is_file($file) && is_readable($file) ? json_decode((string) file_get_contents($file), true) : null;
    $data = is_array($data) ? $data + array('items' => array(), 'approved' => array()) : array('items' => array(), 'approved' => array());
    $approved = array();
    foreach ((array) $data['approved'] as $sha => $a) {
        if (is_array($a) && (int) $a['until'] >= time()) {
            $approved[$sha] = $a;
        }
    }
    return array('items' => array_reverse((array) $data['items']), 'approved' => $approved);
}

// Approves (the user may upload the same file again) or rejects a quarantined file; '' or an error
function security_guard_upload_decide($id, $approve, array $admin, array $s)
{
    require_once __DIR__ . '/upload.php';
    $dir = security_guard_quarantine_dir();
    $hours = max(1, min(720, (int) $s['up_grant_hours']));
    $res = security_guard_upload_update(function (array &$d) use ($id, $approve, $admin, $s, $dir, $hours) {
        foreach ($d['items'] as $i => $it) {
            if ((int) $it['id'] !== (int) $id) {
                continue;
            }
            if ($it['status'] !== 'pending') {
                return 'File #' . (int) $id . ' was already decided.';
            }
            if ($approve && $s['up_four_eyes'] && (int) $it['user'] === (int) $admin['ref']) {
                return 'File #' . (int) $id . ' was uploaded by you - another administrator must approve it ("four eyes").';
            }
            $d['items'][$i]['status']  = $approve ? 'approved' : 'rejected';
            $d['items'][$i]['by']      = $admin['username'];
            $d['items'][$i]['decided'] = time();
            if ($approve && $it['sha256'] !== '') {
                $d['approved'][$it['sha256']] = array('user' => (int) $it['user'], 'username' => $it['username'], 'name' => $it['name'],
                    'until' => time() + $hours * 3600, 'by' => $admin['username']);
            }
            // the file is not kept after the decision (an approved file is uploaded again)
            if ($it['file'] !== '' && is_file($dir . '/' . $it['file'])) {
                unlink($dir . '/' . $it['file']);
            }
            $d['items'][$i]['file'] = '';
            return '';
        }
        return 'File #' . (int) $id . ' not found.';
    });
    if ($res === null) {
        return 'The quarantine could not be updated (check write access to ' . security_guard_data_dir() . ').';
    }
    if ($res === '') {
        security_guard_log($approve ? 'allow' : 'log', $approve ? 'upload_release' : 'upload_rejected', 'file #' . (int) $id . ' by ' . $admin['username']);
    }
    return $res;
}

// Sends a quarantined file to the administrator (as a download, never displayed); false if missing
function security_guard_upload_download($id)
{
    require_once __DIR__ . '/upload.php';
    foreach (security_guard_upload_data()['items'] as $it) {
        if ((int) $it['id'] !== (int) $id || $it['file'] === '') {
            continue;
        }
        $path = security_guard_quarantine_dir() . '/' . $it['file'];
        if (!is_file($path) || !is_readable($path)) {
            return false;
        }
        $name = preg_replace('/[^A-Za-z0-9._-]+/', '_', (string) $it['name']) . '.quarantine';
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . $name . '"');
        header('X-Content-Type-Options: nosniff');
        header('Content-Security-Policy: sandbox');
        header('Content-Length: ' . filesize($path));
        header('Cache-Control: no-store');
        readfile($path);
        return true;
    }
    return false;
}
