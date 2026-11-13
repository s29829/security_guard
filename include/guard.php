<?php
// Security Guard - request checks that run on every request (hook "initialise", include/boot.php).
//
// Kept small on purpose: a normal request costs a few string comparisons and one include of the
// settings file (a PHP array, cached by OPcache). The database and the disk are only used when
// something is blocked or logged, for API logins and for posts to the SimpleSAMLphp login form.
//
// Emergency switches (no code change needed):
//   - $security_guard_disable = true;  in include/config.php
//   - an empty file  <filestore>/security_guard/disabled
//   - move the folder plugins/security_guard away (ResourceSpace skips plugins without files)

if (defined('SECURITY_GUARD_LOADED')) {
    return;
}
define('SECURITY_GUARD_LOADED', true);

// ---- Storage -------------------------------------------------------------------------------

function security_guard_storage_dir()
{
    $s = (string) ($GLOBALS['storagedir'] ?? '');
    return rtrim($s !== '' ? $s : dirname(__FILE__, 4) . '/filestore', '/');
}

// <filestore>/security_guard - everything the plugin stores (removed by "Reset plugin")
function security_guard_base_dir()
{
    return security_guard_storage_dir() . '/security_guard';
}

// Settings, log and counters: not readable by URL (folder name derived from $scramble_key)
function security_guard_data_dir()
{
    $key = (string) ($GLOBALS['scramble_key'] ?? '');
    return security_guard_base_dir() . '/data' . ($key !== '' ? '_' . substr(md5($key . 'security_guard'), 0, 12) : '');
}

function security_guard_settings_file()
{
    return security_guard_data_dir() . '/settings.php';
}

function security_guard_log_file()
{
    return security_guard_data_dir() . '/events.log';
}

// Emergency switch file (fixed name, so it can be created from the command line)
function security_guard_kill_file()
{
    return security_guard_base_dir() . '/disabled';
}

function security_guard_mkdir($dir)
{
    if (is_dir($dir)) {
        return true;
    }
    return mkdir($dir, 0755, true) || is_dir($dir);
}

// ---- Settings ------------------------------------------------------------------------------

function security_guard_defaults()
{
    return array(
        'enabled'              => true,
        // patches for known weaknesses
        'patch_report_params'  => true,   // numeric date parameters of reports (SQL injection)
        'patch_login_redirect' => true,   // "url" of login.php / terms.php only to this site
        'patch_api_confusion'  => true,   // "function" outside "query" must match the one in "query"
        'patch_api_lockout'    => true,   // API login respects the login lockouts of ResourceSpace
        'patch_get_session'    => true,   // session hash not accepted in the URL (?user=)
        'force_random_session' => false,  // $randomised_session_hash = true (one session per account)
        // SimpleSAMLphp (only when it loads ResourceSpace, i.e. config from config.php)
        'saml_hide_errors'     => true,   // showerrors / errorreporting off
        'saml_panel'           => 'open', // local login and admin pages: open | allowlist | block
        'saml_limit'           => 10,     // posts to the local login form per IP and window (0 = off)
        'saml_window'          => 10,     // minutes
        // firewall
        'trusted_proxies'      => array(),
        'blocklist'            => array(),
        'admin_ips'            => array(),
        'admin_paths'          => array('pages/admin/', 'pages/team/', 'plugins/*/pages/'),
        'api_ips'              => array(),
        'block_scanners'       => true,
        'scanner_agents'       => array('sqlmap', 'nikto', 'nuclei', 'acunetix', 'nessus', 'openvas', 'masscan', 'zgrab',
                                        'wpscan', 'dirbuster', 'gobuster', 'feroxbuster', 'ffuf', 'wfuzz', 'hydra', 'netsparker', 'w3af'),
        'waf_mode'             => 'log',  // off | log | block
        'waf_skip_paths'       => array('plugins/customcss/pages/', 'pages/admin/admin_content'),
        // response headers
        'remove_powered_by'    => true,
        'permissions_policy'   => 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
        // log
        'log_max_kb'           => 2048,
        // deletion protection (since 1.01)
        'del_enabled'          => true,
        'del_force_trash'      => true,   // deleting moves to the "Deleted" state first ($resource_deletion_state)
        'del_soft_limit'       => 50,     // resources moved to "Deleted" per user and window without approval (0 = no limit)
        'del_perm_mode'        => 'limit', // permanent deletion in the browser: limit | block
        'del_perm_limit'       => 10,     // permanent deletions per user and window without approval (0 = always approval)
        'del_window'           => 60,     // minutes
        'del_four_eyes'        => true,   // the approver must be another administrator
        'del_grant_minutes'    => 60,     // validity of an approval
        'del_notify'           => true,   // notify administrators about new requests (ResourceSpace messages)
        // share policy (since 1.01)
        'share_enabled'        => false,
        'share_require_password' => true,
        'share_password_length'  => 12,   // minimum length, also the length of generated passwords
        'share_generate_password' => true, // propose a random password in the share forms
        'share_default_days'   => 14,
        'share_max_days'       => 30,
        'share_user_can_change' => true,  // users may choose another expiry date (up to the maximum)
        'share_allow_never'    => false,  // "Never" expires
        // incident notifications (since 1.02)
        'notify_enabled'       => false,
        'notify_users'         => array(),  // user names
        'notify_groups'        => array(),  // user group refs
        'notify_events'        => array('attack', 'bruteforce', 'deletion', 'admin'),
        'notify_screen'        => true,     // ResourceSpace notification (bell)
        'notify_email'         => true,     // e-mail to the address of the user account
        'notify_throttle'      => 15,       // minutes: one notification per rule and address
        'notify_max_per_hour'  => 30,       // all notifications per hour
    );
}

// Incident categories: key => label (notifications, since 1.02)
function security_guard_incident_categories()
{
    return array(
        'attack'     => 'Blocked attacks (firewall, patches, attack patterns in "block" mode)',
        'bruteforce' => 'Login attacks (API login lockout, SimpleSAMLphp login limit)',
        'deletion'   => 'Deletion of many resources (approval requests, blocked permanent deletion, approvals given)',
        'detection'  => 'Detections without blocking (attack patterns in "log only" mode, corrected login redirect, session in the URL)',
        'admin'      => 'Changes of Security Guard (settings, protection switched off, log cleared, reset)',
    );
}

// Category of a log event ('' = no notification)
function security_guard_incident_category($action, $rule)
{
    if ($action === 'admin') {
        return 'admin';
    }
    if (strpos($rule, 'delete_') === 0) {
        // approval requests notify from security_guard_deletion_gate() (with the administrators)
        return ($rule === 'delete_approval' || $rule === 'delete_grant_revoked' || $rule === 'delete_request_rejected') ? '' : 'deletion';
    }
    if ($action === 'block') {
        if ($rule === 'api_lockout' || $rule === 'saml_bruteforce') {
            return 'bruteforce';
        }
        return $rule === 'share_password' ? '' : 'attack';
    }
    if (($action === 'log' && strpos($rule, 'waf_') === 0) || ($action === 'fix' && ($rule === 'login_redirect' || $rule === 'get_session'))) {
        return 'detection';
    }
    return '';
}

function security_guard_settings()
{
    static $settings = null;
    if ($settings !== null) {
        return $settings;
    }
    $settings = security_guard_defaults();
    $file = security_guard_settings_file();
    if (is_file($file) && is_readable($file)) {
        $saved = include $file;
        if (is_array($saved)) {
            foreach ($saved as $k => $v) {
                if (array_key_exists($k, $settings) && gettype($v) === gettype($settings[$k])) {
                    $settings[$k] = $v;
                }
            }
        }
    }
    return $settings;
}

// ---- Request helpers -----------------------------------------------------------------------

// Path of the request relative to the ResourceSpace root, e.g. "pages/team/team_report.php"
// (for SimpleSAMLphp also the path info: "plugins/simplesaml/lib/public/module.php/core/...")
function security_guard_path()
{
    $path = (string) parse_url((string) ($_SERVER['REQUEST_URI'] ?? ''), PHP_URL_PATH);
    if ($path === '') {
        $path = (string) ($_SERVER['PHP_SELF'] ?? '');
    }
    $path = rawurldecode($path);
    $base = (string) parse_url((string) ($GLOBALS['baseurl_short'] ?? '/'), PHP_URL_PATH);
    $base = '/' . trim($base, '/');
    $base = $base === '/' ? '/' : $base . '/';
    if (strpos($path, $base) === 0) {
        $path = substr($path, strlen($base));
    }
    return ltrim($path, '/');
}

// Does the path start with one of the prefixes ("*" = any folder name)?
function security_guard_path_match($path, array $prefixes)
{
    foreach ($prefixes as $p) {
        $p = ltrim(trim((string) $p), '/');
        if ($p === '') {
            continue;
        }
        if (strpos($p, '*') === false) {
            if (strpos($path, $p) === 0) {
                return true;
            }
        } elseif (preg_match('#^' . str_replace('\*', '[^/]+', preg_quote($p, '#')) . '#', $path)) {
            return true;
        }
    }
    return false;
}

// Is the address in one of the networks (IPv4 / IPv6, "10.0.0.0/8", "2001:db8::/32" or one address)?
function security_guard_ip_in($ip, array $cidrs)
{
    $bin = inet_pton((string) $ip);
    if ($bin === false) {
        return false;
    }
    foreach ($cidrs as $cidr) {
        $cidr = trim((string) $cidr);
        if ($cidr === '') {
            continue;
        }
        $bits = null;
        if (strpos($cidr, '/') !== false) {
            list($net, $bits) = explode('/', $cidr, 2);
            $bits = (int) $bits;
        } else {
            $net = $cidr;
        }
        $nbin = inet_pton($net);
        if ($nbin === false || strlen($nbin) !== strlen($bin)) {
            continue;
        }
        $max = strlen($bin) * 8;
        $bits = $bits === null ? $max : max(0, min($max, $bits));
        $bytes = intdiv($bits, 8);
        if (substr($bin, 0, $bytes) !== substr($nbin, 0, $bytes)) {
            continue;
        }
        $rest = $bits % 8;
        if ($rest === 0) {
            return true;
        }
        $mask = (0xff << (8 - $rest)) & 0xff;
        if ((ord($bin[$bytes]) & $mask) === (ord($nbin[$bytes]) & $mask)) {
            return true;
        }
    }
    return false;
}

// Address of the client. X-Forwarded-For is used only when the request comes from a trusted
// proxy (setting "trusted_proxies"); then the last address that is not a trusted proxy wins.
function security_guard_client_ip(?array $s = null)
{
    $s = $s ?? security_guard_settings();
    $remote = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
    if (!$s['trusted_proxies'] || !security_guard_ip_in($remote, $s['trusted_proxies'])) {
        return $remote;
    }
    $chain = array_reverse(array_map('trim', explode(',', (string) ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? ''))));
    foreach ($chain as $ip) {
        if ($ip !== '' && inet_pton($ip) !== false && !security_guard_ip_in($ip, $s['trusted_proxies'])) {
            return $ip;
        }
    }
    return $remote;
}

// ---- Log -------------------------------------------------------------------------------------

// One line per event; "action=block ... ip=<address>" lines can be used by fail2ban.
function security_guard_log($action, $rule, $detail = '', $ref = '')
{
    $s = security_guard_settings();
    $dir = security_guard_data_dir();
    if (!security_guard_mkdir($dir)) {
        return;
    }
    $file = security_guard_log_file();
    $max = max(64, (int) $s['log_max_kb']) * 1024;
    if (is_file($file) && filesize($file) > $max) {
        if (is_file($file . '.1')) {
            unlink($file . '.1');
        }
        rename($file, $file . '.1');
    }
    $clean = function ($v, $len) {
        $v = preg_replace('/[\x00-\x1f\x7f"]+/', ' ', (string) $v);
        return function_exists('mb_substr') ? mb_substr($v, 0, $len) : substr($v, 0, $len);
    };
    $line = date('c') . ' [security_guard] action=' . $action . ' rule=' . $rule
        . ' ip=' . $clean(security_guard_client_ip($s), 45)
        . ($ref !== '' ? ' ref=' . $ref : '')
        . ' method=' . $clean($_SERVER['REQUEST_METHOD'] ?? '', 10)
        . ' path="/' . $clean(security_guard_path(), 200) . '"'
        . ($detail !== '' ? ' detail="' . $clean($detail, 300) . '"' : '') . "\n";
    file_put_contents($file, $line, FILE_APPEND | LOCK_EX);

    // incident notification (only events; throttled)
    if ($s['notify_enabled']) {
        $category = security_guard_incident_category($action, $rule);
        if ($category !== '' && in_array($category, $s['notify_events'], true)) {
            security_guard_incident($category, $action, $rule, $detail, $ref);
        }
    }
}

// Stops the request. The answer only contains a reference (and, for rules the user can act on,
// an explanation); the reason is in the log.
function security_guard_deny($code, $rule, $detail = '', $json = false, $message = '')
{
    $ref = substr(bin2hex(random_bytes(6)), 0, 10);
    security_guard_log('block', $rule, $detail, $ref);
    if (!headers_sent()) {
        http_response_code($code);
        header('Cache-Control: no-store');
        header('Content-Type: ' . ($json ? 'application/json' : 'text/plain') . '; charset=UTF-8');
    }
    $text = ($message !== '' ? $message . ' ' : 'Request blocked. ') . 'Reference: ' . $ref;
    echo $json ? json_encode(array('error' => array('status' => $code, 'title' => 'Request blocked', 'detail' => $text)))
        : $text;
    exit;
}

// ---- Checks ------------------------------------------------------------------------------------

// Is the value a safe target for a redirect after login (a path on this site)?
function security_guard_safe_redirect($url)
{
    if (!is_string($url)) {
        return false;
    }
    $u = trim($url);
    if ($u === '') {
        return true;
    }
    if (preg_match('/[\x00-\x1f\x7f]/', $u) || strpos($u, '\\') !== false) {
        return false;
    }
    if (substr($u, 0, 2) === '//') {
        return false;
    }
    // a scheme ("https:", "javascript:") is only allowed for addresses of this site
    if (preg_match('#^[a-z][a-z0-9+.\-]*:#i', $u)) {
        $base = rtrim((string) ($GLOBALS['baseurl'] ?? ''), '/');
        return $base !== '' && ($u === $base || strpos($u, $base . '/') === 0 || strpos($u, $base . '?') === 0);
    }
    return true;
}

// Values of GET and POST (also nested), at most $limit values
function security_guard_values(array $src, $limit, &$out)
{
    foreach ($src as $k => $v) {
        if (count($out) >= $limit) {
            return;
        }
        if (is_array($v)) {
            security_guard_values($v, $limit, $out);
        } elseif (is_string($v) && $v !== '') {
            $out[] = array((string) $k, $v);
        }
    }
}

// Typical attack patterns (SQL injection, XSS, path traversal). Returns the matched name or ''.
function security_guard_signature($value)
{
    static $rules = array(
        'sql_union'     => '/\bunion\b[\s\/*+()]{1,40}(all[\s\/*+()]+)?select\b/i',
        'sql_time'      => '/\b(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(/i',
        'sql_schema'    => '/\binformation_schema\b|\bmysql\.user\b/i',
        'sql_rlike'     => '/\brlike\s*\(\s*select\b/i',
        'sql_tautology' => '/[\'")]\s*(or|and)\s+[\'"]?(\d+)[\'"]?\s*=\s*[\'"]?\2\b/i',
        'xss_script'    => '/<\s*script\b|javascript\s*:|\bon(error|load|mouseover|focus)\s*=/i',
        'traversal'     => '#(\.\./){2,}|/etc/passwd|\x00#i',
    );
    if (strlen($value) > 8192) {
        $value = substr($value, 0, 8192);
    }
    foreach ($rules as $name => $rx) {
        if (preg_match($rx, $value)) {
            return $name;
        }
    }
    return '';
}

// ---- Main ----------------------------------------------------------------------------------------

function security_guard_run()
{
    if (PHP_SAPI === 'cli' || !empty($GLOBALS['security_guard_disable']) || is_file(security_guard_kill_file())) {
        return;
    }
    $s = security_guard_settings();
    if (!$s['enabled']) {
        return;
    }
    $path   = security_guard_path();
    $ip     = security_guard_client_ip($s);
    $method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
    $is_api = $path === 'api/' || strpos($path, 'api/index.php') === 0;

    // deleting first moves resources to the "Deleted" state (also used by the deletion checks below)
    if ($s['del_enabled'] && $s['del_force_trash'] && !isset($GLOBALS['resource_deletion_state'])) {
        $GLOBALS['resource_deletion_state'] = 3;
    }

    // -- response headers
    if (!headers_sent()) {
        if ($s['remove_powered_by']) {
            header_remove('X-Powered-By');
        }
        if (trim($s['permissions_policy']) !== '') {
            header('Permissions-Policy: ' . preg_replace('/[\r\n]+/', ' ', $s['permissions_policy']));
        }
    }

    // -- firewall: blocked addresses, scanners, admin / API allowlists
    if ($s['blocklist'] && security_guard_ip_in($ip, $s['blocklist'])) {
        security_guard_deny(403, 'ip_blocklist', '', $is_api);
    }
    if ($s['block_scanners'] && $s['scanner_agents']) {
        $ua = strtolower((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''));
        foreach ($s['scanner_agents'] as $a) {
            $a = strtolower(trim((string) $a));
            if ($a !== '' && strpos($ua, $a) !== false) {
                security_guard_deny(403, 'scanner', 'user agent: ' . $a, $is_api);
            }
        }
    }
    if ($s['admin_ips'] && security_guard_path_match($path, $s['admin_paths']) && !security_guard_ip_in($ip, $s['admin_ips'])) {
        security_guard_deny(403, 'admin_allowlist');
    }

    // -- API
    if ($is_api) {
        security_guard_check_api($s, $ip);
    } elseif ($s['patch_get_session'] && array_key_exists('user', $_GET)) {
        // the session hash only from the cookie (authenticate.php reads $_GET['user'] first)
        unset($_GET['user'], $_REQUEST['user']);
        security_guard_log('fix', 'get_session');
    }

    // -- SimpleSAMLphp (this hook runs there only when SimpleSAMLphp loads ResourceSpace)
    if (strpos($path, 'plugins/simplesaml/') === 0) {
        security_guard_check_saml($s, $ip, $path, $method);
    }

    // -- numeric date parameters of reports (team_report.php, periodic report e-mails)
    if ($s['patch_report_params']) {
        foreach (array('from-y' => 4, 'from-m' => 2, 'from-d' => 2, 'to-y' => 4, 'to-m' => 2, 'to-d' => 2, 'period_days' => 5) as $p => $len) {
            foreach (array($_GET, $_POST) as $src) {
                if (array_key_exists($p, $src) && !(is_string($src[$p]) && preg_match('/^\d{0,' . $len . '}$/', $src[$p]))) {
                    security_guard_deny(400, 'report_param', $p);
                }
            }
        }
    }

    // -- redirect after login only to this site
    if ($s['patch_login_redirect'] && ($path === 'login.php' || $path === 'pages/terms.php')) {
        if (isset($_GET['url']) && !security_guard_safe_redirect($_GET['url'])) {
            security_guard_log('fix', 'login_redirect', is_string($_GET['url']) ? $_GET['url'] : 'array');
            $_GET['url'] = 'index.php';
            $_REQUEST['url'] = 'index.php';
        }
        if (isset($_POST['url']) && !security_guard_safe_redirect($_POST['url'])) {
            security_guard_log('fix', 'login_redirect', is_string($_POST['url']) ? $_POST['url'] : 'array');
            $_POST['url'] = 'index.php';
            $_REQUEST['url'] = 'index.php';
        }
    }

    // -- deletion protection: deleting collections of resources in the browser
    if ($s['del_enabled'] && $method === 'POST' && !$is_api) {
        security_guard_check_deletion_page($s, $path);
    }

    // -- share policy: password and expiry of external shares
    if ($s['share_enabled']) {
        security_guard_share_policy($s, $path);
    }

    // -- one session per account: a new random session hash at every login
    if ($s['force_random_session']) {
        $GLOBALS['randomised_session_hash'] = true;
    }

    // -- attack patterns in parameters (log or block)
    if ($s['waf_mode'] !== 'off' && ($_GET || $_POST) && !security_guard_path_match($path, $s['waf_skip_paths'])) {
        $values = array();
        security_guard_values($_GET, 300, $values);
        security_guard_values($_POST, 300, $values);
        foreach ($values as $kv) {
            $hit = security_guard_signature($kv[1]);
            if ($hit !== '') {
                if ($s['waf_mode'] === 'block') {
                    security_guard_deny(403, 'waf_' . $hit, 'parameter: ' . $kv[0], $is_api);
                }
                security_guard_log('log', 'waf_' . $hit, 'parameter: ' . $kv[0]);
                break;
            }
        }
    }
}

function security_guard_check_api(array $s, $ip)
{
    // the same "query" api/index.php uses (getval: POST, GET, cookie)
    $query = (string) ($_SERVER['QUERY_STRING'] ?? '');
    foreach (array($_POST, $_GET, $_COOKIE) as $src) {
        if (array_key_exists('query', $src)) {
            if (is_string($src['query']) && $src['query'] !== '') {
                $query = $src['query'];
            }
            break;
        }
    }
    $params = array();
    parse_str($query, $params);
    $qfunc = is_string($params['function'] ?? null) ? $params['function'] : '';

    $authmode = '';
    foreach (array($_POST, $_GET, $_COOKIE) as $src) {
        if (array_key_exists('authmode', $src)) {
            $authmode = is_string($src['authmode']) ? $src['authmode'] : '';
            break;
        }
    }

    // MED: function=login outside "query" skipped the authentication of api/index.php
    if ($s['patch_api_confusion']) {
        foreach (array($_POST, $_GET, $_COOKIE) as $src) {
            if (array_key_exists('function', $src)) {
                if (!is_string($src['function']) || $src['function'] !== $qfunc) {
                    security_guard_deny(403, 'api_confusion', 'function=' . (is_string($src['function']) ? $src['function'] : 'array') . ' query function=' . $qfunc, true);
                }
                break;
            }
        }
    }

    // API keys only from allowed addresses (the browser interface uses authmode=native and stays open)
    if ($s['api_ips'] && $authmode !== 'native' && !security_guard_ip_in($ip, $s['api_ips'])) {
        security_guard_deny(403, 'api_allowlist', '', true);
    }

    // login through the API: same lockouts as login.php
    if ($s['patch_api_lockout'] && $qfunc === 'login' && function_exists('ps_value')) {
        $rs_ip   = function_exists('get_ip') ? (string) get_ip() : $ip;
        $per_ip  = (int) ($GLOBALS['max_login_attempts_per_ip'] ?? 20);
        $per_usr = (int) ($GLOBALS['max_login_attempts_per_username'] ?? 5);
        $wait    = (int) ($GLOBALS['max_login_attempts_wait_minutes'] ?? 10);
        $user    = is_string($params['param1'] ?? null) ? $params['param1'] : (is_string($params['username'] ?? null) ? $params['username'] : '');
        try {
            $locked = (int) ps_value('SELECT count(*) value FROM ip_lockout WHERE ip = ? AND tries >= ? AND date_add(last_try, interval ? minute) > now()',
                array('s', $rs_ip, 'i', $per_ip, 'i', $wait), 0);
            if (!$locked && $user !== '') {
                $locked = (int) ps_value('SELECT count(*) value FROM user WHERE username = ? AND login_tries >= ? AND date_add(login_last_try, interval ? minute) > now()',
                    array('s', $user, 'i', $per_usr, 'i', $wait), 0);
            }
        } catch (Throwable $e) {
            $locked = 0;
        }
        if ($locked) {
            security_guard_deny(429, 'api_lockout', $user !== '' ? 'username: ' . $user : '', true);
        }
    }

    // deletion through the API (the browser interface deletes resources this way)
    if ($s['del_enabled'] && in_array($qfunc, array('delete_resource', 'delete_resources_in_collection', 'delete_alternative_file'), true)) {
        $p1 = $params['param1'] ?? null;
        if ($qfunc === 'delete_resource') {
            $counts = security_guard_count_resources(array((int) ($p1 ?? $params['resource'] ?? 0)));
        } elseif ($qfunc === 'delete_resources_in_collection') {
            $counts = security_guard_count_collection((int) ($p1 ?? $params['collection'] ?? 0));
        } else {
            $counts = array(0, 1); // an alternative file is removed from the disk at once
        }
        $api_user = $authmode === 'native' ? null : (is_string($_POST['user'] ?? $_GET['user'] ?? null) ? ($_POST['user'] ?? $_GET['user']) : '');
        security_guard_deletion_gate($s, $counts[0], $counts[1], $qfunc, $api_user, true);
    }
}

function security_guard_check_saml(array $s, $ip, $path, $method)
{
    // no stack traces on SimpleSAMLphp error pages (config from $simplesamlconfig in config.php)
    if ($s['saml_hide_errors']) {
        $GLOBALS['simplesamlconfig']['config']['showerrors'] = false;
        $GLOBALS['simplesamlconfig']['config']['errorreporting'] = false;
    }
    // local login form and admin pages of SimpleSAMLphp (SSO itself, e.g. saml/sp/..., stays open)
    if (!preg_match('#^plugins/simplesaml/lib/(public|www)/(admin|module\.php/(admin|core/(login|loginuserpass|frontpage)))#', $path)) {
        return;
    }
    if ($s['saml_panel'] === 'block' || ($s['saml_panel'] === 'allowlist' && !security_guard_ip_in($ip, $s['admin_ips']))) {
        security_guard_deny(403, 'saml_panel');
    }
    if ($method === 'POST' && (int) $s['saml_limit'] > 0) {
        if (!security_guard_rate($ip, 'saml', (int) $s['saml_limit'], max(1, (int) $s['saml_window']) * 60)) {
            security_guard_deny(429, 'saml_bruteforce', 'more than ' . (int) $s['saml_limit'] . ' attempts');
        }
    }
}

// Counter per address and purpose in small files; false when the limit is exceeded
function security_guard_rate($ip, $what, $limit, $window)
{
    $dir = security_guard_data_dir() . '/rate';
    if (!security_guard_mkdir($dir)) {
        return true;
    }
    $file = $dir . '/' . $what . '_' . md5((string) $ip) . '.json';
    $now = time();
    $fh = fopen($file, 'c+');
    if ($fh === false) {
        return true;
    }
    flock($fh, LOCK_EX);
    $data = json_decode((string) stream_get_contents($fh), true);
    if (!is_array($data) || ($now - (int) ($data['start'] ?? 0)) > $window) {
        $data = array('start' => $now, 'count' => 0);
    }
    $data['count'] = (int) $data['count'] + 1;
    ftruncate($fh, 0);
    rewind($fh);
    fwrite($fh, json_encode($data));
    flock($fh, LOCK_UN);
    fclose($fh);
    // occasionally remove old counters
    if (mt_rand(1, 50) === 1) {
        foreach ((array) glob($dir . '/*.json') as $f) {
            if (is_file($f) && filemtime($f) < $now - 86400) {
                unlink($f);
            }
        }
    }
    return $data['count'] <= $limit;
}

// ---- Deletion protection (since 1.01) ---------------------------------------------------------
//
// ResourceSpace has no hook that could stop a permanent deletion before the files are removed, so
// the requests that delete are checked here, before the page code:
//   - API delete_resource, delete_resources_in_collection, delete_alternative_file (used by the UI),
//   - pages/collection_manage.php (purge / deleteall = delete all resources of a collection),
//   - pages/edit.php batch edit that sets the "Deleted" state.
// Above the limits (per user and time window, counted in resource_log) the deletion needs the
// approval of an administrator on the options page (another administrator with "four eyes").

// Logged in user of the request (session cookie, or the user name of a signed API call)
function security_guard_current_user($api_user = null)
{
    static $cache = array();
    $key = $api_user === null ? 'cookie' : 'api:' . $api_user;
    if (array_key_exists($key, $cache)) {
        return $cache[$key];
    }
    $row = null;
    try {
        $rows = array();
        if ($api_user === null) {
            $hash = $_COOKIE['user'] ?? '';
            if (is_string($hash) && $hash !== '') {
                $rows = ps_query('SELECT ref, username FROM user WHERE session = ? LIMIT 1', array('s', $hash));
            }
        } elseif ($api_user !== '') {
            $rows = ps_query('SELECT ref, username FROM user WHERE username = ? LIMIT 1', array('s', $api_user));
        }
        if (!empty($rows)) {
            $row = array('ref' => (int) $rows[0]['ref'], 'username' => (string) $rows[0]['username']);
        }
    } catch (Throwable $e) {
        $row = null;
    }
    return $cache[$key] = $row;
}

// [resources moved to "Deleted", resources removed permanently] for one resource
function security_guard_count_resources(array $refs)
{
    $soft = 0;
    $perm = 0;
    $state = $GLOBALS['resource_deletion_state'] ?? null;
    foreach ($refs as $ref) {
        $ref = (int) $ref;
        if ($ref <= 0) {
            continue;
        }
        try {
            $archive = ps_value('SELECT archive value FROM resource WHERE ref = ?', array('i', $ref), null);
        } catch (Throwable $e) {
            $archive = null;
        }
        if ($archive === null || $archive === '') {
            continue;
        }
        if ($state === null || (int) $archive === (int) $state) {
            $perm++;
        } else {
            $soft++;
        }
    }
    return array($soft, $perm);
}

// [moved to "Deleted", removed permanently] when all resources of a collection are deleted
function security_guard_count_collection($collection)
{
    $collection = (int) $collection;
    if ($collection <= 0) {
        return array(0, 0);
    }
    $state = $GLOBALS['resource_deletion_state'] ?? null;
    try {
        $rows = ps_query('SELECT COUNT(*) total, SUM(r.archive = ?) perm FROM collection_resource cr JOIN resource r ON r.ref = cr.resource WHERE cr.collection = ?',
            array('i', $state === null ? -2147483647 : (int) $state, 'i', $collection));
    } catch (Throwable $e) {
        return array(0, 0);
    }
    $total = (int) ($rows[0]['total'] ?? 0);
    $perm  = $state === null ? $total : (int) ($rows[0]['perm'] ?? 0);
    return array($total - $perm, $perm);
}

// Deletions of the user in the last $minutes minutes: [moved to "Deleted", removed permanently]
function security_guard_recent_deletions($user, $minutes)
{
    $soft_code = defined('LOG_CODE_DELETED') ? LOG_CODE_DELETED : 'x';
    $perm_code = defined('LOG_CODE_DELETED_PERMANENTLY') ? LOG_CODE_DELETED_PERMANENTLY : 'xx';
    try {
        $rows = ps_query('SELECT SUM(type = ?) soft, SUM(type = ?) perm FROM resource_log WHERE user = ? AND type IN (?, ?) AND date > NOW() - INTERVAL ? MINUTE',
            array('s', $soft_code, 's', $perm_code, 'i', (int) $user, 's', $soft_code, 's', $perm_code, 'i', (int) $minutes));
    } catch (Throwable $e) {
        return array(0, 0);
    }
    return array((int) ($rows[0]['soft'] ?? 0), (int) ($rows[0]['perm'] ?? 0));
}

function security_guard_deletion_file()
{
    return security_guard_data_dir() . '/deletion.json';
}

// Reads and changes the deletion requests / approvals under a lock; $fn(array &$data) returns the result
function security_guard_deletion_update(callable $fn)
{
    if (!security_guard_mkdir(security_guard_data_dir())) {
        return null;
    }
    $fh = fopen(security_guard_deletion_file(), 'c+');
    if ($fh === false) {
        return null;
    }
    flock($fh, LOCK_EX);
    $data = json_decode((string) stream_get_contents($fh), true);
    if (!is_array($data)) {
        $data = array();
    }
    $data += array('next' => 1, 'requests' => array(), 'grants' => array());
    $result = $fn($data);
    ftruncate($fh, 0);
    rewind($fh);
    fwrite($fh, json_encode($data));
    fflush($fh);
    flock($fh, LOCK_UN);
    fclose($fh);
    return $result;
}

// Uses an approval of the user for $n resources; true when there was one
function security_guard_use_grant($user, $n)
{
    if (!is_file(security_guard_deletion_file())) {
        return false;
    }
    return (bool) security_guard_deletion_update(function (array &$d) use ($user, $n) {
        $k = (string) $user;
        $g = $d['grants'][$k] ?? null;
        if (!is_array($g) || (int) $g['until'] < time()) {
            unset($d['grants'][$k]);
            return false;
        }
        if ((int) $g['remaining'] < $n) {
            return false;
        }
        $d['grants'][$k]['remaining'] = (int) $g['remaining'] - $n;
        if ($d['grants'][$k]['remaining'] <= 0) {
            unset($d['grants'][$k]);
        }
        return true;
    });
}

// Stores a request for approval (the same pending request is reused) and returns [id, new]
function security_guard_deletion_request(array $user, $soft, $perm, $what)
{
    $ip = security_guard_client_ip();
    $res = security_guard_deletion_update(function (array &$d) use ($user, $soft, $perm, $what, $ip) {
        foreach ($d['requests'] as $r) {
            if ($r['status'] === 'pending' && (int) $r['user'] === $user['ref'] && $r['what'] === $what
                && (int) $r['soft'] === $soft && (int) $r['perm'] === $perm && (int) $r['time'] > time() - 3600) {
                return array((int) $r['id'], false);
            }
        }
        $id = (int) $d['next'];
        $d['next'] = $id + 1;
        $d['requests'][] = array('id' => $id, 'user' => $user['ref'], 'username' => $user['username'], 'soft' => $soft, 'perm' => $perm,
            'what' => $what, 'ip' => $ip, 'time' => time(), 'status' => 'pending', 'by' => '', 'decided' => 0);
        $d['requests'] = array_slice($d['requests'], -200);
        return array($id, true);
    });
    return is_array($res) ? $res : array(0, false);
}

// Lets the deletion through, or stops it and asks for approval
function security_guard_deletion_gate(array $s, $soft, $perm, $what, $api_user, $json)
{
    $soft = (int) $soft;
    $perm = (int) $perm;
    if ($soft + $perm <= 0) {
        return;
    }
    if ($perm > 0 && $s['del_perm_mode'] === 'block') {
        security_guard_deny(403, 'delete_permanent_blocked', $what . ': ' . $perm, $json,
            'Permanent deletion is switched off in the browser (Security Guard). Resources stay in the "Deleted" state; an administrator can remove them on the server.');
    }
    $user = security_guard_current_user($api_user);
    if ($user === null) {
        return; // not logged in: ResourceSpace refuses the deletion itself
    }
    list($recent_soft, $recent_perm) = security_guard_recent_deletions($user['ref'], max(1, (int) $s['del_window']));
    $soft_limit = (int) $s['del_soft_limit'];
    $perm_limit = (int) $s['del_perm_limit'];
    $need = ($soft > 0 && $soft_limit > 0 && $recent_soft + $soft > $soft_limit)
        || ($perm > 0 && ($perm_limit === 0 || $recent_perm + $perm > $perm_limit));
    if (!$need) {
        return;
    }
    $detail = $what . ': ' . $soft . ' to Deleted, ' . $perm . ' permanently (user ' . $user['username'] . ')';
    if (security_guard_use_grant($user['ref'], $soft + $perm)) {
        security_guard_log('allow', 'delete_approved', $detail);
        return;
    }
    list($id, $new) = security_guard_deletion_request($user, $soft, $perm, $what);
    if ($new) {
        $text = 'Security Guard: ' . $user['username'] . ' asks for approval to delete ' . ($soft + $perm) . ' resource(s)'
            . ($perm > 0 ? ' (' . $perm . ' permanently)' : '') . '. Request #' . $id . '.';
        $extra = ($s['notify_enabled'] && in_array('deletion', $s['notify_events'], true)) ? array_keys(security_guard_notify_recipients($s)) : array();
        if ($s['del_notify'] || $extra) {
            security_guard_notify_admins($text, $extra, $s['del_notify']);
        }
    }
    security_guard_deny(403, 'delete_approval', $detail . ', request #' . $id, $json,
        'Deleting ' . ($soft + $perm) . ' resource(s)' . ($perm > 0 ? ' (' . $perm . ' permanently)' : '') . ' needs the approval of '
        . ($s['del_four_eyes'] ? 'another administrator' : 'an administrator') . ' (Security Guard request #' . $id . '). '
        . 'After the approval (System > Plugins > Security Guard > Options) repeat the deletion.');
}

// ResourceSpace notification to the system administrators (and/or the given users)
function security_guard_notify_admins($text, array $extra = array(), $admins = true)
{
    if (!function_exists('message_add')) {
        return;
    }
    try {
        $refs = $extra;
        if ($admins && function_exists('get_notification_users')) {
            $refs = array_merge($refs, array_column((array) get_notification_users('SYSTEM_ADMIN'), 'ref'));
        }
        $refs = array_values(array_unique(array_filter(array_map('intval', $refs))));
        if ($refs) {
            message_add($refs, $text, rtrim((string) ($GLOBALS['baseurl'] ?? ''), '/') . '/plugins/security_guard/pages/setup.php');
        }
    } catch (Throwable $e) {
        security_guard_log('log', 'notify_failed', $e->getMessage());
    }
}

function security_guard_check_deletion_page(array $s, $path)
{
    if ($path === 'pages/collection_manage.php') {
        foreach (array('purge', 'deleteall') as $k) {
            $v = $_POST[$k] ?? '';
            if (is_string($v) && ctype_digit($v) && (int) $v > 0) {
                $c = security_guard_count_collection((int) $v);
                security_guard_deletion_gate($s, $c[0], $c[1], 'delete all resources of collection ' . (int) $v, null, false);
                return;
            }
        }
    } elseif ($path === 'pages/edit.php' && !empty($_POST['editthis_status'])) {
        $state  = $GLOBALS['resource_deletion_state'] ?? null;
        $col    = (int) ($_GET['collection'] ?? $_POST['collection'] ?? 0);
        $status = $_POST['status'] ?? '';
        if ($state !== null && $col > 0 && is_string($status) && $status !== '' && (int) $status === (int) $state) {
            $c = security_guard_count_collection($col);
            security_guard_deletion_gate($s, $c[0], 0, 'batch edit: status Deleted for collection ' . $col, null, false);
        }
    }
}

// ---- Share policy (since 1.01) ----------------------------------------------------------------

// Expiry date of shares by the policy: [default 'Y-m-d', max days, default days, "never" allowed]
function security_guard_share_limits(array $s)
{
    $max   = max(1, min(3650, (int) $s['share_max_days']));
    $def   = max(1, min($max, (int) $s['share_default_days']));
    $never = $s['share_allow_never'] && $s['share_user_can_change'];
    return array(date('Y-m-d', strtotime('today') + $def * 86400), $max, $def, $never);
}

function security_guard_share_policy(array $s, $path)
{
    list($default_date, $max, $def, $never) = security_guard_share_limits($s);
    // settings of ResourceSpace used by the share forms
    $GLOBALS['resource_share_expire_days']         = $s['share_user_can_change'] ? $max : $def;
    $GLOBALS['resource_share_expire_days_default'] = $def;
    $GLOBALS['resource_share_expire_never']        = $never;
    if ($s['share_require_password']) {
        $GLOBALS['share_password_required'] = true; // checked on the server by enforceSharePassword()
    }

    $pages = array('pages/resource_share.php', 'pages/collection_share.php', 'pages/resource_email.php', 'pages/collection_email.php', 'pages/share_upload.php');
    if (!in_array($path, $pages, true)) {
        return;
    }

    // expiry date: within the limits (the forms do not check it on the server)
    $key = $path === 'pages/share_upload.php' ? 'shareexpires' : 'expires';
    $fix = function ($v) use ($s, $default_date, $max, $never) {
        if (!is_string($v)) {
            return $default_date;
        }
        $v = trim($v);
        if ($v === '') {
            return $never ? '' : $default_date;
        }
        $t = strtotime(substr($v, 0, 10));
        if ($t === false || !$s['share_user_can_change']) {
            return $default_date;
        }
        $today = strtotime('today');
        return date('Y-m-d', min(max($t, $today + 86400), $today + $max * 86400));
    };
    $apply = function (array $arr) use ($key, $fix) {
        if (!array_key_exists($key, $arr)) {
            return $arr;
        }
        $old = $arr[$key];
        $new = $fix($old);
        if (!is_string($old) || substr(trim($old), 0, 10) !== $new) {
            security_guard_log('fix', 'share_expiry', (is_string($old) ? ($old === '' ? 'never' : $old) : 'array') . ' -> ' . ($new === '' ? 'never' : $new));
        }
        $arr[$key] = $new;
        $_REQUEST[$key] = $new;
        return $arr;
    };
    $_GET  = $apply($_GET);
    $_POST = $apply($_POST);

    // password length
    $min = max(6, (int) $s['share_password_length']);
    $unchanged = (string) ($GLOBALS['lang']['password_unchanged'] ?? '(unchanged)');
    foreach (array($_POST, $_GET) as $src) {
        if (array_key_exists('sharepassword', $src)) {
            $pw = $src['sharepassword'];
            $len = is_string($pw) ? (function_exists('mb_strlen') ? mb_strlen($pw) : strlen($pw)) : 0;
            if (is_string($pw) && $pw !== '' && $pw !== $unchanged && $len < $min) {
                security_guard_deny(400, 'share_password', 'length ' . $len, false,
                    'The share password must have at least ' . $min . ' characters (Security Guard policy).');
            }
            break;
        }
    }
}

// Script for the share forms: proposes a generated password, fixes the expiry date
function security_guard_share_script(array $s)
{
    list($default_date) = security_guard_share_limits($s);
    $cfg = array(
        'generate'  => (bool) $s['share_generate_password'],
        'length'    => max(6, (int) $s['share_password_length']),
        'canChange' => (bool) $s['share_user_can_change'],
        'date'      => $default_date,
    );
    return '(function () {
    var cfg = ' . json_encode($cfg) . ';
    var chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#%*-_+=";
    function gen(n) {
        var a = new Uint32Array(n), s = "";
        window.crypto.getRandomValues(a);
        for (var i = 0; i < n; i++) { s += chars.charAt(a[i] % chars.length); }
        return s;
    }
    function apply() {
        document.querySelectorAll("input#sharepassword").forEach(function (el) {
            if (el.getAttribute("data-sg")) { return; }
            el.setAttribute("data-sg", "1");
            el.setAttribute("minlength", cfg.length);
            el.removeAttribute("maxlength");
            if (!cfg.generate) { return; }
            if (el.value === "") { el.value = gen(cfg.length); el.type = "text"; }
            var a = document.createElement("a");
            a.href = "#";
            a.textContent = "New password";
            a.className = "sg-newpw";
            a.style.marginLeft = "8px";
            a.addEventListener("click", function (e) { e.preventDefault(); el.value = gen(cfg.length); el.type = "text"; el.focus(); el.select(); });
            el.parentNode.appendChild(a);
        });
        if (cfg.canChange) { return; }
        document.querySelectorAll("select[name=expires], select[name=shareexpires]").forEach(function (sel) {
            if (sel.getAttribute("data-sg")) { return; }
            sel.setAttribute("data-sg", "1");
            var found = false;
            for (var i = 0; i < sel.options.length; i++) { if (sel.options[i].value === cfg.date) { found = true; } }
            if (!found) { var o = document.createElement("option"); o.value = cfg.date; o.textContent = cfg.date; sel.appendChild(o); }
            sel.value = cfg.date;
            for (var j = sel.options.length - 1; j >= 0; j--) { if (sel.options[j].value !== cfg.date) { sel.remove(j); } }
            sel.title = "Set by the security policy";
        });
    }
    var queued = false;
    function schedule() {
        if (queued) { return; }
        queued = true;
        window.requestAnimationFrame(function () { queued = false; apply(); });
    }
    if (document.readyState === "loading") { document.addEventListener("DOMContentLoaded", apply); } else { apply(); }
    new MutationObserver(schedule).observe(document.documentElement, {childList: true, subtree: true});
})();';
}

// ---- Incident notifications (since 1.02) ------------------------------------------------------
//
// Sent only when an event is logged (never on normal requests), to the chosen users and to all
// active members of the chosen user groups: ResourceSpace notification and/or e-mail. One
// notification per category, rule and address in "notify_throttle" minutes, at most
// "notify_max_per_hour" notifications per hour (the log keeps every event).

// Recipients: [user ref => ['username' => .., 'email' => ..]]
function security_guard_notify_recipients(array $s)
{
    $where  = array();
    $params = array();
    $users  = array_values(array_filter(array_map('strval', $s['notify_users']), 'strlen'));
    $groups = array_values(array_filter(array_map('intval', $s['notify_groups'])));
    if ($users) {
        $where[] = 'username IN (' . implode(',', array_fill(0, count($users), '?')) . ')';
        foreach ($users as $u) {
            $params[] = 's';
            $params[] = $u;
        }
    }
    if ($groups) {
        $where[] = 'usergroup IN (' . implode(',', array_fill(0, count($groups), '?')) . ')';
        foreach ($groups as $g) {
            $params[] = 'i';
            $params[] = $g;
        }
    }
    if (!$where || !function_exists('ps_query')) {
        return array();
    }
    $out = array();
    try {
        foreach (ps_query('SELECT ref, username, email, email_invalid FROM user WHERE approved = 1 AND (' . implode(' OR ', $where) . ')', $params) as $r) {
            $out[(int) $r['ref']] = array('username' => (string) $r['username'], 'email' => empty($r['email_invalid']) ? trim((string) $r['email']) : '');
        }
    } catch (Throwable $e) {
        return array();
    }
    return $out;
}

// Sends one notification; returns the number of recipients
function security_guard_send_notification(array $s, $subject, $text, $short)
{
    $recipients = security_guard_notify_recipients($s);
    if (!$recipients) {
        return 0;
    }
    $url = rtrim((string) ($GLOBALS['baseurl'] ?? ''), '/') . '/plugins/security_guard/pages/setup.php';
    if ($s['notify_screen'] && function_exists('message_add')) {
        try {
            message_add(array_keys($recipients), $short, $url);
        } catch (Throwable $e) {
            security_guard_log('log', 'notify_failed', 'message: ' . $e->getMessage());
        }
    }
    if ($s['notify_email'] && function_exists('send_mail')) {
        foreach ($recipients as $r) {
            if ($r['email'] === '' || !filter_var($r['email'], FILTER_VALIDATE_EMAIL)) {
                continue;
            }
            try {
                send_mail($r['email'], $subject, $text . "\n\n" . $url);
            } catch (Throwable $e) {
                security_guard_log('log', 'notify_failed', 'e-mail: ' . $e->getMessage());
            }
        }
    }
    return count($recipients);
}

function security_guard_incident($category, $action, $rule, $detail, $ref)
{
    static $busy = false;
    if ($busy) {
        return; // no notifications about notifications
    }
    $busy = true;
    try {
        $s  = security_guard_settings();
        $ip = security_guard_client_ip($s);
        // throttle: one per category + rule + address, and a cap per hour
        if (!security_guard_rate($category . '|' . $rule . '|' . $ip, 'notify', 1, max(1, (int) $s['notify_throttle']) * 60)
            || !security_guard_rate('all', 'notify_hour', max(1, (int) $s['notify_max_per_hour']), 3600)) {
            return;
        }
        $labels = security_guard_incident_categories();
        $site   = (string) ($GLOBALS['applicationname'] ?? 'ResourceSpace');
        $path   = '/' . security_guard_path();
        $method = (string) ($_SERVER['REQUEST_METHOD'] ?? '');
        $subject = '[Security Guard] ' . $site . ': ' . $rule . ($action === 'block' ? ' blocked' : '');
        $text = 'Security Guard - ' . $site . "\n\n"
            . 'Incident: ' . ($labels[$category] ?? $category) . "\n"
            . 'Rule: ' . $rule . ' (' . $action . ")\n"
            . 'Address: ' . $ip . "\n"
            . ($action !== 'admin' ? 'Request: ' . $method . ' ' . $path . "\n" : '')
            . ($detail !== '' ? 'Detail: ' . $detail . "\n" : '')
            . ($ref !== '' ? 'Reference: ' . $ref . "\n" : '')
            . 'Time: ' . date('Y-m-d H:i:s T') . "\n\n"
            . 'Further notifications about the same rule and address are paused for ' . (int) $s['notify_throttle'] . ' minutes; the security log keeps every event.';
        $short = 'Security Guard: ' . $rule . ($action === 'block' ? ' blocked' : '') . ' - ' . $ip
            . ($action !== 'admin' ? ' (' . $method . ' ' . $path . ')' : '') . ($detail !== '' ? ': ' . $detail : '') . ($ref !== '' ? ' [' . $ref . ']' : '');
        security_guard_send_notification($s, $subject, $text, function_exists('mb_substr') ? mb_substr($short, 0, 400) : substr($short, 0, 400));
    } catch (Throwable $e) {
        // a notification must never break the request
    } finally {
        $busy = false;
    }
}
