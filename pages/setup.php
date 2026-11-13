<?php
include '../../../include/db.php';
include '../../../include/authenticate.php';
require_once dirname(__FILE__, 2) . '/include/functions.php';

// Admins only
if (!checkperm('a')) {
    exit($lang['error-permissiondenied']);
}

$self        = $_SERVER['PHP_SELF'];
$plugins_url = $baseurl_short . 'pages/team/team_plugins.php';
$action      = (string) ($_POST['action'] ?? '');
$reset_open  = false;
$message     = '';
$errors      = array();
$settings    = security_guard_settings();
$client_ip   = security_guard_client_ip($settings);

// Download of a quarantined file (before any output)
if (isset($_GET['qdownload'])) {
    if (security_guard_upload_download((int) $_GET['qdownload'])) {
        security_guard_log('admin', 'upload_download', 'file #' . (int) $_GET['qdownload'] . ' by ' . $username);
        exit;
    }
    $errors[] = 'The quarantined file is no longer available.';
}

// ---- Handle form actions ----
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action !== '') {
    if (function_exists('enforcePostRequest') && !enforcePostRequest(false)) {
        $errors[] = 'The request could not be verified. Reload the page and try again.';
    } elseif ($action === 'save') {
        $new = $settings;
        foreach (array('enabled', 'patch_report_params', 'patch_login_redirect', 'patch_api_confusion', 'patch_api_lockout', 'patch_get_session',
            'force_random_session', 'saml_hide_errors', 'block_scanners', 'remove_powered_by',
            'del_enabled', 'del_force_trash', 'del_four_eyes', 'del_notify',
            'share_enabled', 'share_require_password', 'share_generate_password', 'share_user_can_change', 'share_allow_never',
            'notify_enabled', 'notify_screen', 'notify_email',
            'up_inspect', 'up_clamav', 'up_four_eyes', 'up_notify_admins') as $k) {
            $new[$k] = !empty($_POST[$k]);
        }
        $new['saml_panel'] = in_array($_POST['saml_panel'] ?? '', array('open', 'allowlist', 'block'), true) ? $_POST['saml_panel'] : 'open';
        $new['waf_mode']   = in_array($_POST['waf_mode'] ?? '', array('off', 'log', 'block'), true) ? $_POST['waf_mode'] : 'log';
        $new['saml_limit']  = max(0, min(1000, (int) ($_POST['saml_limit'] ?? 10)));
        $new['saml_window'] = max(1, min(1440, (int) ($_POST['saml_window'] ?? 10)));
        $new['log_max_kb']  = max(64, min(102400, (int) ($_POST['log_max_kb'] ?? 2048)));
        $new['del_perm_mode']     = ($_POST['del_perm_mode'] ?? '') === 'block' ? 'block' : 'limit';
        $new['del_soft_limit']    = max(0, min(1000000, (int) ($_POST['del_soft_limit'] ?? 50)));
        $new['del_perm_limit']    = max(0, min(1000000, (int) ($_POST['del_perm_limit'] ?? 10)));
        $new['del_window']        = max(1, min(10080, (int) ($_POST['del_window'] ?? 60)));
        $new['del_grant_minutes'] = max(5, min(1440, (int) ($_POST['del_grant_minutes'] ?? 60)));
        $new['share_password_length'] = max(6, min(64, (int) ($_POST['share_password_length'] ?? 12)));
        $new['share_max_days']        = max(1, min(3650, (int) ($_POST['share_max_days'] ?? 30)));
        $new['share_default_days']    = max(1, min($new['share_max_days'], (int) ($_POST['share_default_days'] ?? 14)));
        $new['permissions_policy'] = trim(preg_replace('/[\r\n]+/', ' ', (string) ($_POST['permissions_policy'] ?? '')));
        $new['notify_throttle']     = max(1, min(1440, (int) ($_POST['notify_throttle'] ?? 15)));
        $new['notify_max_per_hour'] = max(1, min(1000, (int) ($_POST['notify_max_per_hour'] ?? 30)));
        $new['notify_events'] = array_values(array_intersect(array_keys(security_guard_incident_categories()), (array) ($_POST['notify_events'] ?? array())));
        $new['notify_groups'] = array_values(array_unique(array_filter(array_map('intval', (array) ($_POST['notify_groups'] ?? array())))));
        $new['notify_users']  = security_guard_lines($_POST['notify_users'] ?? '');
        $new['up_mode']        = in_array($_POST['up_mode'] ?? '', array('off', 'log', 'enforce'), true) ? $_POST['up_mode'] : 'log';
        $new['up_groups']      = array_values(array_intersect(array('images', 'video', 'documents', 'audio'), (array) ($_POST['up_groups'] ?? array())));
        $new['up_scan_mb']     = max(1, min(500, (int) ($_POST['up_scan_mb'] ?? 25)));
        $new['up_grant_hours'] = max(1, min(720, (int) ($_POST['up_grant_hours'] ?? 24)));
        $new['up_keep_days']   = max(1, min(365, (int) ($_POST['up_keep_days'] ?? 30)));
        $new['up_clamav_cmd']  = trim(preg_replace('/[^A-Za-z0-9 ._\/=-]+/', '', (string) ($_POST['up_clamav_cmd'] ?? '')));
        $new['up_skip_paths']  = security_guard_lines($_POST['up_skip_paths'] ?? '');
        foreach (array('up_extra_ext', 'up_block_ext') as $k) {
            $new[$k] = array_map('strtolower', array_map(function ($e) { return ltrim($e, '.'); }, security_guard_lines($_POST[$k] ?? '')));
            foreach ($new[$k] as $e) {
                if (!preg_match('/^[a-z0-9]{1,10}$/', $e)) {
                    $errors[] = 'Not a file extension: "' . $e . '".';
                }
            }
        }
        $banned_added = array_intersect($new['up_extra_ext'], array_map('strtolower', (array) ($banned_extensions ?? array())));
        if ($banned_added) {
            $errors[] = 'These extensions are banned by ResourceSpace ($banned_extensions) and cannot be allowed: ' . implode(', ', $banned_added) . '.';
        }
        if ($new['up_clamav'] && $new['up_clamav_cmd'] === '') {
            $errors[] = 'Enter the ClamAV command (e.g. clamdscan --no-summary --fdpass).';
        }
        $unknown = security_guard_unknown_users($new['notify_users']);
        if ($unknown) {
            $errors[] = 'Unknown user name(s) in "Notify users": ' . implode(', ', $unknown) . '.';
        }
        if ($new['notify_enabled'] && !$new['notify_users'] && !$new['notify_groups']) {
            $errors[] = 'Notifications are on, but no users or user groups are chosen.';
        }
        foreach (array('trusted_proxies', 'blocklist', 'admin_ips', 'api_ips') as $k) {
            $new[$k] = security_guard_lines($_POST[$k] ?? '');
            foreach ($new[$k] as $ip) {
                if (!security_guard_valid_cidr($ip)) {
                    $errors[] = 'Not an IP address or network: "' . $ip . '".';
                }
            }
        }
        foreach (array('admin_paths', 'waf_skip_paths', 'scanner_agents') as $k) {
            $new[$k] = security_guard_lines($_POST[$k] ?? '');
        }
        // never lock out the administrator who is saving
        $check_ip = security_guard_client_ip($new);
        if ($new['enabled'] && $new['admin_ips'] && !security_guard_ip_in($check_ip, $new['admin_ips'])) {
            $errors[] = 'Not saved: your address ' . $check_ip . ' is not in "Admin pages only from" - you would lock yourself out.';
        }
        if ($new['enabled'] && $new['blocklist'] && security_guard_ip_in($check_ip, $new['blocklist'])) {
            $errors[] = 'Not saved: your address ' . $check_ip . ' is in "Blocked addresses".';
        }
        if (!$errors) {
            if (security_guard_save_settings($new)) {
                $changes = security_guard_settings_changes($settings, $new);
                security_guard_log('admin', !$new['enabled'] && $settings['enabled'] ? 'protection_off' : 'settings_saved',
                    'by ' . $username . ($changes ? ': ' . implode(', ', $changes) : ''));
                redirect($self . '?done=saved');
                exit;
            }
            $errors[] = 'The settings could not be stored (check write access to ' . security_guard_data_dir() . ').';
        }
        $settings = $new; // show what was entered
    } elseif (in_array($action, array('del_approve', 'del_reject', 'del_grant', 'del_revoke'), true)) {
        $admin = array('ref' => (int) $userref, 'username' => (string) $username);
        if ($action === 'del_revoke') {
            security_guard_deletion_revoke((int) ($_POST['revoke_user'] ?? 0), $admin);
            $err = '';
        } elseif ($action === 'del_grant') {
            $err = security_guard_deletion_grant($_POST['grant_user'] ?? '', $_POST['grant_count'] ?? 0, $_POST['grant_minutes'] ?? $settings['del_grant_minutes'], $admin, $settings['del_four_eyes']);
        } else {
            $err = security_guard_deletion_decide((int) ($_POST['request_id'] ?? 0), $action === 'del_approve', $admin, $_POST['grant_minutes'] ?? $settings['del_grant_minutes'], $settings['del_four_eyes']);
        }
        if ($err === '') {
            redirect($self . '?done=' . $action . '#sg-deletion');
            exit;
        }
        $errors[] = $err;
    } elseif ($action === 'up_approve' || $action === 'up_reject') {
        $err = security_guard_upload_decide((int) ($_POST['file_id'] ?? 0), $action === 'up_approve', array('ref' => (int) $userref, 'username' => (string) $username), $settings);
        if ($err === '') {
            redirect($self . '?done=' . $action . '#sg-quarantine');
            exit;
        }
        $errors[] = $err;
    } elseif ($action === 'notify_test') {
        $n = security_guard_send_notification($settings, '[Security Guard] ' . ($applicationname ?? 'ResourceSpace') . ': test notification',
            "Security Guard - test notification\n\nSent by " . $username . ' from the options page at ' . date('Y-m-d H:i:s T') . '. No incident happened.',
            'Security Guard: test notification sent by ' . $username . ' (no incident).');
        if ($n > 0) {
            security_guard_log('admin', 'notify_test', 'by ' . $username . ', ' . $n . ' recipient(s)');
            redirect($self . '?done=notify_test&n=' . $n . '#sg-notify');
            exit;
        }
        $errors[] = 'No recipients: save at least one user or user group in "Incident notifications" first (active accounts only).';
    } elseif ($action === 'clear_log') {
        if (security_guard_clear_log()) {
            security_guard_log('admin', 'log_cleared', 'by ' . $username);
            redirect($self . '?done=log_cleared');
            exit;
        }
        $errors[] = 'The log could not be deleted.';
    } elseif ($action === 'reset') {
        $reset_open = true;
        if (trim((string) ($_POST['reset_confirm'] ?? '')) !== 'RESET') {
            $errors[] = 'Not reset: type RESET (capital letters) to confirm.';
        } else {
            security_guard_log('admin', 'plugin_reset', 'by ' . $username); // notification before the settings are deleted
            if (security_guard_reset()) {
                redirect($self . '?done=reset');
                exit;
            }
            $errors[] = 'The plugin could not be reset (check permissions of ' . security_guard_base_dir() . ').';
        }
    }
}

switch ((string) ($_GET['done'] ?? '')) {
    case 'saved':
        $message = 'Settings saved. They apply to the next request.';
        break;
    case 'del_approve':
        $message = 'The deletion was approved. The user can repeat it now.';
        break;
    case 'del_reject':
        $message = 'The deletion request was rejected.';
        break;
    case 'del_grant':
        $message = 'The approval was given.';
        break;
    case 'del_revoke':
        $message = 'The approval was withdrawn.';
        break;
    case 'up_approve':
        $message = 'The file was approved. The user can upload it again within ' . (int) $settings['up_grant_hours'] . ' hour(s); the quarantined copy was deleted.';
        break;
    case 'up_reject':
        $message = 'The file was rejected and deleted from the quarantine.';
        break;
    case 'notify_test':
        $message = 'Test notification sent to ' . (int) ($_GET['n'] ?? 0) . ' user(s).';
        break;
    case 'log_cleared':
        $message = 'The security log was deleted.';
        break;
    case 'reset':
        $message = 'The plugin was reset: settings, log and counters were deleted. The default settings apply.';
        break;
}

$h      = function ($s) { return htmlspecialchars((string) $s); };
$nonce  = isset($CSP_nonce) ? ' nonce="' . htmlspecialchars($CSP_nonce) . '"' : '';
$lines  = function (array $a) { return implode("\n", $a); };
$check  = function ($k, $label, $help) use ($settings, $h) {
    echo '<label class="sg-check"><input type="checkbox" name="' . $h($k) . '" value="1"' . (!empty($settings[$k]) ? ' checked' : '') . '> <b>' . $h($label) . '</b>';
    echo $help !== '' ? '<span class="sg-help">' . $help . '</span>' : '';
    echo '</label>';
};
$kill_on   = is_file(security_guard_kill_file()) || !empty($GLOBALS['security_guard_disable']);
$active    = $settings['enabled'] && !$kill_on;
$log       = array_map('security_guard_log_parse', security_guard_log_tail(200));
$blocks24  = 0;
foreach ($log as $e) {
    if ($e['action'] === 'block' && strtotime($e['time']) > time() - 86400) {
        $blocks24++;
    }
}
$rs_root    = dirname(__FILE__, 4);
$plugin_dir = dirname(__FILE__, 2);
$qcache     = function_exists('get_query_cache_location') ? get_query_cache_location() : $storagedir . '/tmp/querycache';

include '../../../include/header.php';
?>
<div class="BasicsBox sg-page">
    <h1>Security Guard</h1>
    <?php
    renderBreadcrumbs([
        ['title' => $lang['systemsetup'],   'href' => $baseurl_short . 'pages/admin/admin_home.php', 'menu' => true],
        ['title' => $lang['pluginmanager'], 'href' => $plugins_url],
        ['title' => 'Security Guard'],
    ]);
    ?>

    <?php if ($message) { ?><div class="PageInformal"><?php echo $h($message); ?></div><?php } ?>
    <?php foreach ($errors as $e) { ?><div class="FormError"><?php echo $h($e); ?></div><?php } ?>

    <style<?php echo $nonce; ?>>
        .sg-box { margin: 14px 0; padding: 10px 14px; border: 1px solid rgba(128, 128, 128, 0.45); border-radius: 6px; }
        .sg-box h3 { margin: 0 0 8px; font-size: 1.05em; }
        details.sg-box > summary { cursor: pointer; list-style: none; display: flex; align-items: center; gap: 8px; }
        details.sg-box > summary::-webkit-details-marker { display: none; }
        details.sg-box > summary::before { content: "\25B8"; display: inline-block; transition: transform 0.15s; }
        details.sg-box[open] > summary::before { transform: rotate(90deg); }
        details.sg-box > summary h3 { margin: 0; display: inline; }
        details.sg-box[open] > summary { margin-bottom: 8px; }
        .sg-box p { margin: 0.5em 0; }
        .sg-status { display: flex; flex-wrap: wrap; gap: 8px 24px; align-items: center; }
        .sg-badge { display: inline-block; padding: 2px 10px; border-radius: 10px; font-weight: bold; color: #fff; }
        .sg-on { background: #2e7d32; } .sg-off { background: #c62828; }
        .sg-check { display: block; margin: 6px 0; }
        .sg-help { display: block; margin: 2px 0 0 24px; opacity: 0.8; font-size: 0.92em; font-weight: normal; }
        .sg-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 12px 20px; }
        .sg-grid label { font-weight: bold; display: block; margin-bottom: 3px; }
        .sg-grid textarea { width: 100%; box-sizing: border-box; min-height: 90px; font-family: monospace; font-size: 0.9em; }
        .sg-grid .sg-help { margin-left: 0; }
        .sg-row { display: flex; flex-wrap: wrap; gap: 8px 16px; align-items: center; margin: 6px 0; }
        .sg-table { width: 100%; border-collapse: collapse; font-size: 0.92em; }
        .sg-table th, .sg-table td { text-align: left; padding: 4px 8px; border-bottom: 1px solid rgba(128, 128, 128, 0.3); vertical-align: top; }
        .sg-table td.sg-wrap { word-break: break-all; }
        .sg-ok { color: #2e7d32; font-weight: bold; } .sg-warn { color: #c62828; font-weight: bold; } .sg-info { opacity: 0.75; font-weight: bold; }
        .sg-log { max-height: 420px; overflow: auto; }
        .sg-pre { white-space: pre; overflow: auto; padding: 8px; border: 1px solid rgba(128, 128, 128, 0.4); border-radius: 4px; font-family: monospace; font-size: 0.85em; max-height: 360px; }
        .sg-m0 { margin: 0 !important; } .sg-w5 { width: 5em; } .sg-w7 { width: 7em; } .sg-wide { width: 36em; max-width: 100%; }
        .sg-list { max-height: 160px; overflow: auto; border: 1px solid rgba(128, 128, 128, 0.4); border-radius: 4px; padding: 4px 8px; }
        .sg-outline { background: transparent !important; border: 1px solid currentColor !important; color: inherit !important; }
    </style>

    <!-- Status -->
    <div class="sg-box sg-status">
        <span>Protection: <span class="sg-badge <?php echo $active ? 'sg-on' : 'sg-off'; ?>"><?php echo $active ? 'ON' : 'OFF'; ?></span></span>
        <span>Your address: <code><?php echo $h($client_ip); ?></code></span>
        <span>Blocked in the last 24 h: <b><?php echo (int) $blocks24; ?></b></span>
        <?php if ($kill_on) { ?><span class="sg-warn">Emergency switch is on (see "Disable from the server").</span><?php } ?>
    </div>

    <form method="post" action="<?php echo $h($self); ?>">
        <?php generateFormToken('security_guard'); ?>

        <div class="sg-box">
            <h3>Protection</h3>
            <?php $check('enabled', 'Security Guard is on', 'Off = the plugin does nothing (also without deactivating it).'); ?>
        </div>

        <div class="sg-box">
            <h3>Patches for known weaknesses</h3>
            <?php
            $check('patch_report_params', 'Report dates only as numbers', 'Date parameters of reports (from-y, from-m, from-d, to-y, to-m, to-d, period_days) must be numbers - blocks SQL injection in pages/team/team_report.php.');
            $check('patch_login_redirect', 'Redirect after login only to this site', 'The "url" parameter of login.php and pages/terms.php must be a path on this site (no //other-site, no other host) - open redirect.');
            $check('patch_api_confusion', 'API: one source of the function name', 'A "function" parameter outside "query" must match the function in "query" - otherwise function=login skipped the authentication of the API.');
            $check('patch_api_lockout', 'API login lockout', 'Login through the API (function=login) is refused while ResourceSpace locks the IP or the user name ($max_login_attempts_*), like login.php.');
            $check('patch_get_session', 'Session only from the cookie', 'The session hash in the URL (?user=...) is ignored outside the API.');
            $check('force_random_session', 'One session per account (random session hash)', 'Same as $randomised_session_hash = true: a new random session at every login, so an old session hash cannot be reused. <b>Logging in on a second device ends the session on the first.</b>');
            ?>
        </div>

        <div class="sg-box">
            <h3>SimpleSAMLphp</h3>
            <p class="sg-help sg-m0">Works when SimpleSAMLphp reads its configuration from ResourceSpace ($simplesaml_rsconfig) - then it loads ResourceSpace and this plugin. SSO logins are never blocked. Verify after activation (see README).</p>
            <?php $check('saml_hide_errors', 'Hide error details', 'showerrors / errorreporting = false: error pages without stack traces and paths.'); ?>
            <div class="sg-row">
                <label>Local login form and admin pages
                    <select name="saml_panel">
                        <?php foreach (array('open' => 'open to everyone', 'allowlist' => 'only from "Admin pages only from" addresses', 'block' => 'blocked') as $v => $l) { ?>
                            <option value="<?php echo $h($v); ?>"<?php echo $settings['saml_panel'] === $v ? ' selected' : ''; ?>><?php echo $h($l); ?></option>
                        <?php } ?>
                    </select>
                </label>
                <label>at most <input type="number" name="saml_limit" min="0" max="1000" value="<?php echo (int) $settings['saml_limit']; ?>" class="sg-w5"> login attempts
                    per IP in <input type="number" name="saml_window" min="1" max="1440" value="<?php echo (int) $settings['saml_window']; ?>" class="sg-w5"> minutes (0 = no limit)</label>
            </div>
        </div>

        <div class="sg-box">
            <h3>Firewall</h3>
            <p class="sg-help sg-m0">One entry per line: an address (192.0.2.10, 2001:db8::1) or a network (192.0.2.0/24). An empty list switches the rule off. Lines after # are comments.</p>
            <div class="sg-grid">
                <div><label for="sg-tp">Trusted proxies</label>
                    <textarea id="sg-tp" name="trusted_proxies" spellcheck="false"><?php echo $h($lines($settings['trusted_proxies'])); ?></textarea>
                    <span class="sg-help">Load balancer / reverse proxy addresses. Only their X-Forwarded-For header is trusted for the client address.</span></div>
                <div><label for="sg-bl">Blocked addresses</label>
                    <textarea id="sg-bl" name="blocklist" spellcheck="false"><?php echo $h($lines($settings['blocklist'])); ?></textarea>
                    <span class="sg-help">No access to ResourceSpace at all.</span></div>
                <div><label for="sg-ai">Admin pages only from</label>
                    <textarea id="sg-ai" name="admin_ips" spellcheck="false"><?php echo $h($lines($settings['admin_ips'])); ?></textarea>
                    <span class="sg-help">Office / VPN addresses. Your address must be in the list. Also used for the SimpleSAMLphp "allowlist".</span></div>
                <div><label for="sg-ap">Admin pages</label>
                    <textarea id="sg-ap" name="admin_paths" spellcheck="false"><?php echo $h($lines($settings['admin_paths'])); ?></textarea>
                    <span class="sg-help">Path prefixes, * = any folder (plugins/*/pages/).</span></div>
                <div><label for="sg-api">API key access only from</label>
                    <textarea id="sg-api" name="api_ips" spellcheck="false"><?php echo $h($lines($settings['api_ips'])); ?></textarea>
                    <span class="sg-help">External systems using API keys. The browser interface (authmode=native) is not affected.</span></div>
                <div><label for="sg-ua"><input type="checkbox" name="block_scanners" value="1"<?php echo $settings['block_scanners'] ? ' checked' : ''; ?>> Block scanners (User-Agent contains)</label>
                    <textarea id="sg-ua" name="scanner_agents" spellcheck="false"><?php echo $h($lines($settings['scanner_agents'])); ?></textarea>
                    <span class="sg-help">Automated attack tools announce themselves. Not a protection against careful attackers, but stops noise.</span></div>
                <div><label for="sg-waf">Attack patterns in parameters
                        <select name="waf_mode" id="sg-waf">
                            <?php foreach (array('off' => 'off', 'log' => 'log only', 'block' => 'block') as $v => $l) { ?>
                                <option value="<?php echo $h($v); ?>"<?php echo $settings['waf_mode'] === $v ? ' selected' : ''; ?>><?php echo $h($l); ?></option>
                            <?php } ?>
                        </select></label>
                    <textarea name="waf_skip_paths" spellcheck="false" aria-label="Paths without pattern check"><?php echo $h($lines($settings['waf_skip_paths'])); ?></textarea>
                    <span class="sg-help">SQL injection, XSS and path traversal patterns. Start with "log only", check the log for false alarms, then "block". Paths above are not checked (editors that post code).</span></div>
            </div>
        </div>

        <div class="sg-box" id="sg-del-settings">
            <h3>Deletion protection</h3>
            <p class="sg-help sg-m0">Stops the deletion of many resources at once, e.g. by mistake or with a stolen account. Above the limits the deletion waits for the approval
                of an administrator (box "Deletion approvals" below). Counted per user in the ResourceSpace log; checked for the API (the interface uses it), "delete all resources
                of a collection" and batch edit to the "Deleted" state. Scripts on the server (command line) are not limited.</p>
            <?php
            $check('del_enabled', 'Deletion protection is on', '');
            $check('del_force_trash', 'Always move to "Deleted" first', 'If $resource_deletion_state is not set, deleting would remove the files at once; this sets it to 3 ("Deleted"). Resources can then be restored.');
            ?>
            <div class="sg-row">
                <label>Without approval at most <input type="number" name="del_soft_limit" min="0" max="1000000" value="<?php echo (int) $settings['del_soft_limit']; ?>" class="sg-w7"> resources moved to "Deleted"</label>
                <label>and <input type="number" name="del_perm_limit" min="0" max="1000000" value="<?php echo (int) $settings['del_perm_limit']; ?>" class="sg-w7"> deleted permanently</label>
                <label>per user in <input type="number" name="del_window" min="1" max="10080" value="<?php echo (int) $settings['del_window']; ?>" class="sg-w7"> minutes</label>
            </div>
            <p class="sg-help sg-m0">0 resources moved = no limit; 0 deleted permanently = every permanent deletion needs approval.</p>
            <div class="sg-row">
                <label>Permanent deletion in the browser
                    <select name="del_perm_mode">
                        <option value="limit"<?php echo $settings['del_perm_mode'] === 'limit' ? ' selected' : ''; ?>>allowed within the limit, above it with approval</option>
                        <option value="block"<?php echo $settings['del_perm_mode'] === 'block' ? ' selected' : ''; ?>>blocked (only on the server)</option>
                    </select></label>
                <label>Approval valid for <input type="number" name="del_grant_minutes" min="5" max="1440" value="<?php echo (int) $settings['del_grant_minutes']; ?>" class="sg-w7"> minutes</label>
            </div>
            <?php
            $check('del_four_eyes', 'Four eyes', 'An administrator cannot approve their own request - another administrator must do it. Switch off only when there is one administrator.');
            $check('del_notify', 'Notify administrators', 'New requests appear as ResourceSpace notifications of the system administrators.');
            ?>
        </div>

        <div class="sg-box">
            <h3>Share policy</h3>
            <p class="sg-help sg-m0">Rules for external shares (links with access keys) in the share and e-mail forms of resources and collections and for upload shares. Checked on the server.</p>
            <?php
            $check('share_enabled', 'Share policy is on', '');
            $check('share_require_password', 'Password required', 'Every new share needs a password ($share_password_required).');
            $check('share_generate_password', 'Propose a generated password', 'The password field is filled with a random password (it can be regenerated or changed); the user passes it to the recipient.');
            ?>
            <div class="sg-row">
                <label>Minimum password length <input type="number" name="share_password_length" min="6" max="64" value="<?php echo (int) $settings['share_password_length']; ?>" class="sg-w5"> characters (also the length of generated passwords)</label>
            </div>
            <div class="sg-row">
                <label>Expires after <input type="number" name="share_default_days" min="1" max="3650" value="<?php echo (int) $settings['share_default_days']; ?>" class="sg-w5"> days by default,</label>
                <label>at most <input type="number" name="share_max_days" min="1" max="3650" value="<?php echo (int) $settings['share_max_days']; ?>" class="sg-w5"> days</label>
            </div>
            <?php
            $check('share_user_can_change', 'Users may change the expiry date', 'Off = every share expires after the default number of days.');
            $check('share_allow_never', 'Allow "Never"', 'Shares without an expiry date (only when users may change the date).');
            ?>
        </div>

        <div class="sg-box" id="sg-notify">
            <h3>Incident notifications</h3>
            <p class="sg-help sg-m0">Security incidents are sent to the chosen users and to all active members of the chosen user groups - as a ResourceSpace notification
                and/or an e-mail to the address of their account. Only when something happens (never on normal requests); the security log keeps every event.</p>
            <?php $check('notify_enabled', 'Notifications are on', ''); ?>
            <div class="sg-grid">
                <div><label for="sg-nu">Notify users (user names)</label>
                    <textarea id="sg-nu" name="notify_users" spellcheck="false"><?php echo $h($lines($settings['notify_users'])); ?></textarea>
                    <span class="sg-help">One user name per line.</span></div>
                <div><label>Notify user groups</label>
                    <div class="sg-list">
                        <?php foreach (security_guard_usergroups() as $gref => $gname) { ?>
                            <label class="sg-check sg-m0"><input type="checkbox" name="notify_groups[]" value="<?php echo (int) $gref; ?>"<?php echo in_array((int) $gref, $settings['notify_groups'], true) ? ' checked' : ''; ?>> <?php echo $h($gname); ?></label>
                        <?php } ?>
                    </div></div>
                <div><label>Incidents</label>
                    <?php foreach (security_guard_incident_categories() as $ck => $cl) { ?>
                        <label class="sg-check sg-m0"><input type="checkbox" name="notify_events[]" value="<?php echo $h($ck); ?>"<?php echo in_array($ck, $settings['notify_events'], true) ? ' checked' : ''; ?>> <?php echo $h($cl); ?></label>
                    <?php } ?>
                </div>
            </div>
            <div class="sg-row">
                <label><input type="checkbox" name="notify_screen" value="1"<?php echo $settings['notify_screen'] ? ' checked' : ''; ?>> ResourceSpace notification</label>
                <label><input type="checkbox" name="notify_email" value="1"<?php echo $settings['notify_email'] ? ' checked' : ''; ?>> E-mail</label>
                <label>one per rule and address in <input type="number" name="notify_throttle" min="1" max="1440" value="<?php echo (int) $settings['notify_throttle']; ?>" class="sg-w5"> minutes,</label>
                <label>at most <input type="number" name="notify_max_per_hour" min="1" max="1000" value="<?php echo (int) $settings['notify_max_per_hour']; ?>" class="sg-w5"> per hour</label>
            </div>
            <p class="sg-help sg-m0">Users whose preferences send every ResourceSpace notification also by e-mail may get two e-mails - then leave only one channel on.
                Save the settings, then use "Send test notification" below.</p>
        </div>

        <div class="sg-box" id="sg-upload">
            <h3>Upload verification</h3>
            <p class="sg-help sg-m0">Checks every uploaded file: the upload in the interface (new resources, replaced files, alternative files, uploads through a share),
                the API (upload_multipart) and forms. Start with "log only", check the security log, then switch to "enforce".
                Files on the server (API upload_file with a path, upload by URL) are not checked here - they are limited by $valid_upload_paths and $api_upload_urls.</p>
            <div class="sg-row">
                <label>Mode
                    <select name="up_mode">
                        <?php foreach (array('off' => 'off', 'log' => 'log only (nothing is blocked)', 'enforce' => 'enforce (block file types, quarantine doubtful files)') as $v => $l) { ?>
                            <option value="<?php echo $h($v); ?>"<?php echo $settings['up_mode'] === $v ? ' selected' : ''; ?>><?php echo $h($l); ?></option>
                        <?php } ?>
                    </select></label>
            </div>
            <div class="sg-grid">
                <div><label>Allowed file types</label>
                    <?php require_once dirname(__FILE__, 2) . '/include/upload.php'; foreach (security_guard_upload_groups() as $gk => $g) { ?>
                        <label class="sg-check sg-m0"><input type="checkbox" name="up_groups[]" value="<?php echo $h($gk); ?>"<?php echo in_array($gk, $settings['up_groups'], true) ? ' checked' : ''; ?>> <b><?php echo $h($g['label']); ?></b>
                            <span class="sg-help"><?php echo $h(implode(', ', $g['ext'])); ?></span></label>
                    <?php } ?>
                </div>
                <div><label for="sg-ue">Also allow (extensions)</label>
                    <textarea id="sg-ue" name="up_extra_ext" spellcheck="false"><?php echo $h($lines($settings['up_extra_ext'])); ?></textarea>
                    <span class="sg-help">e.g. zip. Extensions banned by ResourceSpace (php, exe, js ...) are never allowed.</span></div>
                <div><label for="sg-ub">Do not allow (extensions)</label>
                    <textarea id="sg-ub" name="up_block_ext" spellcheck="false"><?php echo $h($lines($settings['up_block_ext'])); ?></textarea>
                    <span class="sg-help">Removed from the groups, e.g. svg (SVG images can contain scripts).</span></div>
                <div><label for="sg-us">Not checked (paths)</label>
                    <textarea id="sg-us" name="up_skip_paths" spellcheck="false"><?php echo $h($lines($settings['up_skip_paths'])); ?></textarea>
                    <span class="sg-help">Pages that upload code on purpose (Plugin Manager, Custom CSS import). On the admin pages only the content is checked, not the file type.</span></div>
            </div>
            <?php
            $check('up_inspect', 'Advanced checks', 'The content must match the extension (file signatures) and must not contain programs, scripts, PHP code, macros, active PDF / SVG content, private keys or encrypted content that cannot be checked. Doubtful files go to the quarantine.');
            ?>
            <div class="sg-row">
                <label>Documents are scanned completely up to <input type="number" name="up_scan_mb" min="1" max="500" value="<?php echo (int) $settings['up_scan_mb']; ?>" class="sg-w5"> MB</label>
                <span class="sg-help sg-m0">(images and videos: the beginning and the end of the file)</span>
            </div>
            <div class="sg-row">
                <label><input type="checkbox" name="up_clamav" value="1"<?php echo $settings['up_clamav'] ? ' checked' : ''; ?>> Virus scan with ClamAV, command</label>
                <input type="text" name="up_clamav_cmd" value="<?php echo $h($settings['up_clamav_cmd']); ?>" class="sg-wide" spellcheck="false">
            </div>
            <p class="sg-help sg-m0">Needs ClamAV on the server (e.g. sudo apt install clamav-daemon). clamdscan with --fdpass works with the clamd service; the user that runs PHP must be allowed to use it.</p>
            <div class="sg-row">
                <label>An approved file may be uploaded again within <input type="number" name="up_grant_hours" min="1" max="720" value="<?php echo (int) $settings['up_grant_hours']; ?>" class="sg-w5"> hours;</label>
                <label>quarantined files are deleted after <input type="number" name="up_keep_days" min="1" max="365" value="<?php echo (int) $settings['up_keep_days']; ?>" class="sg-w5"> days</label>
            </div>
            <?php
            $check('up_four_eyes', 'Four eyes', 'Nobody can approve a file they uploaded themselves.');
            $check('up_notify_admins', 'Notify administrators', 'Quarantined files appear as ResourceSpace notifications of the system administrators.');
            ?>
        </div>

        <div class="sg-box">
            <h3>Response headers and log</h3>
            <?php $check('remove_powered_by', 'Remove X-Powered-By', 'Hides the PHP version.'); ?>
            <div class="sg-row"><label>Permissions-Policy <input type="text" name="permissions_policy" value="<?php echo $h($settings['permissions_policy']); ?>" class="sg-wide"></label>
                <span class="sg-help sg-m0">Empty = header not sent.</span></div>
            <div class="sg-row"><label>Log size <input type="number" name="log_max_kb" min="64" max="102400" value="<?php echo (int) $settings['log_max_kb']; ?>" class="sg-w7"> KB</label>
                <span class="sg-help sg-m0">then the log is renamed to events.log.1 (one old file is kept).</span></div>
        </div>

        <div class="sg-row"><button type="submit" name="action" value="save">Save settings</button></div>
    </form>

    <form method="post" action="<?php echo $h($self); ?>" class="sg-row">
        <?php generateFormToken('security_guard'); ?>
        <button type="submit" name="action" value="notify_test" class="sg-outline">Send test notification</button>
        <span class="sg-help sg-m0">to the saved recipients, with the saved channels (also when notifications are off).</span>
    </form>

    <!-- Upload quarantine -->
    <?php
    $uploads   = security_guard_upload_data();
    $q_pending = array_values(array_filter($uploads['items'], function ($r) { return ($r['status'] ?? '') === 'pending'; }));
    $q_decided = array_slice(array_values(array_filter($uploads['items'], function ($r) { return ($r['status'] ?? '') !== 'pending'; })), 0, 20);
    ?>
    <div class="sg-box" id="sg-quarantine">
        <h3>Upload quarantine<?php echo $q_pending ? ' <span class="sg-badge sg-off">' . count($q_pending) . '</span>' : ''; ?></h3>
        <?php if ($q_pending) { ?>
            <table class="sg-table">
                <tr><th>#</th><th>Time</th><th>User</th><th>File</th><th>Reasons</th><th>SHA-256</th><th></th></tr>
                <?php foreach ($q_pending as $r) { ?>
                    <tr><td><?php echo (int) $r['id']; ?></td><td><?php echo $h(date('Y-m-d H:i', (int) $r['time'])); ?></td>
                        <td><?php echo $h($r['username'] !== '' ? $r['username'] : '?'); ?><br><span class="sg-help sg-m0"><?php echo $h($r['ip'] . ', ' . $r['context']); ?></span></td>
                        <td class="sg-wrap"><?php echo $h($r['name']); ?><br><span class="sg-help sg-m0"><?php echo $h(number_format((int) $r['size'] / 1024, 0, '.', ' ') . ' KB'); ?></span></td>
                        <td class="sg-wrap sg-warn"><?php echo $h(implode('; ', (array) $r['reasons'])); ?></td>
                        <td><code title="<?php echo $h($r['sha256']); ?>"><?php echo $h(substr((string) $r['sha256'], 0, 12)); ?>…</code></td>
                        <td><form method="post" action="<?php echo $h($self); ?>" class="sg-row sg-m0">
                            <?php generateFormToken('security_guard'); ?>
                            <input type="hidden" name="file_id" value="<?php echo (int) $r['id']; ?>">
                            <?php if ($r['file'] !== '') { ?><a href="<?php echo $h($self . '?qdownload=' . (int) $r['id']); ?>" title="Download for analysis (do not open it on a workstation without protection)">Download</a><?php } ?>
                            <button type="submit" name="action" value="up_approve"<?php echo ($settings['up_four_eyes'] && (int) $r['user'] === (int) $userref) ? ' disabled title="Your own upload - another administrator must approve it"' : ''; ?>>Approve</button>
                            <button type="submit" name="action" value="up_reject" class="sg-outline">Reject</button>
                        </form></td></tr>
                <?php } ?>
            </table>
            <p class="sg-help sg-m0">Approve = the same file (same SHA-256) may be uploaded by that user within <?php echo (int) $settings['up_grant_hours']; ?> hour(s); the quarantined copy is deleted.</p>
        <?php } else { ?>
            <p><i>No files in the quarantine.</i></p>
        <?php } ?>
        <?php if ($uploads['approved']) { ?>
            <p><b>Approved files</b></p>
            <table class="sg-table">
                <tr><th>File</th><th>User</th><th>Valid until</th><th>Approved by</th></tr>
                <?php foreach ($uploads['approved'] as $sha => $a) { ?>
                    <tr><td><?php echo $h($a['name']); ?> <code title="<?php echo $h($sha); ?>"><?php echo $h(substr((string) $sha, 0, 12)); ?>…</code></td><td><?php echo $h($a['username']); ?></td>
                        <td><?php echo $h(date('Y-m-d H:i', (int) $a['until'])); ?></td><td><?php echo $h($a['by']); ?></td></tr>
                <?php } ?>
            </table>
        <?php } ?>
        <?php if ($q_decided) { ?>
            <details><summary>Decided files (newest 20)</summary>
                <table class="sg-table">
                    <tr><th>#</th><th>Time</th><th>User</th><th>File</th><th>Decision</th><th>By</th></tr>
                    <?php foreach ($q_decided as $r) { ?>
                        <tr><td><?php echo (int) $r['id']; ?></td><td><?php echo $h(date('Y-m-d H:i', (int) $r['time'])); ?></td><td><?php echo $h($r['username']); ?></td>
                            <td class="sg-wrap"><?php echo $h($r['name']); ?></td><td><?php echo $h($r['status']); ?></td>
                            <td><?php echo $h($r['by'] . ((int) $r['decided'] ? ', ' . date('Y-m-d H:i', (int) $r['decided']) : '')); ?></td></tr>
                    <?php } ?>
                </table>
            </details>
        <?php } ?>
    </div>

    <!-- Deletion approvals -->
    <?php
    $deletion = security_guard_deletion_data();
    $pending  = array_values(array_filter($deletion['requests'], function ($r) { return ($r['status'] ?? '') === 'pending'; }));
    $decided  = array_slice(array_values(array_filter($deletion['requests'], function ($r) { return ($r['status'] ?? '') !== 'pending'; })), 0, 20);
    ?>
    <div class="sg-box" id="sg-deletion">
        <h3>Deletion approvals<?php echo $pending ? ' <span class="sg-badge sg-off">' . count($pending) . '</span>' : ''; ?></h3>
        <?php if ($pending) { ?>
            <table class="sg-table">
                <tr><th>#</th><th>Time</th><th>User</th><th>Resources</th><th>What</th><th>Address</th><th></th></tr>
                <?php foreach ($pending as $r) { ?>
                    <tr><td><?php echo (int) $r['id']; ?></td><td><?php echo $h(date('Y-m-d H:i', (int) $r['time'])); ?></td><td><?php echo $h($r['username']); ?></td>
                        <td><?php echo (int) $r['soft']; ?> to Deleted<?php echo (int) $r['perm'] > 0 ? ', <b class="sg-warn">' . (int) $r['perm'] . ' permanently</b>' : ''; ?></td>
                        <td class="sg-wrap"><?php echo $h($r['what']); ?></td><td><?php echo $h($r['ip']); ?></td>
                        <td><form method="post" action="<?php echo $h($self); ?>" class="sg-row sg-m0">
                            <?php generateFormToken('security_guard'); ?>
                            <input type="hidden" name="request_id" value="<?php echo (int) $r['id']; ?>">
                            <label>for <input type="number" name="grant_minutes" min="5" max="1440" value="<?php echo (int) $settings['del_grant_minutes']; ?>" class="sg-w5"> min</label>
                            <button type="submit" name="action" value="del_approve"<?php echo ($settings['del_four_eyes'] && (int) $r['user'] === (int) $userref) ? ' disabled title="Your own request - another administrator must approve it"' : ''; ?>>Approve</button>
                            <button type="submit" name="action" value="del_reject" class="sg-outline">Reject</button>
                        </form></td></tr>
                <?php } ?>
            </table>
        <?php } else { ?>
            <p><i>No requests waiting.</i></p>
        <?php } ?>

        <?php if ($deletion['grants']) { ?>
            <p><b>Active approvals</b></p>
            <table class="sg-table">
                <tr><th>User</th><th>Resources left</th><th>Valid until</th><th>Approved by</th><th></th></tr>
                <?php foreach ($deletion['grants'] as $uref => $g) { ?>
                    <tr><td><?php echo $h($g['username']); ?></td><td><?php echo (int) $g['remaining']; ?></td><td><?php echo $h(date('Y-m-d H:i', (int) $g['until'])); ?></td><td><?php echo $h($g['by']); ?></td>
                        <td><form method="post" action="<?php echo $h($self); ?>" class="sg-m0">
                            <?php generateFormToken('security_guard'); ?>
                            <input type="hidden" name="revoke_user" value="<?php echo (int) $uref; ?>">
                            <button type="submit" name="action" value="del_revoke" class="sg-outline">Withdraw</button>
                        </form></td></tr>
                <?php } ?>
            </table>
        <?php } ?>

        <form method="post" action="<?php echo $h($self); ?>" class="sg-row">
            <?php generateFormToken('security_guard'); ?>
            <b>Approve in advance:</b>
            <label>user name <input type="text" name="grant_user" class="sg-w7" autocomplete="off"></label>
            <label>may delete <input type="number" name="grant_count" min="1" value="100" class="sg-w7"> resources</label>
            <label>within <input type="number" name="grant_minutes" min="5" max="1440" value="<?php echo (int) $settings['del_grant_minutes']; ?>" class="sg-w5"> minutes</label>
            <button type="submit" name="action" value="del_grant">Approve</button>
        </form>

        <?php if ($decided) { ?>
            <details><summary>Decided requests (newest 20)</summary>
                <table class="sg-table">
                    <tr><th>#</th><th>Time</th><th>User</th><th>Resources</th><th>Decision</th><th>By</th></tr>
                    <?php foreach ($decided as $r) { ?>
                        <tr><td><?php echo (int) $r['id']; ?></td><td><?php echo $h(date('Y-m-d H:i', (int) $r['time'])); ?></td><td><?php echo $h($r['username']); ?></td>
                            <td><?php echo (int) $r['soft'] + (int) $r['perm']; ?></td><td><?php echo $h($r['status']); ?></td>
                            <td><?php echo $h($r['by'] . ((int) $r['decided'] ? ', ' . date('Y-m-d H:i', (int) $r['decided']) : '')); ?></td></tr>
                    <?php } ?>
                </table>
            </details>
        <?php } ?>
    </div>

    <!-- Checklist -->
    <div class="sg-box">
        <h3>Configuration check</h3>
        <table class="sg-table">
            <?php foreach (security_guard_checklist($settings) as $c) { ?>
                <tr><td class="sg-<?php echo $h($c[0]); ?>"><?php echo $h(strtoupper($c[0])); ?></td><td><b><?php echo $h($c[1]); ?></b></td><td><?php echo $h($c[2]); ?></td></tr>
            <?php } ?>
        </table>
    </div>

    <!-- Log -->
    <div class="sg-box">
        <h3>Security log (newest 200)</h3>
        <?php if ($log) { ?>
            <div class="sg-log">
                <table class="sg-table">
                    <tr><th>Time</th><th>Action</th><th>Rule</th><th>Address</th><th>Ref.</th><th>Request</th><th>Detail</th></tr>
                    <?php foreach ($log as $e) { ?>
                        <tr><td><?php echo $h(str_replace('T', ' ', substr($e['time'], 0, 19))); ?></td>
                            <td class="<?php echo $e['action'] === 'block' ? 'sg-warn' : 'sg-info'; ?>"><?php echo $h($e['action']); ?></td>
                            <td><?php echo $h($e['rule']); ?></td><td><?php echo $h($e['ip']); ?></td><td><?php echo $h($e['ref']); ?></td>
                            <td class="sg-wrap"><?php echo $h($e['method'] . ' ' . $e['path']); ?></td><td class="sg-wrap"><?php echo $h($e['detail']); ?></td></tr>
                    <?php } ?>
                </table>
            </div>
            <form method="post" action="<?php echo $h($self); ?>" class="sg-row">
                <?php generateFormToken('security_guard'); ?>
                <button type="submit" name="action" value="clear_log" class="sg-outline" id="sg-clear">Clear log</button>
                <span class="sg-help sg-m0">File: <code><?php echo $h(security_guard_log_file()); ?></code></span>
            </form>
        <?php } else { ?>
            <p><i>No events yet.</i> File: <code><?php echo $h(security_guard_log_file()); ?></code></p>
        <?php } ?>
    </div>

    <!-- Server configuration -->
    <details class="sg-box">
        <summary><h3>Server configuration (nginx, fail2ban)</h3></summary>
        <p>A plugin only sees requests that reach ResourceSpace's PHP code. Rate limits before PHP, static files and banning addresses belong to the web server and the system firewall:</p>
        <p><b>nginx</b></p>
        <div class="sg-pre"><?php echo $h(security_guard_nginx_snippet($settings)); ?></div>
        <p><b>fail2ban</b> - bans addresses that were blocked several times (lines <code>action=block</code> of the security log):</p>
        <div class="sg-pre"><?php echo $h(security_guard_fail2ban_snippet()); ?></div>
    </details>

    <!-- Emergency -->
    <details class="sg-box">
        <summary><h3>Disable from the server (emergency)</h3></summary>
        <p>If the plugin blocks something it should not (e.g. after a ResourceSpace update) and the options page cannot be reached, use one of these on the server (fastest first):</p>
        <div class="sg-pre"><?php echo $h(
            "# 1. switch off all checks (the plugin stays active; delete the file to switch on again)\n"
            . "sudo -u www-data mkdir -p " . security_guard_base_dir() . "\n"
            . "sudo -u www-data touch " . security_guard_kill_file() . "\n"
            . "sudo rm " . security_guard_kill_file() . "        # on again\n\n"
            . "# 2. or in " . $rs_root . "/include/config.php:\n"
            . "\$security_guard_disable = true;\n\n"
            . "# 3. remove the code (ResourceSpace skips a plugin without files; settings stay in the filestore)\n"
            . "sudo mv " . $plugin_dir . " /root/security_guard.off\n"
            . "sudo mv /root/security_guard.off " . $plugin_dir . "   # back\n\n"
            . "# 4. deactivate in the database (like System > Plugins > Deactivate)\n"
            . "mysql <database> -e \"UPDATE plugins SET inst_version = NULL WHERE name = 'security_guard';\"\n"
            . "sudo rm -f " . $qcache . "/plugins_*   # ResourceSpace query cache of the plugin list\n"
        ); ?></div>
        <p>Locked out of the admin pages by "Admin pages only from"? Use 1 or 2, log in, fix the list, then switch back on.</p>
    </details>

    <!-- Reset (collapsible) -->
    <details class="sg-box"<?php echo $reset_open ? ' open' : ''; ?>>
        <summary><h3>Reset plugin</h3></summary>
        <p>Deletes everything the plugin stored in <code><?php echo $h(security_guard_base_dir()); ?></code>: settings, security log, counters
            (and the emergency switch file). The default settings apply afterwards. ResourceSpace data is not changed. This cannot be undone.</p>
        <form method="post" action="<?php echo $h($self); ?>" id="sg-reset">
            <?php generateFormToken('security_guard'); ?>
            <div class="sg-row">
                <label>To confirm, type <b>RESET</b> <input type="text" name="reset_confirm" autocomplete="off" spellcheck="false"></label>
                <button type="submit" name="action" value="reset">Reset plugin</button>
            </div>
        </form>
    </details>

    <script<?php echo $nonce; ?>>
    (function () {
        var reset = document.getElementById('sg-reset');
        if (reset) {
            reset.addEventListener('submit', function (e) {
                if (reset.reset_confirm.value.trim() !== 'RESET') { alert('Type RESET to confirm.'); e.preventDefault(); return; }
                if (!confirm('Delete the settings and the security log of Security Guard?')) { e.preventDefault(); }
            });
        }
        var clear = document.getElementById('sg-clear');
        if (clear) {
            clear.addEventListener('click', function (e) {
                if (!confirm('Delete the security log?')) { e.preventDefault(); }
            });
        }
    })();
    </script>
</div>
<?php
include '../../../include/footer.php';
