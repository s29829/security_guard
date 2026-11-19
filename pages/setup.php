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

// Never lock out the administrator who is saving: errors for settings that are switched on
$lockout = function (array $new) {
    $out = array();
    if (!$new['enabled']) {
        return $out;
    }
    $check_ip = security_guard_client_ip($new);
    if ($new['admin_ips'] && !security_guard_ip_in($check_ip, $new['admin_ips'])) {
        $out[] = 'Not saved: your address ' . $check_ip . ' is not in "Admin pages only from" - you would lock yourself out.';
    }
    if ($new['ll_enabled'] && $new['ll_enforce'] && $new['ll_ips'] && !security_guard_ip_in($check_ip, $new['ll_ips'])) {
        $out[] = 'Not saved: your address ' . $check_ip . ' is not in "Local login page only from" - with enforcing you could not log in with a local account.';
    }
    if ($new['blocklist'] && security_guard_ip_in($check_ip, $new['blocklist'])) {
        $out[] = 'Not saved: your address ' . $check_ip . ' is in "Blocked addresses".';
    }
    return $out;
};
$store_err = function () {
    return 'The settings could not be stored (check write access to ' . security_guard_data_dir() . ').';
};
$profiles     = security_guard_profiles();
$pause_times  = array(15 => '15 minutes', 60 => '1 hour', 240 => '4 hours', 1440 => '24 hours');
$wizard_first = !is_file(security_guard_settings_file()); // first start (or after "Reset plugin")

// ---- Handle form actions ----
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action !== '') {
    if (function_exists('enforcePostRequest') && !enforcePostRequest(false)) {
        $errors[] = 'The request could not be verified. Reload the page and try again.';
    } elseif ($action === 'save') {
        $new = $settings;
        foreach (array('patch_report_params', 'patch_login_redirect', 'patch_api_confusion', 'patch_api_lockout', 'patch_get_session',
            'force_random_session', 'saml_hide_errors', 'block_scanners', 'remove_powered_by',
            'del_enabled', 'del_force_trash', 'del_four_eyes', 'del_notify',
            'share_enabled', 'share_require_password', 'share_generate_password', 'share_user_can_change', 'share_allow_never',
            'notify_enabled', 'notify_screen', 'notify_email',
            'up_inspect', 'up_clamav', 'up_four_eyes', 'up_notify_admins',
            'll_enabled', 'll_path_key', 'll_enforce', 'll_enforce_api') as $k) {
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
        $new['ll_path'] = trim(trim((string) ($_POST['ll_path'] ?? '')), '/');
        $ll_err = security_guard_ll_path_error($new['ll_path'], dirname(__FILE__, 4));
        if ($ll_err !== '') {
            $errors[] = $ll_err;
        }
        if ($new['ll_enabled'] && strlen($new['ll_key']) < 16) {
            $new['ll_key'] = bin2hex(random_bytes(16));
        }
        if ($new['ll_enforce'] && !$new['ll_enabled']) {
            $errors[] = 'Enforcing needs the login page for local accounts - switch it on too.';
        }
        foreach (array('trusted_proxies', 'blocklist', 'admin_ips', 'api_ips', 'll_ips') as $k) {
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
        $errors = array_merge($errors, $lockout($new));
        if (!$errors) {
            if (security_guard_save_settings($new)) {
                $changes = security_guard_settings_changes($settings, $new);
                security_guard_log('admin', 'settings_saved', 'by ' . $username . ($changes ? ': ' . implode(', ', $changes) : ''));
                redirect($self . '?done=saved');
                exit;
            }
            $errors[] = $store_err();
        }
        $settings = $new; // show what was entered
    } elseif ($action === 'enable' || $action === 'disable') {
        // top switch (since 1.06); switching on also ends a pause
        $new = $settings;
        $new['enabled'] = $action === 'enable';
        $new['paused_until'] = 0;
        $errors = $lockout($new);
        if (!$errors) {
            if (security_guard_save_settings($new)) {
                security_guard_log('admin', $new['enabled'] ? 'protection_on' : 'protection_off', 'by ' . $username);
                redirect($self . '?done=' . $action);
                exit;
            }
            $errors[] = $store_err();
        }
    } elseif ($action === 'pause' || $action === 'resume') {
        // pause for a chosen time (since 1.06): the checks switch on again by themselves
        $new = $settings;
        $minutes = (int) ($_POST['pause_minutes'] ?? 0);
        if ($action === 'pause' && (!$settings['enabled'] || !isset($pause_times[$minutes]))) {
            $errors[] = 'Choose how long to pause (protection must be on).';
        } else {
            $new['paused_until'] = $action === 'pause' ? time() + $minutes * 60 : 0;
            if ($action === 'resume') {
                $errors = $lockout($new);
            }
            if (!$errors) {
                if (security_guard_save_settings($new)) {
                    security_guard_log('admin', $action === 'pause' ? 'protection_paused' : 'protection_resumed',
                        'by ' . $username . ($action === 'pause' ? ', until ' . date('Y-m-d H:i', $new['paused_until']) : ''));
                    redirect($self . '?done=' . $action);
                    exit;
                }
                $errors[] = $store_err();
            }
        }
    } elseif ($action === 'profile' || $action === 'profile_skip') {
        // configurator (since 1.06): a protection level, or the default settings on the first start
        $new = $settings;
        $level = (string) ($_POST['profile'] ?? '');
        if ($action === 'profile' && !isset($profiles[$level])) {
            $errors[] = 'Choose a protection level.';
        } else {
            if ($action === 'profile') {
                $new = array_merge($new, $profiles[$level]['values']);
                $new['enabled'] = true;
                $new['paused_until'] = 0;
            }
            $errors = $lockout($new);
            if (!$errors) {
                if (security_guard_save_settings($new)) {
                    security_guard_log('admin', 'settings_saved', 'by ' . $username . ': '
                        . ($action === 'profile' ? 'protection level ' . $level : 'configurator skipped, default settings'));
                    redirect($self . '?done=' . $action);
                    exit;
                }
                $errors[] = $store_err();
            }
        }
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
    } elseif ($action === 'll_new_key') {
        $new = $settings;
        $new['ll_key'] = bin2hex(random_bytes(16));
        if (security_guard_save_settings($new)) {
            security_guard_log('admin', 'local_login_key', 'new key of the local login page by ' . $username);
            redirect($self . '?done=ll_key#sg-local-login');
            exit;
        }
        $errors[] = $store_err();
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
    case 'enable':
        $message = 'Security Guard is on.';
        break;
    case 'disable':
        $message = 'Security Guard is off: no checks until you switch it on again.';
        break;
    case 'pause':
        $message = 'Security Guard is paused until ' . date('H:i', (int) $settings['paused_until']) . ' - then it switches on again by itself.';
        break;
    case 'resume':
        $message = 'The pause has ended: Security Guard is on.';
        break;
    case 'profile':
        $message = 'Protection level applied and Security Guard is on. Settings specific to your system are in "Advanced settings".';
        break;
    case 'profile_skip':
        $message = 'The default settings are stored. The configurator is available with the "Configurator" button.';
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
    case 'll_key':
        $message = 'New key of the local login page: the old link does not work any more.';
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
$check  = function ($k, $label, $help) use (&$settings, $h) {
    echo '<label class="sg-check"><input type="checkbox" name="' . $h($k) . '" value="1"' . (!empty($settings[$k]) ? ' checked' : '') . '> <b>' . $h($label) . '</b>';
    echo $help !== '' ? '<span class="sg-help">' . $help . '</span>' : '';
    echo '</label>';
};
$kill_on    = is_file(security_guard_kill_file()) || !empty($GLOBALS['security_guard_disable']);
$paused     = $settings['enabled'] && (int) $settings['paused_until'] > time();
$active     = security_guard_is_on($settings) && !$kill_on;
$state      = $kill_on || !$settings['enabled'] ? 'OFF' : ($paused ? 'PAUSED' : 'ON');
$level      = security_guard_profile_match($settings);
$show_wiz   = $wizard_first || isset($_GET['configurator']);
$adv_open   = (bool) $errors || isset($_GET['advanced']);
$log        = array_map('security_guard_log_parse', security_guard_log_tail(200));
$blocks24   = 0;
foreach ($log as $e) {
    if ($e['action'] === 'block' && strtotime($e['time']) > time() - 86400) {
        $blocks24++;
    }
}
$rs_root    = dirname(__FILE__, 4);
$plugin_dir = dirname(__FILE__, 2);
$qcache     = function_exists('get_query_cache_location') ? get_query_cache_location() : $storagedir . '/tmp/querycache';
$ll_on      = $settings['ll_enabled'] && strlen($settings['ll_key']) >= 16;

require_once dirname(__FILE__, 2) . '/include/upload.php';
$uploads   = security_guard_upload_data();
$q_pending = array_values(array_filter($uploads['items'], function ($r) { return ($r['status'] ?? '') === 'pending'; }));
$q_decided = array_slice(array_values(array_filter($uploads['items'], function ($r) { return ($r['status'] ?? '') !== 'pending'; })), 0, 20);
$deletion  = security_guard_deletion_data();
$pending   = array_values(array_filter($deletion['requests'], function ($r) { return ($r['status'] ?? '') === 'pending'; }));
$decided   = array_slice(array_values(array_filter($deletion['requests'], function ($r) { return ($r['status'] ?? '') !== 'pending'; })), 0, 20);
$checks    = security_guard_checklist($settings);
$warns     = count(array_filter($checks, function ($c) { return $c[0] === 'warn'; }));

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
        /* Two columns on desktop (settings 2/3 like the editor of Custom CSS, status 1/3); one column on smaller screens - since 1.06 */
        .sg-layout { display: block; }
        @media (min-width: 1100px) {
            .sg-layout { display: grid; grid-template-columns: minmax(0, 2fr) minmax(0, 1fr); gap: 24px; align-items: start; }
        }
        .sg-box { margin: 0 0 14px; padding: 10px 14px; border: 1px solid rgba(128, 128, 128, 0.45); border-radius: 6px; }
        .sg-box h3 { margin: 0 0 8px; font-size: 1.05em; }
        details.sg-box > summary, details.sg-adv > summary { cursor: pointer; list-style: none; display: flex; align-items: center; gap: 8px; }
        details.sg-box > summary::-webkit-details-marker, details.sg-adv > summary::-webkit-details-marker { display: none; }
        details.sg-box > summary::before, details.sg-adv > summary::before { content: "\25B8"; display: inline-block; transition: transform 0.15s; }
        details.sg-box[open] > summary::before, details.sg-adv[open] > summary::before { transform: rotate(90deg); }
        details.sg-box > summary h3 { margin: 0; display: inline; }
        details.sg-box[open] > summary { margin-bottom: 8px; }
        .sg-box p { margin: 0.5em 0; }
        .sg-part { margin: 0 0 10px; font-size: 1.2em; }
        .sg-part small { font-size: 0.75em; font-weight: normal; opacity: 0.8; }
        .sg-adv { margin: 22px 0 14px; }
        .sg-adv > summary h2 { margin: 0; display: inline; font-size: 1.2em; }
        .sg-adv-warn { border-left: 4px solid #b26a00; padding: 6px 12px; margin: 10px 0 14px; background: rgba(178, 106, 0, 0.1); }
        /* top bar: state, address, switch, pause, configurator */
        .sg-top { display: flex; flex-wrap: wrap; gap: 10px 24px; align-items: center; justify-content: space-between; }
        .sg-top-info, .sg-top-actions { display: flex; flex-wrap: wrap; gap: 8px 20px; align-items: center; }
        .sg-top-actions { gap: 8px; }
        .sg-top-actions form { display: flex; gap: 6px; align-items: center; margin: 0; }
        .sg-badge { display: inline-block; padding: 2px 10px; border-radius: 10px; font-weight: bold; color: #fff; }
        .sg-on { background: #2e7d32; } .sg-off { background: #c62828; } .sg-paused { background: #b26a00; }
        .sg-page button.sg-blue, .sg-page a.sg-blue { background: #1a68d1 !important; border: 1px solid #1a68d1 !important; color: #fff !important; border-radius: 4px;
            padding: 5px 16px; font-weight: bold; cursor: pointer; text-decoration: none; display: inline-flex; align-items: center; gap: 6px; }
        .sg-page button.sg-blue:hover, .sg-page button.sg-blue:focus { background: #1453a8 !important; border-color: #1453a8 !important; }
        .sg-page .sg-outline { display: inline-flex; align-items: center; gap: 5px; background: transparent !important; border: 1px solid currentColor !important;
            color: inherit !important; border-radius: 4px; box-shadow: none; text-decoration: none; padding: 4px 12px; cursor: pointer; }
        .sg-page .sg-outline:hover, .sg-page .sg-outline:focus { background: rgba(128, 128, 128, 0.18) !important; }
        /* configurator */
        .sg-wizard { border: 2px solid #1a68d1; }
        .sg-levels { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 12px; margin: 10px 0; }
        .sg-level { display: block; border: 1px solid rgba(128, 128, 128, 0.5); border-radius: 6px; padding: 10px 12px; cursor: pointer; }
        .sg-level:has(input:checked) { border-color: #1a68d1; box-shadow: 0 0 0 1px #1a68d1; }
        .sg-level ul { margin: 6px 0 0 18px; padding: 0; }
        .sg-level li { margin: 2px 0; font-size: 0.92em; }
        /* fields */
        .sg-check { display: block; margin: 6px 0; }
        .sg-help { display: block; margin: 2px 0 0 24px; opacity: 0.8; font-size: 0.92em; font-weight: normal; }
        .sg-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 12px 20px; }
        .sg-grid label { font-weight: bold; display: block; margin-bottom: 3px; }
        .sg-grid textarea { width: 100%; box-sizing: border-box; min-height: 90px; font-family: monospace; font-size: 0.9em; }
        .sg-grid .sg-help { margin-left: 0; }
        .sg-row { display: flex; flex-wrap: wrap; gap: 8px 16px; align-items: center; margin: 6px 0; }
        .sg-table { width: 100%; border-collapse: collapse; font-size: 0.92em; }
        .sg-table th, .sg-table td { text-align: left; padding: 4px 8px; border-bottom: 1px solid rgba(128, 128, 128, 0.3); vertical-align: top; }
        .sg-wrap { word-break: break-all; }
        .sg-ok { color: #2e7d32; font-weight: bold; } .sg-warn { color: #c62828; font-weight: bold; } .sg-info { opacity: 0.75; font-weight: bold; }
        .sg-pre { white-space: pre; overflow: auto; padding: 8px; border: 1px solid rgba(128, 128, 128, 0.4); border-radius: 4px; font-family: monospace; font-size: 0.85em; max-height: 360px; }
        .sg-m0 { margin: 0 !important; } .sg-w5 { width: 5em; } .sg-w7 { width: 7em; } .sg-w15 { width: 15em; } .sg-wide { width: 36em; max-width: 100%; }
        .sg-list { max-height: 160px; overflow: auto; border: 1px solid rgba(128, 128, 128, 0.4); border-radius: 4px; padding: 4px 8px; }
        .sg-save { margin: 10px 0 0; }
        /* status column: compact lists */
        .sg-side .sg-box { overflow-wrap: anywhere; }
        .sg-items { list-style: none; margin: 0; padding: 0; }
        .sg-items li { padding: 5px 0; border-bottom: 1px solid rgba(128, 128, 128, 0.3); font-size: 0.92em; }
        .sg-items li:last-child { border-bottom: 0; }
        .sg-tag { display: inline-block; min-width: 3.2em; font-size: 0.85em; }
        .sg-log { max-height: 520px; overflow: auto; }
        .sg-log li { font-family: monospace; font-size: 0.85em; }
        .sg-count { font-weight: normal; opacity: 0.75; }
        /* section status against the recommended settings, Reset / Undo, fields below the recommendation (since 1.07) */
        .sg-head { display: flex; flex-wrap: wrap; align-items: center; gap: 6px 10px; margin: 0 0 8px; }
        .sg-head h3 { margin: 0 !important; flex: 1 1 auto; }
        .sg-sec-status { display: inline-flex; align-items: center; gap: 4px; padding: 1px 9px; border: 1px solid currentColor; border-radius: 10px;
            font-size: 0.85em; font-weight: bold; white-space: nowrap; cursor: help; }
        .sg-sec-status svg { width: 15px; height: 15px; fill: currentColor; flex: 0 0 auto; }
        .sg-st-rec, .sg-st-custom { color: #2e7d32; }
        .sg-st-low { color: #c62828; }
        .sg-page .sg-head .sg-outline { padding: 1px 10px; font-size: 0.85em; }
        details.sg-box > summary > .sg-sec-status { margin-left: auto; }
        .sg-low { outline: 2px solid rgba(214, 120, 0, 0.8); outline-offset: 2px; border-radius: 3px; background: rgba(214, 120, 0, 0.08); }
        .sg-rec-hint { display: inline-block; margin-left: 8px; color: #b26a00; font-size: 0.88em; font-weight: bold; }
    </style>

    <!-- Top bar: state and switches (since 1.06) -->
    <div class="sg-box sg-top">
        <div class="sg-top-info">
            <span>Protection: <span class="sg-badge <?php echo $state === 'ON' ? 'sg-on' : ($state === 'PAUSED' ? 'sg-paused' : 'sg-off'); ?>"><?php echo $h($state); ?></span>
                <?php if ($paused) { ?> until <b><?php echo $h(date('H:i', (int) $settings['paused_until'])); ?></b><?php } ?></span>
            <span>Level: <b><?php echo $h($level !== '' ? substr($profiles[$level]['label'], 3) : 'Custom'); ?></b></span>
            <span>Your address: <code><?php echo $h($client_ip); ?></code></span>
            <span>Blocked in the last 24 h: <b><?php echo (int) $blocks24; ?></b></span>
            <?php if ($kill_on) { ?><span class="sg-warn">Emergency switch is on (see "Disable from the server").</span><?php } ?>
        </div>
        <div class="sg-top-actions">
            <form method="post" action="<?php echo $h($self); ?>" id="sg-switch">
                <?php generateFormToken('security_guard'); ?>
                <?php if ($settings['enabled']) { ?>
                    <button type="submit" name="action" value="disable" class="sg-blue" title="Off = the plugin does nothing (also without deactivating it)">&#9211; Turn off</button>
                <?php } else { ?>
                    <button type="submit" name="action" value="enable" class="sg-blue">&#9211; Turn on</button>
                <?php } ?>
            </form>
            <?php if ($settings['enabled']) { ?>
                <form method="post" action="<?php echo $h($self); ?>">
                    <?php generateFormToken('security_guard'); ?>
                    <?php if ($paused) { ?>
                        <button type="submit" name="action" value="resume" class="sg-outline">&#9654; Resume now</button>
                    <?php } else { ?>
                        <select name="pause_minutes" aria-label="Pause for">
                            <?php foreach ($pause_times as $m => $l) { ?><option value="<?php echo (int) $m; ?>"<?php echo $m === 60 ? ' selected' : ''; ?>><?php echo $h($l); ?></option><?php } ?>
                        </select>
                        <button type="submit" name="action" value="pause" class="sg-outline" title="All checks off for the chosen time, then on again by themselves">&#10074;&#10074; Pause</button>
                    <?php } ?>
                </form>
            <?php } ?>
            <a href="<?php echo $h($self . '?configurator=1#sg-configurator'); ?>" class="sg-outline">&#9881; Configurator&hellip;</a>
        </div>
    </div>

    <?php if ($show_wiz) { ?>
    <!-- Configurator (since 1.06): shown on the first start and with the "Configurator" button -->
    <div class="sg-box sg-wizard" id="sg-configurator">
        <h3><?php echo $wizard_first ? 'Welcome to Security Guard - choose a protection level' : 'Configurator - protection level'; ?></h3>
        <p class="sg-m0">A level sets only general settings that suit most sites. Settings specific to your system - IP address lists, proxies, admin pages, the login page
            for local accounts, ClamAV, notification recipients, extra file types - are not changed; set them in "Advanced settings" when you know your setup.
            Applying a level switches Security Guard on. You can change every setting afterwards or open the configurator again.</p>
        <form method="post" action="<?php echo $h($self); ?>">
            <?php generateFormToken('security_guard'); ?>
            <div class="sg-levels">
                <?php foreach ($profiles as $pk => $p) { ?>
                    <label class="sg-level">
                        <input type="radio" name="profile" value="<?php echo $h($pk); ?>"<?php echo ($level !== '' ? $level === $pk : $pk === 'recommended') ? ' checked' : ''; ?>>
                        <b><?php echo $h($p['label']); ?></b><?php echo $pk === $level ? ' <span class="sg-count">(current)</span>' : ''; ?>
                        <span class="sg-help sg-m0"><?php echo $h($p['desc']); ?></span>
                        <ul><?php foreach ($p['items'] as $it) { ?><li><?php echo $h($it); ?></li><?php } ?></ul>
                    </label>
                <?php } ?>
            </div>
            <div class="sg-row">
                <button type="submit" name="action" value="profile" class="sg-blue">Apply level</button>
                <?php if ($wizard_first) { ?>
                    <button type="submit" name="action" value="profile_skip" class="sg-outline">Skip - keep the default settings (level Basic)</button>
                <?php } else { ?>
                    <a href="<?php echo $h($self); ?>" class="sg-outline">Cancel</a>
                <?php } ?>
            </div>
        </form>
    </div>
    <?php } ?>

    <div class="sg-layout">
    <!-- ================= Left: settings ================= -->
    <div class="sg-main">
    <form method="post" action="<?php echo $h($self); ?>" id="sg-settings">
        <?php generateFormToken('security_guard'); ?>

        <h2 class="sg-part">Settings <small>- recommended for most sites</small></h2>

        <div class="sg-box" data-sg-section="patches">
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

        <div class="sg-box" data-sg-section="detection">
            <h3>Attack detection</h3>
            <?php $check('block_scanners', 'Block scanners', 'Automated attack tools announce themselves in the User-Agent (list in the advanced settings). Not a protection against careful attackers, but stops noise.'); ?>
            <div class="sg-row">
                <label><b>Attack patterns in parameters</b>
                    <select name="waf_mode">
                        <?php foreach (array('off' => 'off', 'log' => 'log only', 'block' => 'block') as $v => $l) { ?>
                            <option value="<?php echo $h($v); ?>"<?php echo $settings['waf_mode'] === $v ? ' selected' : ''; ?>><?php echo $h($l); ?></option>
                        <?php } ?>
                    </select></label>
            </div>
            <span class="sg-help sg-m0">SQL injection, XSS and path traversal patterns. Start with "log only", check the log for false alarms, then "block".</span>
            <p><b>SimpleSAMLphp</b> <span class="sg-help sg-m0">Works when SimpleSAMLphp reads its configuration from ResourceSpace ($simplesaml_rsconfig). SSO logins are never blocked.</span></p>
            <?php $check('saml_hide_errors', 'Hide error details', 'showerrors / errorreporting = false: error pages without stack traces and paths.'); ?>
            <div class="sg-row">
                <label>Local login form: at most <input type="number" name="saml_limit" min="0" max="1000" value="<?php echo (int) $settings['saml_limit']; ?>" class="sg-w5"> login attempts
                    per IP in <input type="number" name="saml_window" min="1" max="1440" value="<?php echo (int) $settings['saml_window']; ?>" class="sg-w5"> minutes (0 = no limit)</label>
            </div>
        </div>

        <div class="sg-box" id="sg-del-settings" data-sg-section="deletion">
            <h3>Deletion protection</h3>
            <p class="sg-help sg-m0">Stops the deletion of many resources at once, e.g. by mistake or with a stolen account. Above the limits the deletion waits for the approval
                of an administrator (box "Deletion approvals"). Counted per user in the ResourceSpace log; checked for the API (the interface uses it), "delete all resources
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

        <div class="sg-box" data-sg-section="share">
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

        <div class="sg-box" id="sg-upload" data-sg-section="upload">
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
            <p class="sg-m0"><b>Allowed file types</b> <span class="sg-help sg-m0">(more or fewer extensions: advanced settings)</span></p>
            <?php foreach (security_guard_upload_groups() as $gk => $g) { ?>
                <label class="sg-check"><input type="checkbox" name="up_groups[]" value="<?php echo $h($gk); ?>"<?php echo in_array($gk, $settings['up_groups'], true) ? ' checked' : ''; ?>> <b><?php echo $h($g['label']); ?></b>
                    <span class="sg-help"><?php echo $h(implode(', ', $g['ext'])); ?></span></label>
            <?php } ?>
            <?php
            $check('up_inspect', 'Advanced checks', 'The content must match the extension (file signatures) and must not contain programs, scripts, PHP code, macros, active PDF / SVG content, private keys or encrypted content that cannot be checked. Doubtful files go to the quarantine.');
            ?>
            <div class="sg-row">
                <label>Documents are scanned completely up to <input type="number" name="up_scan_mb" min="1" max="500" value="<?php echo (int) $settings['up_scan_mb']; ?>" class="sg-w5"> MB</label>
                <span class="sg-help sg-m0">(images and videos: the beginning and the end of the file)</span>
            </div>
            <div class="sg-row">
                <label>An approved file may be uploaded again within <input type="number" name="up_grant_hours" min="1" max="720" value="<?php echo (int) $settings['up_grant_hours']; ?>" class="sg-w5"> hours;</label>
                <label>quarantined files are deleted after <input type="number" name="up_keep_days" min="1" max="365" value="<?php echo (int) $settings['up_keep_days']; ?>" class="sg-w5"> days</label>
            </div>
            <?php
            $check('up_four_eyes', 'Four eyes', 'Nobody can approve a file they uploaded themselves.');
            $check('up_notify_admins', 'Notify administrators', 'Quarantined files appear as ResourceSpace notifications of the system administrators.');
            ?>
        </div>

        <div class="sg-box" id="sg-notify" data-sg-section="notify">
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
            </div>
            <p class="sg-m0"><b>Incidents</b></p>
            <?php foreach (security_guard_incident_categories() as $ck => $cl) { ?>
                <label class="sg-check sg-m0"><input type="checkbox" name="notify_events[]" value="<?php echo $h($ck); ?>"<?php echo in_array($ck, $settings['notify_events'], true) ? ' checked' : ''; ?>> <?php echo $h($cl); ?></label>
            <?php } ?>
            <div class="sg-row">
                <label><input type="checkbox" name="notify_screen" value="1"<?php echo $settings['notify_screen'] ? ' checked' : ''; ?>> ResourceSpace notification</label>
                <label><input type="checkbox" name="notify_email" value="1"<?php echo $settings['notify_email'] ? ' checked' : ''; ?>> E-mail</label>
                <label>one per rule and address in <input type="number" name="notify_throttle" min="1" max="1440" value="<?php echo (int) $settings['notify_throttle']; ?>" class="sg-w5"> minutes,</label>
                <label>at most <input type="number" name="notify_max_per_hour" min="1" max="1000" value="<?php echo (int) $settings['notify_max_per_hour']; ?>" class="sg-w5"> per hour</label>
            </div>
            <p class="sg-help sg-m0">Users whose preferences send every ResourceSpace notification also by e-mail may get two e-mails - then leave only one channel on.</p>
            <div class="sg-row">
                <button type="submit" name="action" value="notify_test" form="sg-notify-test" class="sg-outline">Send test notification</button>
                <span class="sg-help sg-m0">to the saved recipients, with the saved channels (also when notifications are off) - save the settings first.</span>
            </div>
        </div>

        <div class="sg-box" data-sg-section="headers">
            <h3>Response headers</h3>
            <?php $check('remove_powered_by', 'Remove X-Powered-By', 'Hides the PHP version.'); ?>
        </div>

        <div class="sg-row sg-save"><button type="submit" name="action" value="save" class="sg-blue">Save settings</button></div>

        <!-- Advanced: settings that depend on the system (since 1.06) -->
        <details class="sg-adv" id="sg-advanced"<?php echo $adv_open ? ' open' : ''; ?>>
            <summary><h2>Advanced settings</h2> <span class="sg-count">- depend on your system</span></summary>
            <div class="sg-adv-warn">These settings depend on your network, web server and accounts. A wrong value can lock out users or administrators
                (e.g. an address list without your office) - change them only when you know the system. The configurator never changes them.
                Locked out? See "Disable from the server".</div>

            <div class="sg-box" data-sg-section="firewall">
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
                    <div><label for="sg-ua">Scanners (User-Agent contains)</label>
                        <textarea id="sg-ua" name="scanner_agents" spellcheck="false"><?php echo $h($lines($settings['scanner_agents'])); ?></textarea>
                        <span class="sg-help">Used by "Block scanners".</span></div>
                    <div><label for="sg-ws">Paths without the attack pattern check</label>
                        <textarea id="sg-ws" name="waf_skip_paths" spellcheck="false"><?php echo $h($lines($settings['waf_skip_paths'])); ?></textarea>
                        <span class="sg-help">Editors that post code (e.g. Custom CSS, site content).</span></div>
                </div>
                <div class="sg-row">
                    <label>SimpleSAMLphp local login form and admin pages
                        <select name="saml_panel">
                            <?php foreach (array('open' => 'open to everyone', 'allowlist' => 'only from "Admin pages only from" addresses', 'block' => 'blocked') as $v => $l) { ?>
                                <option value="<?php echo $h($v); ?>"<?php echo $settings['saml_panel'] === $v ? ' selected' : ''; ?>><?php echo $h($l); ?></option>
                            <?php } ?>
                        </select></label>
                </div>
            </div>

            <div class="sg-box" id="sg-local-login" data-sg-section="local_login">
                <h3>Login page for local accounts</h3>
                <p class="sg-help sg-m0">A separate page with user name and password for accounts without single sign-on - e.g. when the standard login page shows only
                    the SSO button (Custom CSS: "Hide the local login fields"). The form posts to login.php, so ResourceSpace checks the password, the lockouts and the session.
                    Without the key or the own address the page answers "Not found".</p>
                <?php $check('ll_enabled', 'Login page for local accounts is on', 'A secret key for the link is created when you save.'); ?>
                <?php if ($ll_on) { ?>
                    <p class="sg-m0"><b>Link with the key</b> (works without changes to the web server; keep it secret, e.g. in a password manager):<br>
                        <a href="<?php echo $h(security_guard_ll_url($settings, array(), false)); ?>" target="_blank" rel="noopener"><code class="sg-wrap"><?php echo $h(security_guard_ll_url($settings, array(), false)); ?></code></a></p>
                    <?php if (trim($settings['ll_path'], '/') !== '') { ?>
                        <p class="sg-m0"><b>Own address</b> (needs the rule in "Server configuration"):<br>
                            <a href="<?php echo $h(security_guard_ll_url($settings)); ?>" target="_blank" rel="noopener"><code class="sg-wrap"><?php echo $h(security_guard_ll_url($settings)); ?></code></a></p>
                    <?php } ?>
                    <div class="sg-row">
                        <button type="submit" name="action" value="ll_new_key" form="sg-ll-key" class="sg-outline">New key for the local login page</button>
                        <span class="sg-help sg-m0">The old link (and the own address with the key) stops working at once.</span>
                    </div>
                <?php } ?>
                <div class="sg-row">
                    <label>Own address <?php echo $h(rtrim((string) $baseurl, '/') . '/'); ?><input type="text" name="ll_path" value="<?php echo $h($settings['ll_path']); ?>" class="sg-w15" placeholder="local-login" spellcheck="false"></label>
                    <span class="sg-help sg-m0">Empty = only the link with the key. Letters, digits, "-", "_", ".".</span>
                </div>
                <?php $check('ll_path_key', 'The own address also needs the key', 'Without it the address itself is the secret (choose one that is hard to guess).'); ?>
                <div class="sg-grid">
                    <div><label for="sg-lli">Local login page only from</label>
                        <textarea id="sg-lli" name="ll_ips" spellcheck="false"><?php echo $h($lines($settings['ll_ips'])); ?></textarea>
                        <span class="sg-help">Addresses or networks, one per line. Empty = from anywhere (with the key or the own address).</span></div>
                </div>
                <?php
                $check('ll_enforce', 'Enforce: local accounts log in only on this page', 'login.php refuses a user name and password that do not come from this page (the user sees "Local accounts log in on their own login page"). Single sign-on is not affected. Keep the link: without it local accounts (also administrators without SSO) cannot log in - in an emergency switch Security Guard off on the server (box "Disable from the server").');
                $check('ll_enforce_api', 'With enforcing: also refuse the password login of the API (function=login)', 'Systems that sign API calls with an API key are not affected.');
                ?>
            </div>

            <div class="sg-box" data-sg-section="upload_adv">
                <h3>Upload verification - file types and virus scan</h3>
                <div class="sg-grid">
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
                <div class="sg-row">
                    <label><input type="checkbox" name="up_clamav" value="1"<?php echo $settings['up_clamav'] ? ' checked' : ''; ?>> Virus scan with ClamAV, command</label>
                    <input type="text" name="up_clamav_cmd" value="<?php echo $h($settings['up_clamav_cmd']); ?>" class="sg-wide" spellcheck="false">
                </div>
                <p class="sg-help sg-m0">Needs ClamAV on the server (e.g. sudo apt install clamav-daemon). clamdscan with --fdpass works with the clamd service; the user that runs PHP must be allowed to use it.</p>
            </div>

            <div class="sg-box" data-sg-section="headers_log">
                <h3>Headers and log</h3>
                <div class="sg-row"><label>Permissions-Policy <input type="text" name="permissions_policy" value="<?php echo $h($settings['permissions_policy']); ?>" class="sg-wide"></label>
                    <span class="sg-help sg-m0">Empty = header not sent.</span></div>
                <div class="sg-row"><label>Log size <input type="number" name="log_max_kb" min="64" max="102400" value="<?php echo (int) $settings['log_max_kb']; ?>" class="sg-w7"> KB</label>
                    <span class="sg-help sg-m0">then the log is renamed to events.log.1 (one old file is kept).</span></div>
            </div>

            <div class="sg-row sg-save"><button type="submit" name="action" value="save" class="sg-blue">Save settings</button></div>
        </details>
    </form>
    <!-- forms of the buttons inside the settings (forms cannot be nested) -->
    <form method="post" action="<?php echo $h($self); ?>" id="sg-notify-test"><?php generateFormToken('security_guard'); ?></form>
    <?php if ($ll_on) { ?><form method="post" action="<?php echo $h($self); ?>" id="sg-ll-key"><?php generateFormToken('security_guard'); ?></form><?php } ?>
    </div>

    <!-- ================= Right: status ================= -->
    <div class="sg-side">
        <h2 class="sg-part">Status</h2>

        <?php if ($q_pending || $uploads['approved'] || $q_decided) { ?>
        <!-- Upload quarantine -->
        <details class="sg-box" id="sg-quarantine" data-sg-mirror="upload"<?php echo $q_pending ? ' open' : ''; ?>>
            <summary><h3>Upload quarantine<?php echo $q_pending ? ' <span class="sg-badge sg-off">' . count($q_pending) . '</span>' : ''; ?></h3></summary>
            <?php if ($q_pending) { ?>
                <ul class="sg-items">
                    <?php foreach ($q_pending as $r) { ?>
                        <li><b>#<?php echo (int) $r['id']; ?> <?php echo $h($r['name']); ?></b> <span class="sg-count">(<?php echo $h(number_format((int) $r['size'] / 1024, 0, '.', ' ') . ' KB'); ?>)</span><br>
                            <?php echo $h(date('Y-m-d H:i', (int) $r['time'])); ?>, <?php echo $h($r['username'] !== '' ? $r['username'] : '?'); ?>, <?php echo $h($r['ip'] . ', ' . $r['context']); ?><br>
                            <span class="sg-warn"><?php echo $h(implode('; ', (array) $r['reasons'])); ?></span><br>
                            SHA-256 <code title="<?php echo $h($r['sha256']); ?>"><?php echo $h(substr((string) $r['sha256'], 0, 12)); ?>…</code>
                            <form method="post" action="<?php echo $h($self); ?>" class="sg-row">
                                <?php generateFormToken('security_guard'); ?>
                                <input type="hidden" name="file_id" value="<?php echo (int) $r['id']; ?>">
                                <?php if ($r['file'] !== '') { ?><a href="<?php echo $h($self . '?qdownload=' . (int) $r['id']); ?>" title="Download for analysis (do not open it on a workstation without protection)">Download</a><?php } ?>
                                <button type="submit" name="action" value="up_approve"<?php echo ($settings['up_four_eyes'] && (int) $r['user'] === (int) $userref) ? ' disabled title="Your own upload - another administrator must approve it"' : ''; ?>>Approve</button>
                                <button type="submit" name="action" value="up_reject" class="sg-outline">Reject</button>
                            </form></li>
                    <?php } ?>
                </ul>
                <p class="sg-help sg-m0">Approve = the same file (same SHA-256) may be uploaded by that user within <?php echo (int) $settings['up_grant_hours']; ?> hour(s); the quarantined copy is deleted.</p>
            <?php } else { ?>
                <p><i>No files in the quarantine.</i></p>
            <?php } ?>
            <?php if ($uploads['approved']) { ?>
                <p><b>Approved files</b></p>
                <ul class="sg-items">
                    <?php foreach ($uploads['approved'] as $sha => $a) { ?>
                        <li><?php echo $h($a['name']); ?> <code title="<?php echo $h($sha); ?>"><?php echo $h(substr((string) $sha, 0, 12)); ?>…</code><br>
                            <?php echo $h($a['username']); ?>, until <?php echo $h(date('Y-m-d H:i', (int) $a['until'])); ?>, by <?php echo $h($a['by']); ?></li>
                    <?php } ?>
                </ul>
            <?php } ?>
            <?php if ($q_decided) { ?>
                <details><summary>Decided files (newest 20)</summary>
                    <ul class="sg-items">
                        <?php foreach ($q_decided as $r) { ?>
                            <li>#<?php echo (int) $r['id']; ?> <?php echo $h($r['name']); ?> - <b><?php echo $h($r['status']); ?></b><br>
                                <?php echo $h(date('Y-m-d H:i', (int) $r['time']) . ', ' . $r['username'] . '; by ' . $r['by'] . ((int) $r['decided'] ? ', ' . date('Y-m-d H:i', (int) $r['decided']) : '')); ?></li>
                        <?php } ?>
                    </ul>
                </details>
            <?php } ?>
        </details>
        <?php } ?>

        <!-- Deletion approvals -->
        <details class="sg-box" id="sg-deletion" data-sg-mirror="deletion"<?php echo $pending || $deletion['grants'] ? ' open' : ''; ?>>
            <summary><h3>Deletion approvals<?php echo $pending ? ' <span class="sg-badge sg-off">' . count($pending) . '</span>' : ''; ?></h3></summary>
            <?php if ($pending) { ?>
                <ul class="sg-items">
                    <?php foreach ($pending as $r) { ?>
                        <li><b>#<?php echo (int) $r['id']; ?> <?php echo $h($r['username']); ?></b>: <?php echo (int) $r['soft']; ?> to Deleted<?php echo (int) $r['perm'] > 0 ? ', <b class="sg-warn">' . (int) $r['perm'] . ' permanently</b>' : ''; ?><br>
                            <?php echo $h(date('Y-m-d H:i', (int) $r['time']) . ', ' . $r['ip']); ?><br><span class="sg-wrap"><?php echo $h($r['what']); ?></span>
                            <form method="post" action="<?php echo $h($self); ?>" class="sg-row">
                                <?php generateFormToken('security_guard'); ?>
                                <input type="hidden" name="request_id" value="<?php echo (int) $r['id']; ?>">
                                <label>for <input type="number" name="grant_minutes" min="5" max="1440" value="<?php echo (int) $settings['del_grant_minutes']; ?>" class="sg-w5"> min</label>
                                <button type="submit" name="action" value="del_approve"<?php echo ($settings['del_four_eyes'] && (int) $r['user'] === (int) $userref) ? ' disabled title="Your own request - another administrator must approve it"' : ''; ?>>Approve</button>
                                <button type="submit" name="action" value="del_reject" class="sg-outline">Reject</button>
                            </form></li>
                    <?php } ?>
                </ul>
            <?php } else { ?>
                <p><i>No requests waiting.</i></p>
            <?php } ?>
            <?php if ($deletion['grants']) { ?>
                <p><b>Active approvals</b></p>
                <ul class="sg-items">
                    <?php foreach ($deletion['grants'] as $uref => $g) { ?>
                        <li><b><?php echo $h($g['username']); ?></b>: <?php echo (int) $g['remaining']; ?> left, until <?php echo $h(date('Y-m-d H:i', (int) $g['until'])); ?>, by <?php echo $h($g['by']); ?>
                            <form method="post" action="<?php echo $h($self); ?>" class="sg-row">
                                <?php generateFormToken('security_guard'); ?>
                                <input type="hidden" name="revoke_user" value="<?php echo (int) $uref; ?>">
                                <button type="submit" name="action" value="del_revoke" class="sg-outline">Withdraw</button>
                            </form></li>
                    <?php } ?>
                </ul>
            <?php } ?>
            <form method="post" action="<?php echo $h($self); ?>">
                <?php generateFormToken('security_guard'); ?>
                <p class="sg-m0"><b>Approve in advance</b></p>
                <div class="sg-row">
                    <label>user name <input type="text" name="grant_user" class="sg-w7" autocomplete="off"></label>
                    <label>may delete <input type="number" name="grant_count" min="1" value="100" class="sg-w7"> resources</label>
                    <label>within <input type="number" name="grant_minutes" min="5" max="1440" value="<?php echo (int) $settings['del_grant_minutes']; ?>" class="sg-w5"> minutes</label>
                    <button type="submit" name="action" value="del_grant">Approve</button>
                </div>
            </form>
            <?php if ($decided) { ?>
                <details><summary>Decided requests (newest 20)</summary>
                    <ul class="sg-items">
                        <?php foreach ($decided as $r) { ?>
                            <li>#<?php echo (int) $r['id']; ?> <?php echo $h($r['username']); ?>, <?php echo (int) $r['soft'] + (int) $r['perm']; ?> resource(s) - <b><?php echo $h($r['status']); ?></b><br>
                                <?php echo $h(date('Y-m-d H:i', (int) $r['time']) . '; by ' . $r['by'] . ((int) $r['decided'] ? ', ' . date('Y-m-d H:i', (int) $r['decided']) : '')); ?></li>
                        <?php } ?>
                    </ul>
                </details>
            <?php } ?>
        </details>

        <!-- Checklist -->
        <details class="sg-box" id="sg-check" open>
            <summary><h3>Configuration check<?php echo $warns ? ' <span class="sg-badge sg-off">' . (int) $warns . '</span>' : ''; ?></h3></summary>
            <ul class="sg-items">
                <?php foreach ($checks as $c) { ?>
                    <li><span class="sg-tag sg-<?php echo $h($c[0]); ?>"><?php echo $h(strtoupper($c[0])); ?></span> <b><?php echo $h($c[1]); ?></b><br><?php echo $h($c[2]); ?></li>
                <?php } ?>
            </ul>
        </details>

        <!-- Log (collapsible) -->
        <details class="sg-box" id="sg-log">
            <summary><h3>Security log <span class="sg-count">(<?php echo count($log); ?><?php echo count($log) >= 200 ? ', newest 200' : ''; ?>)</span></h3></summary>
            <?php if ($log) { ?>
                <ul class="sg-items sg-log">
                    <?php foreach ($log as $e) { ?>
                        <li><?php echo $h(str_replace('T', ' ', substr($e['time'], 0, 19))); ?>
                            <span class="<?php echo $e['action'] === 'block' ? 'sg-warn' : 'sg-info'; ?>"><?php echo $h($e['action']); ?></span> <b><?php echo $h($e['rule']); ?></b>
                            <?php echo $h($e['ip']); ?><?php echo $e['ref'] !== '' ? ' ' . $h($e['ref']) : ''; ?><br>
                            <span class="sg-wrap"><?php echo $h(trim($e['method'] . ' ' . $e['path'])); ?></span><?php echo $e['detail'] !== '' ? '<br><span class="sg-wrap">' . $h($e['detail']) . '</span>' : ''; ?></li>
                    <?php } ?>
                </ul>
                <form method="post" action="<?php echo $h($self); ?>" class="sg-row">
                    <?php generateFormToken('security_guard'); ?>
                    <button type="submit" name="action" value="clear_log" class="sg-outline" id="sg-clear">Clear log</button>
                </form>
            <?php } else { ?>
                <p><i>No events yet.</i></p>
            <?php } ?>
            <p class="sg-help sg-m0">File: <code><?php echo $h(security_guard_log_file()); ?></code></p>
        </details>

        <!-- Server configuration -->
        <details class="sg-box" id="sg-server">
            <summary><h3>Server configuration (nginx, fail2ban)</h3></summary>
            <p>A plugin only sees requests that reach ResourceSpace's PHP code. Rate limits before PHP, static files and banning addresses belong to the web server and the system firewall:</p>
            <p><b>nginx</b></p>
            <div class="sg-pre"><?php echo $h(security_guard_nginx_snippet($settings)); ?></div>
            <?php $ll_snip = security_guard_ll_server_snippet($settings); if ($ll_snip !== '') { ?>
                <p><b>Own address of the login page for local accounts</b></p>
                <div class="sg-pre"><?php echo $h($ll_snip); ?></div>
            <?php } ?>
            <p><b>fail2ban</b> - bans addresses that were blocked several times (lines <code>action=block</code> of the security log):</p>
            <div class="sg-pre"><?php echo $h(security_guard_fail2ban_snippet()); ?></div>
        </details>

        <!-- Emergency -->
        <details class="sg-box" id="sg-emergency">
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
            <p>Locked out of the admin pages by "Admin pages only from"? Use 1 or 2, log in, fix the list, then switch back on.
                For a short break the "Pause" button at the top is enough.</p>
        </details>

        <!-- Reset (collapsible) -->
        <details class="sg-box"<?php echo $reset_open ? ' open' : ''; ?>>
            <summary><h3>Reset plugin</h3></summary>
            <p>Deletes everything the plugin stored in <code><?php echo $h(security_guard_base_dir()); ?></code>: settings, security log, counters
                (and the emergency switch file). The default settings apply afterwards and the configurator opens again. ResourceSpace data is not changed. This cannot be undone.</p>
            <form method="post" action="<?php echo $h($self); ?>" id="sg-reset">
                <?php generateFormToken('security_guard'); ?>
                <div class="sg-row">
                    <label>To confirm, type <b>RESET</b> <input type="text" name="reset_confirm" autocomplete="off" spellcheck="false"></label>
                    <button type="submit" name="action" value="reset">Reset plugin</button>
                </div>
            </form>
        </details>
    </div>
    </div>

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
        var off = document.querySelector('#sg-switch button[value=disable]');
        if (off) {
            off.addEventListener('click', function (e) {
                if (!confirm('Turn Security Guard off? No checks run until you switch it on again (for a short break use "Pause").')) { e.preventDefault(); }
            });
        }
        // ---- section status: Recommended / Custom (stronger) / Low, Reset <-> Undo (since 1.07) ----
        var SECTIONS = <?php echo json_encode(security_guard_section_config(), JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT); ?>;
        var form = document.getElementById('sg-settings');
        var ICONS = {
            rec: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M9 16.2 4.8 12l-1.4 1.4L9 19 21 7l-1.4-1.4z"/></svg>',
            custom: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M18 7l-1.41-1.41-6.34 6.34 1.41 1.41L18 7zm4.24-1.41L11.66 16.17 7.48 12l-1.41 1.41L11.66 19l12-12-1.42-1.41zM.41 13.41 6 19l1.41-1.41L1.83 12 .41 13.41z"/></svg>',
            low: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg>'
        };
        function els(name) {
            var l = form.querySelectorAll('[name="' + name + '"]');
            if (!l.length) { l = form.querySelectorAll('[name="' + name + '[]"]'); }
            return Array.prototype.slice.call(l);
        }
        function isGroup(l) { return l.length > 0 && /\[\]$/.test(l[0].name); }
        function lines(t) {
            var out = [];
            String(t).split(/\r\n|\r|\n|,/).forEach(function (x) {
                x = x.replace(/#.*$/, '').trim();
                if (x !== '' && out.indexOf(x) < 0) { out.push(x); }
            });
            return out;
        }
        function read(name) {
            var l = els(name), e = l[0];
            if (!e) { return undefined; }
            if (isGroup(l)) { return l.filter(function (x) { return x.checked; }).map(function (x) { return x.value; }); }
            if (e.type === 'checkbox') { return e.checked; }
            if (e.tagName === 'TEXTAREA') { return lines(e.value); }
            if (e.type === 'number') { return parseInt(e.value, 10) || 0; }
            return e.value;
        }
        function write(name, v) {
            var l = els(name), e = l[0];
            if (!e) { return; }
            if (isGroup(l)) { l.forEach(function (x) { x.checked = (v || []).indexOf(x.value) >= 0; }); }
            else if (e.type === 'checkbox') { e.checked = !!v; }
            else if (e.tagName === 'TEXTAREA') { e.value = (v || []).join('\n'); }
            else { e.value = String(v); }
        }
        function snapshot(name) {
            return els(name).map(function (x) { return x.type === 'checkbox' ? x.checked : x.value; });
        }
        function restore(name, snap) {
            els(name).forEach(function (x, i) { if (x.type === 'checkbox') { x.checked = snap[i]; } else { x.value = snap[i]; } });
        }
        function sign(n) { return n > 0 ? 1 : (n < 0 ? -1 : 0); }
        function diff(a, b) { return a.filter(function (x) { return b.indexOf(x) < 0; }); }
        // -1 below the recommendation, 0 as recommended (or not compared), 1 stronger
        function cmp(f, v) {
            var r = f.rec;
            switch (f.dir) {
                case 'on': return v ? (r ? 0 : 1) : (r ? -1 : 0);
                case 'off': return v ? (r ? 0 : -1) : (r ? 1 : 0);
                case 'higher': return sign(v - r);
                case 'lower': return sign(r - v);
                case 'limit0': return v === r ? 0 : (v === 0 ? -1 : (r === 0 ? 1 : sign(r - v)));
                case 'order': return sign(f.order.indexOf(v) - f.order.indexOf(r));
                case 'list_on': return v.length ? 1 : 0;
                case 'list_off': return v.length ? -1 : 0;
                case 'fewer': return diff(v, r).length ? -1 : (v.length < r.length ? 1 : 0);
                case 'more': return diff(r, v).length ? -1 : (diff(v, r).length ? 1 : 0);
                case 'nonempty': return String(v).trim() === '' ? -1 : 0;
            }
            return 0;
        }
        function optionText(name, value) {
            var o = els(name)[0].querySelector('option[value="' + value + '"]');
            return o ? o.textContent.replace(/ \(recommended\)$/, '') : value;
        }
        function hint(name, f, v) {
            switch (f.dir) {
                case 'on': case 'off': return 'Recommended: ' + (f.rec ? 'on' : 'off');
                case 'order': return 'Recommended: ' + optionText(name, f.rec);
                case 'list_off': return 'Recommended: empty';
                case 'fewer': return 'Not recommended: ' + diff(v, f.rec).join(', ');
                case 'more': return 'Recommended also: ' + diff(f.rec, v).join(', ');
                case 'limit0': return 'Recommended: ' + f.rec + (v === 0 ? ' (0 = no limit)' : '');
            }
            return 'Recommended: ' + f.rec;
        }
        function mark(name, f, v) {
            var l = els(name), targets = [];
            if (isGroup(l)) {
                var bad = f.dir === 'fewer' ? diff(v, f.rec) : diff(f.rec, v);
                l.forEach(function (x) { if (bad.indexOf(x.value) >= 0) { targets.push(x.closest('label') || x.parentElement); } });
            } else {
                targets.push(l[0].closest('label') || l[0].parentElement);
            }
            targets.forEach(function (t) { t.classList.add('sg-low'); });
            if (targets[0]) {
                var sp = document.createElement('span');
                sp.className = 'sg-rec-hint';
                sp.textContent = hint(name, f, v);
                targets[0].appendChild(sp);
            }
        }
        function update(box) {
            var key = box.getAttribute('data-sg-section'), sec = SECTIONS[key];
            if (!sec) { return; }
            box.querySelectorAll('.sg-rec-hint').forEach(function (x) { x.remove(); });
            box.querySelectorAll('.sg-low').forEach(function (x) { x.classList.remove('sg-low'); });
            var names = Object.keys(sec.fields), low = [], strong = [];
            if (sec.master && read(sec.master) === false) { names = [sec.master]; } // section off: only its switch counts
            names.forEach(function (n) {
                var f = sec.fields[n], v = read(n);
                if (v === undefined) { return; }
                var c = cmp(f, v);
                if (c < 0) { low.push(f.label); mark(n, f, v); }
                else if (c > 0) { strong.push(f.label); }
            });
            var kind = low.length ? 'low' : (strong.length ? 'custom' : 'rec');
            var title = kind === 'low' ? 'Below the recommendation: ' + low.join(', ')
                : (kind === 'custom' ? 'Stronger than recommended: ' + strong.join(', ') : 'As recommended');
            // the box itself and the status boxes that belong to it (e.g. Deletion approvals)
            var targets = [box.querySelector('.sg-head > .sg-sec-status')];
            document.querySelectorAll('[data-sg-mirror="' + key + '"] .sg-sec-status').forEach(function (x) { targets.push(x); });
            targets.forEach(function (st) {
                if (!st) { return; }
                st.className = 'sg-sec-status sg-st-' + kind;
                st.innerHTML = ICONS[kind];
                st.appendChild(document.createTextNode(kind === 'low' ? 'Low' : (kind === 'custom' ? 'Custom' : 'Recommended')));
                st.title = (st.closest('.sg-head') ? '' : 'Settings: ') + title;
            });
        }
        if (form) {
            // status of the related settings in the boxes of the status column
            document.querySelectorAll('[data-sg-mirror]').forEach(function (box) {
                var sum = box.querySelector('summary');
                if (sum) {
                    var st = document.createElement('span');
                    st.className = 'sg-sec-status';
                    sum.appendChild(st);
                }
            });
            form.querySelectorAll('[data-sg-section]').forEach(function (box) {
                var key = box.getAttribute('data-sg-section'), sec = SECTIONS[key], h3 = box.querySelector('h3');
                if (!sec || !h3) { return; }
                // "(recommended)" after the recommended choice of the lists
                Object.keys(sec.fields).forEach(function (n) {
                    var f = sec.fields[n], e = els(n)[0];
                    if (f.dir === 'order' && e && e.tagName === 'SELECT') {
                        var o = e.querySelector('option[value="' + f.rec + '"]');
                        if (o) { o.textContent += ' (recommended)'; }
                    }
                });
                var head = document.createElement('div'), st = document.createElement('span'), btn = document.createElement('button');
                head.className = 'sg-head';
                st.className = 'sg-sec-status';
                h3.parentNode.insertBefore(head, h3);
                head.appendChild(h3);
                head.appendChild(st);
                btn.type = 'button';
                btn.className = 'sg-outline';
                btn.textContent = '↺ Reset';
                btn.title = 'Set the recommended values of this section (Save settings to apply them)';
                head.appendChild(btn);
                var snap = null;
                btn.addEventListener('click', function () {
                    var names = Object.keys(sec.fields);
                    if (snap === null) {
                        snap = {};
                        names.forEach(function (n) { snap[n] = snapshot(n); write(n, sec.fields[n].rec); });
                        btn.textContent = '↶ Undo';
                        btn.title = 'Restore the values from before Reset (until the settings are saved)';
                    } else {
                        names.forEach(function (n) { restore(n, snap[n]); });
                        snap = null;
                        btn.textContent = '↺ Reset';
                        btn.title = 'Set the recommended values of this section (Save settings to apply them)';
                    }
                    update(box);
                });
                update(box);
            });
            var onEdit = function (e) {
                var box = e.target.closest && e.target.closest('[data-sg-section]');
                if (box) { update(box); }
            };
            form.addEventListener('change', onEdit);
            form.addEventListener('input', onEdit);
        }

        // a link to a section inside a closed box (e.g. #sg-local-login) opens the box
        function openHash() {
            var id = location.hash.slice(1), el = id ? document.getElementById(id) : null;
            for (var p = el; p; p = p.parentElement) {
                if (p.tagName === 'DETAILS') { p.open = true; }
            }
            if (el) { el.scrollIntoView(); }
        }
        openHash();
        window.addEventListener('hashchange', openHash);
        // remember open / closed boxes of the status column and the advanced settings (per browser; boxes with waiting items stay open)
        document.querySelectorAll('.sg-side > details[id], #sg-advanced').forEach(function (d) {
            var key = 'security_guard_open_' + d.id;
            try {
                var v = localStorage.getItem(key);
                if (v !== null && !location.hash && <?php echo json_encode(!$errors); ?> && !d.querySelector('summary .sg-badge')) { d.open = v === '1'; }
            } catch (e) { /* storage blocked */ }
            d.addEventListener('toggle', function () {
                try { localStorage.setItem(key, d.open ? '1' : '0'); } catch (e) { /* storage blocked */ }
            });
        });
    })();
    </script>
</div>
<?php
include '../../../include/footer.php';
