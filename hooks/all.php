<?php
// Function name format: Hook + <plugin> + <page> + <hook name>
// Runs at the end of include/boot.php on every page, the API and SimpleSAMLphp (when it loads
// ResourceSpace), before the page code and before authentication.
function HookSecurity_guardAllInitialise()
{
    require_once dirname(__FILE__, 2) . '/include/guard.php';
    try {
        security_guard_run();
    } catch (Throwable $e) {
        // a fault in the plugin must never take the site down
        if (function_exists('debug')) {
            debug('security_guard: ' . $e->getMessage());
        }
    }
    return false;
}

// Share policy: script for the share forms (proposed password, fixed expiry). Only when the policy is on.
function HookSecurity_guardAllAdditionalheaderjs()
{
    global $CSP_nonce;
    require_once dirname(__FILE__, 2) . '/include/guard.php';
    try {
        if (!empty($GLOBALS['security_guard_disable']) || is_file(security_guard_kill_file())) {
            return false;
        }
        $s = security_guard_settings();
        if ($s['enabled'] && $s['share_enabled'] && ($s['share_generate_password'] || !$s['share_user_can_change'] || $s['share_password_length'] > 0)) {
            $nonce = !empty($CSP_nonce) ? ' nonce="' . htmlspecialchars($CSP_nonce) . '"' : '';
            echo '<script' . $nonce . '>' . security_guard_share_script($s) . '</script>' . "\n";
        }
    } catch (Throwable $e) {
        // never break a page
    }
    return false;
}
