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

// Scripts for pages: share policy (proposed password, fixed expiry) and the login page (local login,
// since 1.05). Only when the feature is on.
function HookSecurity_guardAllAdditionalheaderjs()
{
    global $CSP_nonce, $pagename;
    require_once dirname(__FILE__, 2) . '/include/guard.php';
    try {
        if (!empty($GLOBALS['security_guard_disable']) || is_file(security_guard_kill_file())) {
            return false;
        }
        $s = security_guard_settings();
        if (!$s['enabled']) {
            return false;
        }
        $nonce = !empty($CSP_nonce) ? ' nonce="' . htmlspecialchars($CSP_nonce) . '"' : '';
        if ($s['share_enabled'] && ($s['share_generate_password'] || !$s['share_user_can_change'] || $s['share_password_length'] > 0)) {
            echo '<script' . $nonce . '>' . security_guard_share_script($s) . '</script>' . "\n";
        }
        if ($s['ll_enabled'] && $pagename === 'login' && !security_guard_ll_is_page()) {
            $js = security_guard_ll_login_script($s);
            if ($js !== '') {
                echo '<script' . $nonce . '>' . $js . '</script>' . "\n";
            }
        }
    } catch (Throwable $e) {
        // never break a page
    }
    return false;
}
