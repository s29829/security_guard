<?php
// Upload verification (since 1.04): pages/upload_batch.php - every upload of the interface (new
// resources, replacing files, alternative files, uploads through a share). The hook runs when the
// complete file is in the temporary folder, before ResourceSpace processes it.
// Function name format: Hook + <plugin> + <page> + <hook name>
function HookSecurity_guardUpload_batchModify_upload_file($upfilename, $upfilepath)
{
    require_once dirname(__FILE__, 2) . '/include/guard.php';
    try {
        if (!empty($GLOBALS['security_guard_disable']) || is_file(security_guard_kill_file())) {
            return false;
        }
        $s = security_guard_settings();
        if (!$s['enabled'] || $s['up_mode'] === 'off' || !is_string($upfilepath) || !is_file($upfilepath)) {
            return false;
        }
        require_once dirname(__FILE__, 2) . '/include/upload.php';
        $user = array('ref' => (int) ($GLOBALS['userref'] ?? 0), 'username' => (string) ($GLOBALS['username'] ?? ''));
        $context = 'upload' . ((string) ($_REQUEST['k'] ?? '') !== '' ? ' through a share' : '')
            . ((int) ($_REQUEST['replace_resource'] ?? 0) > 0 ? ', replace resource ' . (int) $_REQUEST['replace_resource'] : '')
            . ((int) ($_REQUEST['alternative'] ?? 0) > 0 ? ', alternative file of ' . (int) $_REQUEST['alternative'] : '');
        $r = security_guard_upload_check($s, $upfilepath, (string) $upfilename, $user, $context);
    } catch (Throwable $e) {
        return false; // never break the upload because of the plugin
    }
    if (!$r['ok']) {
        if (is_file($upfilepath)) {
            unlink($upfilepath);
        }
        // same answer format as the checks of upload_batch.php
        die(json_encode(array('status' => false, 'message' => $r['message'], 'error' => 105)));
    }
    return false;
}
