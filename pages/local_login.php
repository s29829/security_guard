<?php
// Security Guard - login page for local accounts (since 1.05).
//
// Shows the login form of ResourceSpace (user name and password) for accounts without single
// sign-on. Opens only with the secret link (?sgk=<key>) or at the own address set on the options page;
// otherwise the answer is "Not found". The form posts to login.php: ResourceSpace checks the password,
// the lockouts and the session; a failed login comes back here with the message.
// ResourceSpace root: <RS_ROOT>/plugins/security_guard/pages or <RS_ROOT>/filestore/plugins/security_guard/pages
$sg_root = is_file(dirname(__FILE__, 4) . '/include/boot.php') ? dirname(__FILE__, 4) : dirname(__FILE__, 5);
include $sg_root . '/include/boot.php';
if (is_file($sg_root . '/include/login_functions.php')) {
    include_once $sg_root . '/include/login_functions.php';
}
require_once dirname(__FILE__, 2) . '/include/guard.php';

$sg_settings = security_guard_settings();
$sg_off      = PHP_SAPI === 'cli' || !empty($GLOBALS['security_guard_disable']) || is_file(security_guard_kill_file());
$sg_denied   = $sg_off ? 'off' : security_guard_ll_access($sg_settings);
if ($sg_denied !== '') {
    if ($sg_denied !== 'off') {
        security_guard_log('log', 'local_login_denied', $sg_denied === 'ip' ? 'address not allowed' : 'no valid key');
    }
    http_response_code(404);
    header('Content-Type: text/plain; charset=UTF-8');
    header('Cache-Control: no-store');
    echo 'Not found';
    exit;
}

// SimpleSAMLphp "site block" would send this page to SSO
security_guard_ll_allow_standard();

header('Cache-Control: no-store');
header('X-Robots-Tag: noindex, nofollow');
header('Referrer-Policy: same-origin');

$sg_url = $_GET['url'] ?? 'index.php';
if (!is_string($sg_url) || $sg_url === '' || !security_guard_safe_redirect($sg_url)) {
    $sg_url = 'index.php';
}
$sg_error = security_guard_ll_read_message($sg_settings);
$sg_token = security_guard_ll_token($sg_settings);

$sg_h = function ($v) {
    return htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8');
};
$sg_lang = function ($key, $fallback) use ($lang) {
    return isset($lang[$key]) && is_string($lang[$key]) ? $lang[$key] : $fallback;
};

// the layout of the ResourceSpace login page (header without menus, background, login box)
$pagename = 'login';
include $sg_root . '/include/header.php';
$sg_background = $sg_root . '/include/login_background.php';
if (is_file($sg_background)) {
    include $sg_background;
} else {
    echo '<div id="login_box">';
}

$sg_logo = '';
if (function_exists('get_header_image')) {
    try {
        $sg_logo = get_header_image(for_login: true);
    } catch (Throwable $e) {
        try {
            $sg_logo = get_header_image();
        } catch (Throwable $e2) {
            $sg_logo = '';
        }
    }
}
$sg_nonce = !empty($CSP_nonce) ? ' nonce="' . $sg_h($CSP_nonce) . '"' : '';
?>
<form id="loginform" class="sg-local-login" method="post" action="<?php echo $sg_h($baseurl_short . 'login.php'); ?>" autocomplete="on">
    <input type="hidden" name="url" value="<?php echo $sg_h($sg_url); ?>">
    <input type="hidden" name="sg_ll" value="<?php echo $sg_h($sg_token); ?>">
    <input type="hidden" name="user_local_timezone" id="sg_local_tz" value="">

    <?php if ($sg_logo !== '') { ?>
        <div id="LoginHeader">
            <img src="<?php echo $sg_h($sg_logo); ?>" class="LoginHeaderImg" alt="<?php echo $sg_h($applicationname ?? ''); ?>">
        </div>
    <?php } ?>

    <h1>Local account login</h1>
    <p>For accounts without single sign-on.</p>

    <?php if ($sg_error !== '') { ?>
        <div class="FormIncorrect" id="LoginError" tabindex="-1"><?php echo $sg_h($sg_error); ?></div>
    <?php } ?>

    <div class="Question">
        <label for="username"><?php echo $sg_h($sg_lang('email', 'E-mail') . ' / ' . $sg_lang('username', 'Username')); ?></label>
        <input type="text" name="username" id="username" class="stdwidth" autocomplete="username" required>
        <div class="clearerleft"></div>
    </div>

    <div class="Question">
        <label for="password"><?php echo $sg_h($sg_lang('password', 'Password')); ?></label>
        <input type="password" name="password" id="password" class="stdwidth" autocomplete="current-password" required>
        <div class="clearerleft"></div>
    </div>

    <?php if (!empty($allow_keep_logged_in)) { ?>
        <div class="Question KeepLoggedIn">
            <label for="remember"><?php echo $sg_h($sg_lang('keepmeloggedin', 'Keep me logged in')); ?></label>
            <input name="remember" id="remember" type="checkbox" value="yes">
            <div class="clearer"> </div>
        </div>
    <?php } ?>

    <div class="QuestionSubmit">
        <input name="Submit" type="submit" value="<?php echo $sg_h($sg_lang('login', 'Log in')); ?>">
    </div>

    <p class="LoginLinks">
        <a href="<?php echo $sg_h($baseurl_short . 'login.php'); ?>">Back to the login page</a>
    </p>
</form>

<script<?php echo $sg_nonce; ?>>
(function () {
    try {
        var tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
        if (tz) { document.getElementById('sg_local_tz').value = tz; }
    } catch (e) {}
    var err = document.getElementById('LoginError');
    var first = document.getElementById(err ? 'password' : 'username');
    if (first) { first.focus(); }
})();
</script>

</div><!-- end of login_box -->
<?php
include $sg_root . '/include/footer.php';
