<?php
// Security Guard - upload verification (since 1.04). Loaded only for requests that upload files.
//
// 1. Allowed file types: groups (images, video, documents, audio) plus own extensions.
// 2. Advanced checks: the content must match the extension (file signatures), and the file must not
//    contain executable code, scripts, macros, active PDF/SVG content, private keys or the EICAR test
//    string; optional virus scan with ClamAV.
// 3. Doubtful files go to the quarantine (<filestore>/security_guard/data_<key>/quarantine) and the
//    upload is refused. An administrator (another one with "four eyes") approves the file - by its
//    SHA-256 checksum - and the user uploads it again within the set time.
require_once __DIR__ . '/guard.php';

// Groups of allowed extensions
function security_guard_upload_groups()
{
    return array(
        'images'    => array('label' => 'Images', 'ext' => array('jpg', 'jpeg', 'jpe', 'png', 'gif', 'tif', 'tiff', 'bmp', 'webp', 'heic', 'heif', 'avif',
            'psd', 'psb', 'svg', 'eps', 'ai', 'cr2', 'cr3', 'nef', 'nrw', 'arw', 'dng', 'orf', 'raf', 'rw2', 'pef', 'srw')),
        'video'     => array('label' => 'Video', 'ext' => array('mp4', 'm4v', 'mov', 'qt', 'avi', 'mkv', 'webm', 'wmv', 'mpg', 'mpeg', 'mts', 'm2ts', '3gp', 'mxf')),
        'documents' => array('label' => 'Documents', 'ext' => array('pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'odp', 'rtf', 'txt', 'csv', 'indd', 'idml')),
        'audio'     => array('label' => 'Audio', 'ext' => array('mp3', 'wav', 'aac', 'm4a', 'flac', 'ogg', 'aif', 'aiff')),
    );
}

// Allowed extensions by the settings (never the ones ResourceSpace bans)
function security_guard_upload_allowed(array $s)
{
    $ext = array();
    foreach (security_guard_upload_groups() as $key => $g) {
        if (in_array($key, $s['up_groups'], true)) {
            $ext = array_merge($ext, $g['ext']);
        }
    }
    $ext = array_merge($ext, array_map('strtolower', $s['up_extra_ext']));
    $ext = array_diff($ext, array_map('strtolower', $s['up_block_ext']), array_map('strtolower', (array) ($GLOBALS['banned_extensions'] ?? array())));
    return array_values(array_unique(array_filter($ext, 'strlen')));
}

function security_guard_upload_ext($name)
{
    $ext = strtolower((string) pathinfo((string) $name, PATHINFO_EXTENSION));
    return preg_match('/^[a-z0-9]{1,10}$/', $ext) ? $ext : '';
}

// Does the beginning of the file match the extension? true / false / null (no signature known)
function security_guard_upload_signature($ext, $h)
{
    $at = function ($off, $sig) use ($h) {
        return substr($h, $off, strlen($sig)) === $sig;
    };
    $tiff = $at(0, "II*\0") || $at(0, "MM\0*");
    $ftyp = $at(4, 'ftyp');
    switch ($ext) {
        case 'jpg': case 'jpeg': case 'jpe':
            return $at(0, "\xFF\xD8\xFF");
        case 'png':
            return $at(0, "\x89PNG\r\n\x1A\n");
        case 'gif':
            return $at(0, 'GIF87a') || $at(0, 'GIF89a');
        case 'tif': case 'tiff': case 'dng': case 'nef': case 'nrw': case 'arw': case 'pef': case 'srw': case 'cr2':
            return $tiff;
        case 'orf':
            return $tiff || $at(0, 'IIRO') || $at(0, 'IIRS') || $at(0, 'MMOR');
        case 'rw2':
            return $tiff || $at(0, "IIU\0");
        case 'raf':
            return $at(0, 'FUJIFILMCCD-RAW');
        case 'bmp':
            return $at(0, 'BM');
        case 'webp':
            return $at(0, 'RIFF') && $at(8, 'WEBP');
        case 'heic': case 'heif': case 'avif': case 'cr3': case 'mp4': case 'm4v': case '3gp': case 'm4a':
            return $ftyp;
        case 'mov': case 'qt':
            return $ftyp || $at(4, 'moov') || $at(4, 'mdat') || $at(4, 'wide') || $at(4, 'free') || $at(4, 'skip') || $at(4, 'pnot');
        case 'psd': case 'psb':
            return $at(0, '8BPS');
        case 'pdf':
            return strpos(substr($h, 0, 1024), '%PDF-') !== false;
        case 'ai':
            return strpos(substr($h, 0, 1024), '%PDF-') !== false || $at(0, '%!PS');
        case 'eps':
            return $at(0, '%!PS') || $at(0, "\xC5\xD0\xD3\xC6");
        case 'svg':
            return strpos($h, "\0") === false && stripos($h, '<svg') !== false;
        case 'doc': case 'xls': case 'ppt':
            return $at(0, "\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1");
        case 'docx': case 'xlsx': case 'pptx': case 'odt': case 'ods': case 'odp': case 'idml':
            return $at(0, "PK\x03\x04");
        case 'rtf':
            return $at(0, '{\\rtf');
        case 'avi':
            return $at(0, 'RIFF') && $at(8, 'AVI ');
        case 'wav':
            return $at(0, 'RIFF') && $at(8, 'WAVE');
        case 'mkv': case 'webm':
            return $at(0, "\x1A\x45\xDF\xA3");
        case 'wmv':
            return $at(0, "\x30\x26\xB2\x75\x8E\x66\xCF\x11");
        case 'mpg': case 'mpeg':
            return $at(0, "\x00\x00\x01\xBA") || $at(0, "\x00\x00\x01\xB3");
        case 'mts': case 'm2ts':
            return $at(0, "\x47") || $at(4, "\x47");
        case 'mxf':
            return $at(0, "\x06\x0E\x2B\x34");
        case 'indd':
            return $at(0, "\x06\x06\xED\xF5\xD8\x1D\x46\xE5\xBD\x31\xEF\xE7\xFE\x74\xB7\x1D");
        case 'mp3':
            return $at(0, 'ID3') || (strlen($h) > 1 && ord($h[0]) === 0xFF && (ord($h[1]) & 0xE0) === 0xE0);
        case 'aac':
            return $at(0, 'ID3') || (strlen($h) > 1 && ord($h[0]) === 0xFF && (ord($h[1]) & 0xF6) === 0xF0);
        case 'flac':
            return $at(0, 'fLaC');
        case 'ogg':
            return $at(0, 'OggS');
        case 'aif': case 'aiff':
            return $at(0, 'FORM') && ($at(8, 'AIFF') || $at(8, 'AIFC'));
        case 'txt': case 'csv':
            return strpos($h, "\0") === false || $at(0, "\xFF\xFE") || $at(0, "\xFE\xFF"); // UTF-16 text has zero bytes
    }
    return null;
}

// What the file looks like (for the message)
function security_guard_upload_detect($h)
{
    $map = array(
        "\x7FELF" => 'a Linux program', "\xFE\xED\xFA\xCE" => 'a macOS program', "\xFE\xED\xFA\xCF" => 'a macOS program',
        "\xCF\xFA\xED\xFE" => 'a macOS program', "\xCE\xFA\xED\xFE" => 'a macOS program', "\xCA\xFE\xBA\xBE" => 'a Java class / macOS program',
        "#!/" => 'a script', "PK\x03\x04" => 'a ZIP archive', "Rar!" => 'a RAR archive', "7z\xBC\xAF" => 'a 7-Zip archive', "\x1F\x8B" => 'a GZIP archive',
        '%PDF' => 'a PDF document', "\xFF\xD8\xFF" => 'a JPEG image', "\x89PNG" => 'a PNG image', 'GIF8' => 'a GIF image',
        "\xD0\xCF\x11\xE0" => 'an Office 97-2003 document',
    );
    if (strncmp($h, 'MZ', 2) === 0 && (strpos(substr($h, 0, 4096), "PE\0\0") !== false || stripos(substr($h, 0, 512), 'program cannot be run') !== false)) {
        return 'a Windows program';
    }
    foreach ($map as $sig => $label) {
        if (strncmp($h, $sig, strlen($sig)) === 0) {
            return $label;
        }
    }
    $start = strtolower(ltrim(substr($h, 0, 200)));
    if (strpos($start, '<?php') === 0) {
        return 'a PHP script';
    }
    if (strpos($start, '<!doctype html') === 0 || strpos($start, '<html') === 0) {
        return 'an HTML page';
    }
    return '';
}

// Patterns searched in the content: name => [regex, types it applies to ('*' = all)]
function security_guard_upload_patterns()
{
    return array(
        'PHP code'                        => array('/<\?php[\s(]|<\?=\s*\$/i', '*'),
        'HTML / JavaScript code'          => array('/<(script|iframe)[\s>]|<html[\s>]/i', 'binary'),
        'active content in SVG'           => array('/<script[\s>]|\son[a-z]+\s*=|javascript\s*:|<foreignObject[\s>]|<!ENTITY/i', array('svg')),
        'active content in PDF'           => array('#/(JavaScript|JS|Launch|EmbeddedFile|RichMedia)[\s/<(\[]#', array('pdf', 'ai')),
        'encrypted PDF (cannot be checked)' => array('#/Encrypt[\s/<]#', array('pdf', 'ai')),
        'macros (VBA)'                    => array('/vbaProject\.bin|_\x00V\x00B\x00A\x00_\x00P\x00R\x00O\x00J\x00E\x00C\x00T/', array('doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx')),
        'macros (OpenDocument)'           => array('#Basic/[^/\x00]+/[^/\x00]+\.xml|Scripts/(javascript|python|beanshell)/#i', array('odt', 'ods', 'odp')),
        'encrypted document (cannot be checked)' => array('/E\x00n\x00c\x00r\x00y\x00p\x00t\x00e\x00d\x00P\x00a\x00c\x00k\x00a\x00g\x00e/', array('doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx')),
        'private key'                     => array('/-----BEGIN (RSA |DSA |EC |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY( BLOCK)?-----/', '*'),
        'cloud access key'                => array('/\b(AKIA|ASIA)[0-9A-Z]{16}\b/', array('txt', 'csv', 'rtf', 'svg')),
        'EICAR test file'                 => array('/X5O!P%@AP\[4\\\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*/', '*'),
    );
}

// Reasons why a file is doubtful ([] = fine)
function security_guard_upload_inspect(array $s, $path, $name, $ext)
{
    $reasons = array();
    // file name: control characters, right-to-left override, hidden dangerous extension, sensitive files
    if (preg_match('/[\x00-\x1F\x7F]|\xE2\x80[\xAA-\xAE]|\xE2\x81[\xA6-\xA9]/', $name)) {
        $reasons[] = 'control or right-to-left characters in the file name';
    }
    if (preg_match('/\.(php\d?|phtml|phar|asp|aspx|jsp|cgi|pl|py|sh|bash|exe|dll|bat|cmd|com|scr|ps1|vbs|vbe|wsf|js|jar|hta|msi|lnk|htaccess)\./i', $name)) {
        $reasons[] = 'hidden program extension in the file name';
    }
    if (preg_match('/(^|[\/\\\\])(id_rsa|id_dsa|id_ecdsa|id_ed25519|\.env|\.htpasswd|wp-config\.php|shadow)$|\.(pem|key|p12|pfx|kdbx|jks|keystore|ppk|ovpn)$/i', $name)) {
        $reasons[] = 'sensitive file (keys / passwords)';
    }
    $size = is_file($path) ? (int) filesize($path) : 0;
    $fh = $size > 0 ? fopen($path, 'rb') : false;
    if ($fh === false) {
        return $reasons;
    }
    $head = (string) fread($fh, 65536);

    // content against the extension
    $sig = security_guard_upload_signature($ext, $head);
    $looks = security_guard_upload_detect($head);
    if ($sig === false) {
        $reasons[] = 'content does not match .' . $ext . ($looks !== '' ? ' (looks like ' . $looks . ')' : '');
    }
    // programs and scripts whatever the extension
    if ($looks !== '' && preg_match('/program|script|Java class/', $looks) && !($ext === 'txt' && strpos($looks, 'script') !== false)) {
        $reasons[] = 'executable content (' . $looks . ')';
    }
    if ($sig !== false && strncmp($head, "PK\x03\x04", 4) === 0 && (ord($head[6] ?? "\0") & 1) === 1) {
        $reasons[] = 'encrypted archive (cannot be checked)';
    }

    // content patterns: documents completely (up to the limit), media files at the beginning and the end
    $full = in_array($ext, array('pdf', 'ai', 'eps', 'svg', 'txt', 'csv', 'rtf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'odp', 'idml'), true);
    $limit = max(1, (int) $s['up_scan_mb']) * 1048576;
    $chunks = array($head);
    if ($full) {
        fseek($fh, strlen($head));
        $read = strlen($head);
        $prev = substr($head, -256);
        while (!feof($fh) && $read < $limit) {
            $part = (string) fread($fh, 1048576);
            if ($part === '') {
                break;
            }
            $read += strlen($part);
            $chunks[] = $prev . $part;
            $prev = substr($part, -256);
        }
    } elseif ($size > 65536) {
        fseek($fh, max(65536, $size - 65536));
        $chunks[] = (string) fread($fh, 65536);
    }
    fclose($fh);
    $text_like = in_array($ext, array('svg', 'txt', 'csv', 'rtf'), true);
    foreach (security_guard_upload_patterns() as $label => $p) {
        $types = $p[1];
        if ($types === 'binary' ? $text_like : ($types !== '*' && !in_array($ext, $types, true))) {
            continue;
        }
        foreach ($chunks as $c) {
            if (preg_match($p[0], $c)) {
                $reasons[] = $label;
                break;
            }
        }
    }

    // virus scan
    if ($s['up_clamav']) {
        $virus = security_guard_upload_clamav($s, $path);
        if ($virus !== '') {
            $reasons[] = $virus;
        }
    }
    return array_values(array_unique($reasons));
}

// ClamAV: '' = clean or not available, otherwise the reason
function security_guard_upload_clamav(array $s, $path)
{
    if (!function_exists('proc_open')) {
        security_guard_log('log', 'upload_scan_unavailable', 'proc_open is disabled');
        return '';
    }
    $cmd = preg_split('/\s+/', trim((string) $s['up_clamav_cmd']));
    if (!$cmd || $cmd[0] === '') {
        return '';
    }
    $cmd[] = $path;
    $proc = proc_open($cmd, array(1 => array('pipe', 'w'), 2 => array('pipe', 'w')), $pipes);
    if (!is_resource($proc)) {
        security_guard_log('log', 'upload_scan_unavailable', 'cannot start ' . $cmd[0]);
        return '';
    }
    $out = (string) stream_get_contents($pipes[1]);
    $err = (string) stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $code = proc_close($proc);
    if ($code === 1) {
        return 'virus: ' . (preg_match('/:\s*(.+?)\s+FOUND/', $out, $m) ? $m[1] : 'found by ClamAV');
    }
    if ($code !== 0) {
        security_guard_log('log', 'upload_scan_unavailable', 'exit code ' . $code . ': ' . trim($err !== '' ? $err : $out));
    }
    return '';
}

// ---- Quarantine --------------------------------------------------------------------------------

function security_guard_upload_file()
{
    return security_guard_data_dir() . '/upload.json';
}

function security_guard_quarantine_dir()
{
    return security_guard_data_dir() . '/quarantine';
}

function security_guard_upload_update(callable $fn)
{
    return security_guard_json_update(security_guard_upload_file(), array('next' => 1, 'items' => array(), 'approved' => array()), $fn);
}

// Is this file (checksum) approved for the user?
function security_guard_upload_approved($sha, $user)
{
    if (!is_file(security_guard_upload_file())) {
        return false;
    }
    $data = json_decode((string) file_get_contents(security_guard_upload_file()), true);
    $a = $data['approved'][$sha] ?? null;
    return is_array($a) && (int) $a['until'] >= time() && ((int) $a['user'] === 0 || (int) $a['user'] === (int) $user);
}

// Moves the file to the quarantine and stores the request; returns [id, new]
function security_guard_upload_quarantine(array $s, $path, $name, $sha, array $reasons, ?array $user, $context, $uploaded)
{
    $dir = security_guard_quarantine_dir();
    if (!security_guard_mkdir($dir)) {
        return array(0, false);
    }
    $ip = security_guard_client_ip($s);
    $size = is_file($path) ? (int) filesize($path) : 0;
    return security_guard_upload_update(function (array &$d) use ($s, $path, $name, $sha, $reasons, $user, $context, $uploaded, $dir, $ip, $size) {
        // remove expired files
        $keep = time() - max(1, (int) $s['up_keep_days']) * 86400;
        foreach ($d['items'] as $i => $it) {
            if ((int) $it['time'] < $keep && $it['file'] !== '' && is_file($dir . '/' . $it['file'])) {
                unlink($dir . '/' . $it['file']);
                $d['items'][$i]['file'] = '';
                if ($it['status'] === 'pending') {
                    $d['items'][$i]['status'] = 'expired';
                }
            }
        }
        foreach ($d['approved'] as $k => $a) {
            if ((int) $a['until'] < time()) {
                unset($d['approved'][$k]);
            }
        }
        // the same file of the same user is still waiting
        foreach ($d['items'] as $it) {
            if ($it['status'] === 'pending' && $it['sha256'] === $sha && (int) $it['user'] === (int) ($user['ref'] ?? 0)) {
                return array((int) $it['id'], false);
            }
        }
        $id = (int) $d['next'];
        $d['next'] = $id + 1;
        $file = $id . '_' . substr(bin2hex(random_bytes(8)), 0, 12) . '.quarantine';
        $ok = $uploaded ? move_uploaded_file($path, $dir . '/' . $file) : (rename($path, $dir . '/' . $file) || (copy($path, $dir . '/' . $file) && unlink($path)));
        $d['items'][] = array('id' => $id, 'time' => time(), 'user' => (int) ($user['ref'] ?? 0), 'username' => (string) ($user['username'] ?? ''),
            'name' => (string) $name, 'size' => $size, 'sha256' => $sha, 'reasons' => $reasons, 'context' => $context, 'ip' => $ip,
            'file' => $ok ? $file : '', 'status' => 'pending', 'by' => '', 'decided' => 0);
        $d['items'] = array_slice($d['items'], -300);
        return array($id, true);
    }) ?? array(0, false);
}

// Checks one uploaded file; returns ['ok' => bool, 'message' => text for the user]
// $uploaded = the file came through $_FILES (move_uploaded_file), $exempt_ext = no file type check
function security_guard_upload_check(array $s, $path, $name, ?array $user, $context, $uploaded = false, $exempt_ext = false)
{
    $name = (string) $name;
    $ext = security_guard_upload_ext($name);
    $enforce = $s['up_mode'] === 'enforce';
    $who = $user ? $user['username'] : 'unknown user';

    if (!$exempt_ext && ($ext === '' || !in_array($ext, security_guard_upload_allowed($s), true))) {
        security_guard_log($enforce ? 'block' : 'log', 'upload_extension', $name . ' (' . $who . ', ' . $context . ')');
        if ($enforce) {
            return array('ok' => false, 'message' => 'The file type' . ($ext !== '' ? ' .' . $ext : '') . ' of "' . $name . '" is not allowed (Security Guard).');
        }
    }
    if (!$s['up_inspect'] && !$s['up_clamav']) {
        return array('ok' => true, 'message' => '');
    }
    $reasons = $s['up_inspect'] ? security_guard_upload_inspect($s, $path, $name, $ext) : array();
    if (!$s['up_inspect'] && $s['up_clamav']) {
        $v = security_guard_upload_clamav($s, $path);
        $reasons = $v !== '' ? array($v) : array();
    }
    if (!$reasons) {
        return array('ok' => true, 'message' => '');
    }
    $detail = $name . ': ' . implode('; ', $reasons) . ' (' . $who . ', ' . $context . ')';
    $sha = is_file($path) ? (string) hash_file('sha256', $path) : '';
    if ($sha !== '' && security_guard_upload_approved($sha, (int) ($user['ref'] ?? 0))) {
        security_guard_log('allow', 'upload_approved_file', $detail);
        return array('ok' => true, 'message' => '');
    }
    if (!$enforce) {
        security_guard_log('log', 'upload_suspicious', $detail);
        return array('ok' => true, 'message' => '');
    }
    list($id, $new) = security_guard_upload_quarantine($s, $path, $name, $sha, $reasons, $user, $context, $uploaded);
    security_guard_log('block', 'upload_quarantine', $detail . ', quarantine #' . $id);
    if ($new) {
        $text = 'Security Guard: file "' . $name . '" from ' . $who . ' was put in the quarantine (' . implode('; ', $reasons) . '). Request #' . $id . '.';
        $extra = ($s['notify_enabled'] && in_array('upload', $s['notify_events'], true)) ? array_keys(security_guard_notify_recipients($s)) : array();
        if ($s['up_notify_admins'] || $extra) {
            security_guard_notify_admins($text, $extra, $s['up_notify_admins']);
        }
    }
    return array('ok' => false, 'message' => 'The file "' . $name . '" was put in the quarantine: ' . implode('; ', $reasons) . '. '
        . 'It needs the approval of ' . ($s['up_four_eyes'] ? 'another administrator' : 'an administrator') . ' (Security Guard request #' . $id . '); '
        . 'after the approval upload it again.');
}

// Requests that send files: tus upload start (file name only) and $_FILES (API upload_multipart, forms)
function security_guard_upload_request(array $s, $path, $is_api)
{
    if (security_guard_path_match($path, $s['up_skip_paths'])) {
        return;
    }
    $enforce = $s['up_mode'] === 'enforce';

    // tus: the first request announces the file name - refuse types that are not allowed before the transfer
    if ($path === 'pages/upload_batch.php' && isset($_SERVER['HTTP_UPLOAD_METADATA'])) {
        foreach (explode(',', (string) $_SERVER['HTTP_UPLOAD_METADATA']) as $pair) {
            $kv = explode(' ', trim($pair), 2);
            if (in_array($kv[0], array('filename', 'name'), true) && isset($kv[1])) {
                $name = (string) base64_decode($kv[1], true);
                $ext = security_guard_upload_ext($name);
                if ($ext === '' || !in_array($ext, security_guard_upload_allowed($s), true)) {
                    if ($enforce) {
                        security_guard_deny(403, 'upload_extension', $name . ' (upload start)', true, 'The file type of "' . $name . '" is not allowed (Security Guard).');
                    }
                    security_guard_log('log', 'upload_extension', $name . ' (upload start)');
                }
                break;
            }
        }
    }

    if (!$_FILES) {
        return;
    }
    $user = null;
    $api_user = null;
    if ($is_api && ($_POST['authmode'] ?? $_GET['authmode'] ?? '') !== 'native') {
        $api_user = is_string($_POST['user'] ?? $_GET['user'] ?? null) ? ($_POST['user'] ?? $_GET['user']) : '';
    }
    $user = security_guard_current_user($api_user);
    $exempt = security_guard_path_match($path, $s['admin_paths']); // administrators import CSV, XML ... on admin pages
    foreach ($_FILES as $field => $f) {
        $names = (array) ($f['name'] ?? array());
        $tmps  = (array) ($f['tmp_name'] ?? array());
        $errs  = (array) ($f['error'] ?? array());
        array_walk_recursive($tmps, function ($tmp, $k) use ($names, $errs, $s, $path, $is_api, $user, $exempt, $field) {
            $name = is_array($names) ? (array_key_exists($k, $names) && !is_array($names[$k]) ? $names[$k] : basename((string) $tmp)) : $names;
            $err = array_key_exists($k, $errs) && !is_array($errs[$k]) ? (int) $errs[$k] : 0;
            if ($err !== UPLOAD_ERR_OK || !is_string($tmp) || $tmp === '' || !is_uploaded_file($tmp)) {
                return;
            }
            $r = security_guard_upload_check($s, $tmp, (string) $name, $user, ($is_api ? 'API' : $path) . ' / ' . $field, true, $exempt);
            if (!$r['ok']) {
                if (is_file($tmp)) {
                    unlink($tmp);
                }
                security_guard_deny(403, 'upload_rejected', (string) $name, $is_api, $r['message']);
            }
        });
    }
}
