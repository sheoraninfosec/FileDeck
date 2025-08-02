<?php
/**
 * FileDeck - Simple PHP File Manager (Modernized)
 * Original Author: John Campbell
 * Updated by: Jigesh (2025)
 * License: MIT
 */

// Enable strict types and improve error handling
declare(strict_types=1);
error_reporting(E_ALL);
ini_set('display_errors', '1');

// Optional basic password protection
/*
$PASSWORD_HASH = password_hash('sfm', PASSWORD_DEFAULT);
session_start();
if (!isset($_SESSION['_sfm_allowed']) || !$_SESSION['_sfm_allowed']) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['p']) && password_verify($_POST['p'], $PASSWORD_HASH)) {
        $_SESSION['_sfm_allowed'] = true;
        header('Location: ?');
        exit;
    }
    echo '<html><body><form action=? method=post>PASSWORD:<input type=password name=p /></form></body></html>';
    exit;
}
*/

// Set locale
setlocale(LC_ALL, 'en_US.UTF-8');

// Security headers
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");

// Helpers
function err(int \$code, string \$msg): void {
    http_response_code(\$code);
    echo json_encode(['error' => ['code' => \$code, 'msg' => \$msg]]);
    exit;
}

function asBytes(string \$ini_v): int {
    \$ini_v = trim(\$ini_v);
    \$s = ['g' => 1 << 30, 'm' => 1 << 20, 'k' => 1 << 10];
    \$unit = strtolower(substr(\$ini_v, -1));
    return intval(\$ini_v) * (\$s[\$unit] ?? 1);
}

function rmrf(string \$dir): void {
    if (is_dir(\$dir)) {
        foreach (array_diff(scandir(\$dir), ['.', '..']) as \$file) {
            rmrf("\$dir/\$file");
        }
        rmdir(\$dir);
    } elseif (file_exists(\$dir)) {
        unlink(\$dir);
    }
}

function is_recursively_deleteable(string \$d): bool {
    \$stack = [\$d];
    while (\$dir = array_pop(\$stack)) {
        if (!is_readable(\$dir) || !is_writable(\$dir)) return false;
        foreach (array_diff(scandir(\$dir), ['.', '..']) as \$file) {
            \$path = "\$dir/\$file";
            if (is_dir(\$path)) \$stack[] = \$path;
        }
    }
    return true;
}

\$MAX_UPLOAD_SIZE = min(asBytes(ini_get('post_max_size')), asBytes(ini_get('upload_max_filesize')));

// CSRF protection
if (empty($_COOKIE['_sfm_xsrf'])) {
    setcookie('_sfm_xsrf', bin2hex(random_bytes(16)));
}
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['xsrf']) || $_COOKIE['_sfm_xsrf'] !== $_POST['xsrf']) {
        err(403, "XSRF Failure");
    }
}

// Sanitize input path
\$file = $_REQUEST['file'] ?? '.';
\$realPath = realpath(\$file);
if (\$realPath === false || strpos(\$realPath, __DIR__) !== 0) {
    err(403, "Invalid Path");
}

// Actions
switch (\$_REQUEST['do'] ?? null) {
    case 'list':
        if (!is_dir(\$realPath)) err(412, "Not a Directory");
        \$result = [];
        foreach (array_diff(scandir(\$realPath), ['.', '..']) as \$entry) {
            if (\$entry === basename(__FILE__)) continue;
            \$fullPath = \$realPath . DIRECTORY_SEPARATOR . \$entry;
            \$stat = stat(\$fullPath);
            \$result[] = [
                'mtime' => \$stat['mtime'],
                'size' => \$stat['size'],
                'name' => basename(\$fullPath),
                'path' => ltrim(str_replace(__DIR__, '', \$fullPath), '/'),
                'is_dir' => is_dir(\$fullPath),
                'is_deleteable' => (!is_dir(\$fullPath) && is_writable(\$realPath)) ||
                                   (is_dir(\$fullPath) && is_writable(\$realPath) && is_recursively_deleteable(\$fullPath)),
                'is_readable' => is_readable(\$fullPath),
                'is_writable' => is_writable(\$fullPath),
                'is_executable' => is_executable(\$fullPath),
            ];
        }
        echo json_encode(['success' => true, 'is_writable' => is_writable(\$realPath), 'results' => \$result]);
        break;

    case 'delete':
        rmrf(\$realPath);
        echo json_encode(['success' => true]);
        break;

    case 'mkdir':
        \$name = basename($_POST['name'] ?? '');
        if (!\$name) err(400, "Invalid folder name");
        @mkdir(\$realPath . DIRECTORY_SEPARATOR . \$name);
        echo json_encode(['success' => true]);
        break;

    case 'upload':
        if (!isset($_FILES['file_data'])) err(400, "No file uploaded");
        \$targetPath = \$realPath . DIRECTORY_SEPARATOR . basename($_FILES['file_data']['name']);
        move_uploaded_file($_FILES['file_data']['tmp_name'], \$targetPath);
        echo json_encode(['success' => true]);
        break;

    case 'download':
        if (!is_file(\$realPath)) err(404, "File not found");
        \$filename = basename(\$realPath);
        \$finfo = finfo_open(FILEINFO_MIME_TYPE);
        \$mime = finfo_file(\$finfo, \$realPath);
        finfo_close(\$finfo);

        header('Content-Type: ' . \$mime);
        header('Content-Length: ' . filesize(\$realPath));
        header('Content-Disposition: attachment; filename="' . \$filename . '"');
        readfile(\$realPath);
        break;

    default:
        err(400, "Invalid request");
}
