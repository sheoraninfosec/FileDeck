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
$LOGIN_ENABLED = true;
$PASSWORD_HASH = password_hash('filedeck2025', PASSWORD_DEFAULT);
session_start();
if ($LOGIN_ENABLED && (!isset($_SESSION['_sfm_allowed']) || !$_SESSION['_sfm_allowed'])) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['p']) && password_verify($_POST['p'], $PASSWORD_HASH)) {
        $_SESSION['_sfm_allowed'] = true;
        header('Location: ?');
        exit;
    }
    echo '<!DOCTYPE html><html><head><title>Login - FileDeck</title><style>body{font-family:sans-serif;text-align:center;padding:4em;background:#0f0f0f;color:#eee;}input{padding:.5em;margin:.5em;background:#222;border:1px solid #444;color:#eee;}button{padding:.5em 1em;background:#444;border:none;color:#fff;cursor:pointer;}form{display:inline-block;}</style></head><body><h2>🔒 FileDeck Login</h2><form method="post"><input type="password" name="p" placeholder="Enter password"/><br><button type="submit">Login</button></form></body></html>';
    exit;
}

// Set locale
setlocale(LC_ALL, 'en_US.UTF-8');

// Security headers
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");

// Helpers
function err(int $code, string $msg): void {
    http_response_code($code);
    echo json_encode(['error' => ['code' => $code, 'msg' => $msg]]);
    exit;
}

function asBytes(string $ini_v): int {
    $ini_v = trim($ini_v);
    $s = ['g' => 1 << 30, 'm' => 1 << 20, 'k' => 1 << 10];
    $unit = strtolower(substr($ini_v, -1));
    return intval($ini_v) * ($s[$unit] ?? 1);
}

function rmrf(string $dir): void {
    if (is_dir($dir)) {
        foreach (array_diff(scandir($dir), ['.', '..']) as $file) {
            rmrf("$dir/$file");
        }
        rmdir($dir);
    } elseif (file_exists($dir)) {
        unlink($dir);
    }
}

function is_recursively_deleteable(string $d): bool {
    $stack = [$d];
    while ($dir = array_pop($stack)) {
        if (!is_readable($dir) || !is_writable($dir)) return false;
        foreach (array_diff(scandir($dir), ['.', '..']) as $file) {
            $path = "$dir/$file";
            if (is_dir($path)) $stack[] = $path;
        }
    }
    return true;
}

$MAX_UPLOAD_SIZE = min(asBytes(ini_get('post_max_size')), asBytes(ini_get('upload_max_filesize')));

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
$file = $_REQUEST['file'] ?? '.';
$realPath = realpath($file);
if ($realPath === false || strpos($realPath, __DIR__) !== 0) {
    err(403, "Invalid Path");
}

// Actions
switch ($_REQUEST['do'] ?? null) {
    case 'list':
        if (!is_dir($realPath)) err(412, "Not a Directory");
        $result = [];
        foreach (array_diff(scandir($realPath), ['.', '..']) as $entry) {
            if ($entry === basename(__FILE__)) continue;
            $fullPath = $realPath . DIRECTORY_SEPARATOR . $entry;
            $stat = stat($fullPath);
            $result[] = [
                'mtime' => $stat['mtime'],
                'size' => $stat['size'],
                'name' => basename($fullPath),
                'path' => ltrim(str_replace(__DIR__, '', $fullPath), '/'),
                'is_dir' => is_dir($fullPath),
                'is_deleteable' => (!is_dir($fullPath) && is_writable($realPath)) ||
                                   (is_dir($fullPath) && is_writable($realPath) && is_recursively_deleteable($fullPath)),
                'is_readable' => is_readable($fullPath),
                'is_writable' => is_writable($fullPath),
                'is_executable' => is_executable($fullPath),
                'is_image' => preg_match('/\.(jpe?g|png|gif|webp)$/i', $entry) && is_file($fullPath)
            ];
        }
        echo json_encode(['success' => true, 'is_writable' => is_writable($realPath), 'results' => $result]);
        break;

    case 'delete':
        rmrf($realPath);
        echo json_encode(['success' => true]);
        break;

    case 'mkdir':
        $name = basename($_POST['name'] ?? '');
        if (!$name) err(400, "Invalid folder name");
        @mkdir($realPath . DIRECTORY_SEPARATOR . $name);
        echo json_encode(['success' => true]);
        break;

    case 'upload':
        if (!isset($_FILES['file_data'])) err(400, "No file uploaded");
        $targetPath = $realPath . DIRECTORY_SEPARATOR . basename($_FILES['file_data']['name']);
        move_uploaded_file($_FILES['file_data']['tmp_name'], $targetPath);
        echo json_encode(['success' => true]);
        break;

    case 'download':
        if (!is_file($realPath)) err(404, "File not found");
        $filename = basename($realPath);
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime = finfo_file($finfo, $realPath);
        finfo_close($finfo);

        header('Content-Type: ' . $mime);
        header('Content-Length: ' . filesize($realPath));
        header('Content-Disposition: attachment; filename="' . $filename . '"');
        readfile($realPath);
        break;

    case 'zip':
        $zipFile = __DIR__ . '/filedeck_temp.zip';
        $zip = new ZipArchive();
        if ($zip->open($zipFile, ZipArchive::CREATE | ZipArchive::OVERWRITE)) {
            $path = realpath($realPath);
            if (is_dir($path)) {
                $files = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($path),
                    RecursiveIteratorIterator::LEAVES_ONLY
                );
                foreach ($files as $name => $file) {
                    if (!$file->isDir()) {
                        $filePath = $file->getRealPath();
                        $relativePath = substr($filePath, strlen($path) + 1);
                        $zip->addFile($filePath, $relativePath);
                    }
                }
            } else {
                $zip->addFile($path, basename($path));
            }
            $zip->close();
            header('Content-Type: application/zip');
            header('Content-Disposition: attachment; filename="' . basename($realPath) . '.zip"');
            header('Content-Length: ' . filesize($zipFile));
            readfile($zipFile);
            unlink($zipFile);
        } else {
            err(500, "Zip creation failed");
        }
        break;

    default:
        break;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>FileDeck</title>
<style>
  body { background: #121212; color: #ddd; font-family: sans-serif; padding: 2em; }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 0.5em; border-bottom: 1px solid #333; }
  th { background: #1e1e1e; cursor: pointer; }
  tr:hover { background: #222; }
  a { color: #58a6ff; text-decoration: none; }
  a:hover { text-decoration: underline; }
  img.preview { max-height: 80px; max-width: 120px; display: block; margin-top: 4px; }
</style>
<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
</head>
<body>
<h1>📁 FileDeck</h1>
<form id="mkdir">
  <input type="text" name="name" placeholder="New folder name" required>
  <button type="submit">Create Folder</button>
</form>
<input type="file" id="upload" multiple>
<div id="upload_progress"></div>
<table>
<thead>
<tr><th>Name</th><th>Size</th><th>Modified</th><th>Actions</th></tr>
</thead>
<tbody id="file_list"></tbody>
</table>
<script>
const XSRF = (document.cookie.match('(^|; )_sfm_xsrf=([^;]*)')||[])[2];
function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  let i = Math.floor(Math.log(bytes) / Math.log(1024));
  return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + ['B','KB','MB','GB','TB'][i];
}
function formatDate(ts) {
  return new Date(ts * 1000).toLocaleString();
}
function listFiles() {
  $.get('?do=list', res => {
    if (!res.success) return;
    $('#file_list').empty();
    res.results.forEach(file => {
      let name = file.is_dir
        ? `<a href="?file=${file.path}">${file.name}</a>`
        : file.is_image
          ? `<a href="?do=download&file=${encodeURIComponent(file.path)}">${file.name}</a><br><img class="preview" src="${file.path}" loading="lazy">`
          : `<a href="?do=download&file=${encodeURIComponent(file.path)}">${file.name}</a>`;
      let size = file.is_dir ? '--' : formatSize(file.size);
      let actions = '';
      if (!file.is_dir) actions += `<a href="?do=download&file=${encodeURIComponent(file.path)}">Download</a> `;
      if (!file.is_dir) actions += `<a href="?do=zip&file=${encodeURIComponent(file.path)}">Zip</a> `;
      if (file.is_deleteable) actions += `<a href="#" onclick="deleteFile('${file.path}')">Delete</a>`;
      $('#file_list').append(`<tr><td>${name}</td><td>${size}</td><td>${formatDate(file.mtime)}</td><td>${actions}</td></tr>`);
    });
  });
}
function deleteFile(path) {
  $.post('', {do:'delete', xsrf:XSRF, file:path}, () => listFiles());
}
$('#mkdir').submit(function(e) {
  e.preventDefault();
  $.post('', {do:'mkdir', xsrf:XSRF, file:'.', name: this.name.value}, () => {
    this.reset();
    listFiles();
  });
});
$('#upload').on('change', function() {
  [...this.files].forEach(file => {
    let row = $(`<div>${file.name}<div class="progress"></div></div>`);
    $('#upload_progress').append(row);
    let fd = new FormData();
    fd.append('file_data', file);
    fd.append('xsrf', XSRF);
    fd.append('do', 'upload');
    $.ajax({
      url: '?',
      type: 'POST',
      data: fd,
      processData: false,
      contentType: false,
      xhr: function() {
        let xhr = $.ajaxSettings.xhr();
        xhr.upload.onprogress = e => {
          if (e.lengthComputable) row.find('.progress').css('width', (e.loaded / e.total * 100) + '%');
        };
        return xhr;
      },
      success: () => {
        row.delay(500).fadeOut();
        listFiles();
      }
    });
  });
});
$(listFiles);
</script>
</body>
</html>
