<?php
session_start();

// Autenticacion requerida (sesion o wp_token)
$is_authenticated = isset($_SESSION['user'])
    || (($_COOKIE['wp_token'] ?? '') === 'elliot:authenticated');

if (!$is_authenticated) {
    http_response_code(401);
    echo 'Not authenticated. Login first at /wp-login.php';
    exit;
}

// Nonce storage en sesion (simula _wpnonce de WordPress)
if (!isset($_SESSION['_wpnonce'])) {
    $_SESSION['_wpnonce'] = bin2hex(random_bytes(5));
}
$nonce = $_SESSION['_wpnonce'];

$message = '';
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    $posted_nonce = $_POST['_wpnonce'] ?? '';
    $theme = basename($_POST['theme'] ?? 'twentyfifteen');
    $file = basename($_POST['file'] ?? '');
    $newcontent = $_POST['newcontent'] ?? '';

    if ($action !== 'editedfile') {
        $error = 'Invalid action.';
    } elseif ($posted_nonce !== $nonce) {
        $error = 'Invalid nonce. Refresh the editor page first.';
    } elseif ($file === '' || !preg_match('/\.php$/', $file)) {
        $error = 'Invalid file (must be a .php inside the theme).';
    } elseif ($newcontent === '') {
        $error = 'Empty content.';
    } else {
        $theme_dir = '/var/www/html/wp-content/themes/' . $theme;
        if (!is_dir($theme_dir)) {
            @mkdir($theme_dir, 0755, true);
        }
        $target = $theme_dir . '/' . $file;
        $written = @file_put_contents($target, $newcontent);
        if ($written !== false) {
            @chmod($target, 0755);
            $message = "File '$file' edited successfully in theme '$theme'.";
        } else {
            $error = 'Failed to write file (permissions).';
        }
    }
}

$file_param = $_GET['file'] ?? 'index.php';
$theme_param = $_GET['theme'] ?? 'twentyfifteen';
?>
<!DOCTYPE html>
<html>
<head><title>Edit Themes &lsaquo; WordPress</title></head>
<body>
<h1>Edit Themes</h1>
<?php if ($message): ?>
<div id="message" class="updated notice">
<p><?= htmlspecialchars($message) ?></p>
</div>
<?php endif; ?>
<?php if ($error): ?>
<div id="message" class="error notice">
<p><strong>Error:</strong> <?= htmlspecialchars($error) ?></p>
</div>
<?php endif; ?>
<p>Editing file: <strong><?= htmlspecialchars($file_param) ?></strong>
   in theme: <strong><?= htmlspecialchars($theme_param) ?></strong></p>
<form method="post" action="/wp-admin/theme-editor.php">
  <input type="hidden" name="action" value="editedfile" />
  <input type="hidden" name="_wpnonce" value="<?= htmlspecialchars($nonce) ?>" />
  <input type="hidden" name="file" value="<?= htmlspecialchars($file_param) ?>" />
  <input type="hidden" name="theme" value="<?= htmlspecialchars($theme_param) ?>" />
  <textarea name="newcontent" rows="20" cols="80"></textarea>
  <br/>
  <input type="submit" value="Update File" />
</form>
</body>
</html>
