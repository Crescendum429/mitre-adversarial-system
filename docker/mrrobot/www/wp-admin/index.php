<?php
session_start();
if (!isset($_SESSION['user']) && ($_COOKIE['wp_token'] ?? '') !== 'elliot:authenticated') {
    header('Location: /wp-login.php');
    exit;
}
?>
<!DOCTYPE html>
<html>
<head><title>Dashboard &lsaquo; WordPress &mdash; WordPress</title></head>
<body>
<h2>WordPress 4.3.1</h2>
<p>Welcome, elliot. You are logged in as administrator.</p>
<ul>
  <li><a href="/wp-admin/theme-editor.php">Appearance &rsaquo; Theme Editor</a></li>
</ul>
</body>
</html>
