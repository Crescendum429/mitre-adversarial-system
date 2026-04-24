<?php
session_start();

$error = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $log = $_POST['log'] ?? '';
    $pwd = $_POST['pwd'] ?? '';
    if ($log === '__USERNAME__' && $pwd === '__PASSWORD_PLACEHOLDER__') {
        $_SESSION['user'] = '__USERNAME__';
        setcookie('wp_token', 'elliot:authenticated', time() + 3600, '/');
        header('Location: /wp-admin/');
        exit;
    }
    $error = '<div id="login_error"><strong>ERROR</strong>: The password you entered for the username <strong>' . htmlspecialchars($log) . '</strong> is incorrect.</div>';
}
?>
<!DOCTYPE html>
<html>
<head><title>Log In &lsaquo; WordPress &mdash; WordPress</title></head>
<body class="login">
<?php echo $error; ?>
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
  <p><label>Username<br />
    <input type="text" name="log" id="user_login" value="" size="20" /></label>
  </p>
  <p><label>Password<br />
    <input type="password" name="pwd" id="user_pass" value="" size="20" /></label>
  </p>
  <p class="submit">
    <input type="submit" name="wp-submit" id="wp-submit" value="Log In" />
  </p>
  <input type="hidden" name="redirect_to" value="/wp-admin/" />
</form>
</body>
</html>
