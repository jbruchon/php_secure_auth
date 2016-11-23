<?php

// Verify the user has a session; otherwise bounce to login page

require_once('lib_auth.php');

$uri = $_SERVER['REQUEST_URI'];
if ($validated != TRUE) $validated = FALSE;
if (array_key_exists("uri", $_REQUEST)) $r_uri = $_REQUEST['uri'];
else $r_uri = "index.php";

// Don't validate a session that does not exist
if (array_key_exists("php_sa_session", $_COOKIE)) {
	$session_key = $_COOKIE['php_sa_session'];
	destroy_expired_sessions();
	$login_id = session_key_to_login_id($session_key);
	if ($login_id !== FALSE && $login_id !== NULL && $login_id >= 0) $validated = TRUE;
}

// Don't let the user loop on login-specific pages forever
if (preg_match("#/login.php#i", $uri) == 1 || preg_match("#/authenticate.php#i", $uri) == 1) {
	if ($validated == TRUE) {
		//print "<br>validated = true<br>\n";
		$r_uri = preg_replace("/login.php.*/i", "index.php", $r_uri);
		$r_uri = preg_replace("/authenticate.php.*/i", "index.php", $r_uri);
		//print "non-loop redirect: $r_uri\n";
		header("Location: $r_uri");
		exit;
	}
	//print "<br>validated = false<br>\n";
} else if ($validated == FALSE) {
	//print "<br>validated = false and not on login<br>\n";
	header("Location: login.php?uri=$uri");
	exit;
}

?>
