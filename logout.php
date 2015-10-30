<?php

// Terminate user session (logout)

require_once('lib_auth.php');

if (array_key_exists("php_sa_session", $_COOKIE)) {
	$session_key = $_COOKIE['php_sa_session'];
	destroy_session($session_key);
}

header("Location: login.php");

?>
