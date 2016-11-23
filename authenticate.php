<?php

// Authenticate a login and set up the user session

require_once('lib_auth.php');

$username = $_POST['username'];
$password = $_POST['password'];
$r_uri = $_REQUEST['uri'];
if ($username == "" || $password == "") {
	header("Location: login.php?fail=blank");
	exit;
}

// Perform the actual login
$auth = do_login($username, $password);

// If login failed, bail out
if ($auth < 0) {
	$h = "Location: login.php?fail=";
	switch ($auth) {
	case -1:
		// Locked out
		$h .= "lockout";
		break;
	case -2:
		// Invalid credentials
		$h .= "invalid";
		break;
	default:
		// Unspecified error
		$h .= "unknown";
		break;
	}
	if ($r_uri != "") $h .= "&uri=$r_uri";
	header($h);
	exit;
}

// Debugging stuff
/*
echo "<pre>GET\n";
var_dump($_GET);
echo "\nPOST\n";
var_dump($_POST);
echo "\nCOOKIE\n";
var_dump($_COOKIE);
echo "\n\n$auth\n";
 */

$validated = TRUE;
require("validate_session.php");
// Fall through to the index page
header("Location: index.php");

?>
