<?php

/*
 * Login page
 *
 * This code is part of PHP Secure Auth
 * Copyright (C) 2015 by Jody Bruchon <jody@jodybruchon.com>
 * Distributed under the terms of The MIT License.
 */

include_once("header.php");

// After login, redirect to where the user wanted to go
if (array_key_exists("uri", $_REQUEST)) {
	if (preg_match("/login.php/i", $_REQUEST['uri']) == 0) $uri = $_REQUEST['uri'];
} else $uri = "index.php";

?>

<!DOCTYPE html>
<html><body>

<?php
if ($_GET['fail'] == "lockout") {
	print "<p>Too many login attempts. Please try again later.</p>\n";
	print "<p><a href=\"login.php\">Click here to retry.</a></p>\n";
	exit;
}
?>

<form name="login" action="authenticate.php" method="post">
	<p>
		<label for="username">Username</label>
		<input id="username" name="username" type="text"><br>
	</p>
	<p>
		<label for="password">Password</label>
		<input id="password" name="password" type="password">
		<input name="uri" value="<?php echo "$uri"; ?>" type="hidden">
		<input name="submit" type="submit" value="Login">
	</p>
</form>

<?php
if (isset($_GET['fail'])) {
	switch ($_GET['fail']) {
	case "blank":
		print "<p>Username and password must not be blank.</p>\n";
		break;
	case "invalid":
		print "<p>Incorrect user name or password.</p>\n";
		break;
	default:
		print "<p>Unspecified login failure occurred.</p>\n";
		break;
	}
}
?>

</body></html>
