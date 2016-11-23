<?php

/*
 * User management and authentication functions library
 *
 * This code is part of PHP Secure Auth
 * Copyright (C) 2015-2016 by Jody Bruchon <jody@jodybruchon.com>
 * Distributed under the terms of The MIT License.
 */

// Time benchmark code
$time_start = microtime(TRUE);

require_once('config.php');
require_once('db_connect.php');

// Default lib_auth configuration settings
$auth_settings = array(
// Maximum login attempts before lockout
"cookie_name" => 'php_sa_session',
// Maximum login attempts before lockout
"lockout_max" => 5,
// Default login/lockout session expiration time (seconds)
"session_expire_default" => 120,
// Standard token hash settings
"token_hash_type" => 'sha256',
// This is the base64 length WITHOUT trailing '=' chars
"token_length" => 43,
);


// Set httponly session cookie (secure if using HTTPS)
// $expire_time should be based on time() as it is passed to setcookie()
function set_auth_cookie($session_key, $expire_time = NULL, $domain = NULL)
{
	global $auth_settings;

	if ($expire_time == NULL || !is_numeric($expire_time))
		$expire_time = $auth_settings['session_expire_default'];

	$secure = "";
	if ($_SERVER['HTTPS'] != "" && $_SERVER['HTTPS'] != "off") $secure = TRUE;
	return setcookie($auth_settings['cookie_name'], $session_key,
		$expire_time, NULL, NULL, $secure, TRUE);
}


/* Create a new session
 *
 * $expire_secs: seconds until the session should be killed
 * $login_id: the ID for the user in the logins table
 * $network_address: the network address of the user (usually an IPv4 address)
 * $lock: 1 = lock this session to this network address, 0 = don't lock
 * Returns TRUE on success, FALSE on failure */
function create_session($expire_secs = NULL, $login_id = NULL, $network_address = NULL)
{
	global $dbconn;
	global $auth_settings;

	// Check parameters
	// $network_address is mandatory, fail immediately if not set
	if (is_null($network_address)) $network_address = $_SERVER['REMOTE_ADDR'];
	if (strlen($network_address) < 4) return FALSE;
	// Login ID is mandatory
	if (is_numeric($login_id) === FALSE || $login_id < 0 || $login_id == NULL) return FALSE;
	if (is_null($expire_secs) || $expire_secs < $auth_settings['session_expire_default'])
		$expire_secs = $auth_settings['session_expire_default'];

	$session_key = generate_token();
	$csrf_token = generate_token();

	$create_time = time();
	$expire_time = $create_time + $expire_secs;

	// Add or update the session in the database
	$sql = "INSERT INTO sessions (
			login_id,
			session_key, csrf_token, network_address,
			create_time, expire_time
		) VALUES (
			:li, :sk, :csrf, :na,
			:ct, :et
		)
		ON DUPLICATE KEY UPDATE
		login_id = :li,
		session_key = :sk,
		csrf_token = :csrf,
		network_address = :na,
		create_time = :ct,
		expire_time = :et";
	$stmt = $dbconn->prepare($sql);

	$stmt->bindParam(':li', $login_id, PDO::PARAM_INT);
	$stmt->bindParam(':sk', $session_key, PDO::PARAM_STR);
	$stmt->bindParam(':csrf', $csrf_token, PDO::PARAM_STR);
	$stmt->bindParam(':na', $network_address, PDO::PARAM_STR);
	$stmt->bindParam(':ct', $create_time, PDO::PARAM_INT);
	$stmt->bindParam(':et', $expire_time, PDO::PARAM_INT);

	// Catch any failure to create a session
	if ($stmt->execute() == FALSE) return FALSE;

	set_auth_cookie($session_key, $expire_time, $domain);

	return TRUE;
}


/* Lockout management on an IP address or login ID
 * This is the same as create_session() except it handles lockouts
 *
 * $expire_secs: seconds until the lockout should expire
 * $username: the username for the user account to increment lockout on
 * $network_address: the network address of the user (usually an IPv4 address)
 * Returns TRUE on success, FALSE on failure */
function auth_lockout($expire_secs = NULL, $network_address = NULL, $username = NULL)
{
	global $dbconn;
	global $auth_settings;

	// Check parameters
	// $network_address is mandatory, fail immediately if not set
	if (is_null($network_address)) $network_address = $_SERVER['REMOTE_ADDR'];
	if (strlen($network_address) < 4) return -1;
	if (is_null($expire_secs) || $expire_secs < $auth_settings['session_expire_default'])
		$expire_secs = $auth_settings['session_expire_default'];

	$create_time = time();
	$expire_time = $create_time + $expire_secs;

	$username = trim($username);

	// Add or update the session in the database
	$sql = "INSERT INTO sessions (
			login_id, lockout, network_address, create_time, expire_time
		) VALUES (
			COALESCE((SELECT id FROM logins WHERE username = :un), -1),
			1, :na, :ct, :et
		)
		ON DUPLICATE KEY UPDATE
		login_id = (COALESCE((SELECT id FROM logins WHERE username = :un), -1)),
		lockout = (
		CASE
			WHEN lockout < {$auth_settings['lockout_max']}
				THEN lockout + 1
			ELSE {$auth_settings['lockout_max']}
		END
		),
		session_key = '',
		csrf_token = '',
		network_address = :na,
		create_time = :ct,
		expire_time = :et";
	$stmt = $dbconn->prepare($sql);

	$stmt->bindParam(':un', $username, PDO::PARAM_INT);
	$stmt->bindParam(':na', $na, PDO::PARAM_STR);
	$stmt->bindParam(':ct', $create_time, PDO::PARAM_INT);
	$stmt->bindParam(':et', $expire_time, PDO::PARAM_INT);

	// User blocks and IP-only blocks behave differently
	if ($username != NULL && strlen($username) > 2) {
		// User blocks don't store network addresses
		$na = "";
		//print "sql with params: $username, $na, $create_time, $expire_time<br>\n";
		if ($stmt->execute() == FALSE) return -3;
	}

	// Both types will add an IP block
	$username = NULL;
	$na = $network_address;
	//print "sql with params: $username, $na, $create_time, $expire_time<br>\n";
	if ($stmt->execute() == FALSE) return -4;

	return 1;
}


// Get login ID for session key
// Useful for not loading the entire session configuration unnecessarily
function session_key_to_login_id($session_key)
{
	global $dbconn;
	global $auth_settings;

	if (strlen($session_key) != $auth_settings['token_length']) return FALSE;
	$sql = "SELECT login_id
		FROM sessions WHERE session_key = :sk
		AND expire_time > UNIX_TIMESTAMP()";
	$stmt = $dbconn->prepare($sql);
	$stmt->bindParam(':sk', $session_key, PDO::PARAM_STR);
	if ($stmt->execute() == FALSE) return FALSE;

	$result = $stmt->fetch(PDO::FETCH_ASSOC);
	if ($result == NULL) return FALSE;
	return $result['login_id'];
}


// Get session configuration from database for a particular session key
function get_session_config($session_key)
{
	global $dbconn;
	global $auth_settings;

	if (strlen($session_key) != $auth_settings['token_length']) return FALSE;
	$sql = "SELECT login_id, csrf_token, network_address,
		create_time, expire_time
		FROM sessions WHERE session_key = :sk
		AND lockout = 0";
	$stmt = $dbconn->prepare($sql);
	$stmt->bindParam(':sk', $session_key, PDO::PARAM_STR);
	if ($stmt->execute() == FALSE) return FALSE;

	return $stmt->fetch(PDO::FETCH_ASSOC);
}


// Destroy a specific session associated with a session key
// Also cleans out any expired sessions
function destroy_session($session_key)
{
	global $dbconn;
	global $auth_settings;

	if (strlen($session_key) != $auth_settings['token_length']) return FALSE;

	// Delete the session cookie
	set_auth_cookie("", time() - 3600);

	$sql = "DELETE FROM sessions
		WHERE session_key = :sk
		OR expire_time < UNIX_TIMESTAMP()";
	$stmt = $dbconn->prepare($sql);
	$stmt->bindParam(':sk', $session_key, PDO::PARAM_STR);
	return $stmt->execute();
}


// Destroy account lockout sessions
// This effectively resets the bad login attempt throttling for an account
function destroy_lockout_sessions($username)
{
	global $dbconn;

	$username = trim($username);
	if (strlen($username) < 2) return FALSE;

	$sql = "DELETE s FROM sessions s
		INNER JOIN logins l
		ON s.login_id = l.id
		WHERE l.username = :un
		OR s.expire_time < UNIX_TIMESTAMP()";
	$stmt = $dbconn->prepare($sql);
	$stmt->bindParam(':un', $username);
	return $stmt->execute();
}


// Destroy anonymous sessions (login_id -1) for a specified network address
//
// DO NOT USE THIS OUTSIDE OF ADMINISTRATIVE CONTROLS! Resetting the IP
// lockout counters on successful login allows bypassing lockout security
// by repeatedly logging into an account and then attacking again!
function destroy_anonymous_sessions($network_address = NULL)
{
	global $dbconn;
	global $auth_settings;

	// $network_address is mandatory, fail immediately if not set
	if (is_null($network_address)) $network_address = $_SERVER['REMOTE_ADDR'];
	if (strlen($network_address) < 4) return FALSE;

	$sql = "DELETE FROM sessions
		WHERE (network_address = :na AND login_id = -1)
		OR expire_time < UNIX_TIMESTAMP()";
	$stmt = $dbconn->prepare($sql);
	$stmt->bindParam(':na', $network_address);
	return $stmt->execute();
}


// Destroy all sessions that have expired
function destroy_expired_sessions()
{
	global $dbconn;

	$sql = "DELETE FROM sessions
		WHERE expire_time < UNIX_TIMESTAMP()";
	$stmt = $dbconn->prepare($sql);
	return $stmt->execute();
}


// Generate a unique token (auth cookies, CSRF, etc)
function generate_token()
{
	global $auth_settings;

	$x = mt_rand().microtime().mt_rand().microtime();
	//$x .= (mt_rand(0, 65535) << 11 + mt_rand(0, 65535) >> 9).mt_rand();
	$hash = hash($auth_settings['token_hash_type'], $x, TRUE);
	//print strlen(hash($auth_settings['token_hash_type'], $x))." ".strlen(base64_encode($hash))."<br>";

	return substr(base64_encode($hash), 0, $auth_settings['token_length']);
}


// Add or update a user account and password
// Warning: does not perform password quality or length checks
function update_login_entry($username, $password, $friendlyname = "")
{
	global $dbconn;

	// Ignore extraneous spaces in the user name (thanks, phone keyboards)
	$username = trim($username);

	// Block creating an empty username or password
	if (empty($username) || empty($password)) {
		echo "Error: attempt to use an empty username or password";
		return FALSE;
	}

	$p_hash = password_hash($password, PASSWORD_DEFAULT);

	$sql = "INSERT INTO logins (username, active, password_hash, friendly_name)
		VALUES (:un, 1, :pw, :fn)
		ON DUPLICATE KEY UPDATE
		password_hash = :pw";
	if ($friendlyname != "") $sql .= ",friendly_name = :fn";
	$stmt = $dbconn->prepare($sql);
	$stmt->bindParam(':un', $username, PDO::PARAM_STR);
	$stmt->bindParam(':pw', $p_hash, PDO::PARAM_STR);
	$stmt->bindParam(':fn', $friendlyname, PDO::PARAM_STR);
	return $stmt->execute();
}


// Change user account "active" status
// 0 deactivates the account, anything else activates
function change_user_active($username, $user_active)
{
	global $dbconn;

	$username = trim($username);
	if ($user_active != 0) $user_active = 1;
	$sql = "UPDATE logins SET active = :act WHERE username = :un";
	$stmt = $dbconn->prepare($sql);
	$stmt->bindParam(':un', $username, PDO::PARAM_STR);
	$stmt->bindParam(':act', $user_active, PDO::PARAM_INT);
	return $stmt->execute();
}


// Delete a user account
function delete_login_entry($username)
{
	global $dbconn;

	$username = trim($username);
	$sql = "DELETE FROM logins WHERE username = :un";
	$stmt = $dbconn->prepare($sql);
	$stmt->bindParam(':un', $username, PDO::PARAM_STR);
	return $stmt->execute();
}


// Authenticate a user/password combination
// Returns login ID if authenticated, -1 on password mismatch,
// -2 on username or SELECT query failure
function authenticate_user($username, $password)
{
	global $dbconn;
	global $auth_settings;

	$username = trim($username);
	$sql = "SELECT id,password_hash FROM logins
		WHERE username = :un AND active = 1";
	$stmt = $dbconn->prepare($sql);
	$stmt->bindParam(':un', $username, PDO::PARAM_STR);
	$stmt->execute();

	$result = $stmt->fetch(PDO::FETCH_ASSOC);

	// Assume any failure means "user not found"
	if ($result === FALSE) return -2;

	$login_id = $result['id'];
	$p_hash = $result['password_hash'];

	if (password_verify($password, $p_hash) == TRUE && $login_id >= 0) return $login_id;
	else return -1;
}


// Check for a lockout condition for a user account or network address
function check_lockout($username = NULL, $network_address = NULL)
{
	global $dbconn;
	global $auth_settings;

	$username = trim($username);
	if (is_null($network_address)) $network_address = $_SERVER['REMOTE_ADDR'];
	if (strlen($network_address) < 4) return -1;

	// Handle user-level and network-level lockouts
	if ($username == NULL || strlen($username) > 1) {
		// User-level lockout check
		$sql = "SELECT s.lockout FROM sessions s
			INNER JOIN logins l ON s.login_id = l.id
			WHERE l.username = :un";
		$stmt = $dbconn->prepare($sql);
		$stmt->bindParam(':un', $username, PDO::PARAM_STR);
		$stmt->execute();
		$result = $stmt->fetch(PDO::FETCH_ASSOC);
		$lo = $result['lockout'];
		// Check against the lockout maximum
		if ($lo !== FALSE && $lo >= $auth_settings['lockout_max']) return 1;
	}

	// Network address lockout check
	$sql = "SELECT lockout FROM sessions
		WHERE network_address = :na
		AND login_id = -1";
	$stmt = $dbconn->prepare($sql);
	$stmt->bindParam(':na', $network_address, PDO::PARAM_STR);
	$stmt->execute();
	$result = $stmt->fetch(PDO::FETCH_ASSOC);
	$lo = $result['lockout'];
	if ($lo !== FALSE && $lo >= $auth_settings['lockout_max']) return 2;

	// Anything that makes it this far has passed lockout checks
	return 0;
}


// High-level login function
function do_login($username = NULL, $password = NULL, $force_login = FALSE)
{
	global $auth_settings;

	destroy_expired_sessions();
	$session_key = $_COOKIE[$auth_settings['cookie_name']];
	$username = trim($username);

	// Check for session if forced login not specified
	if ($force_login != TRUE) {
		$login_id = session_key_to_login_id($session_key);
		if ($login_id !== FALSE) {
			//print "Session detected!\n<br>";
			return $login_id;
		}
	} else {
		// Destroy any prior session on a forced login
		destroy_session($session_key);
	}

	if (is_null($username)) $username = $_POST['username'];
	if (is_null($password)) $password = $_POST['password'];

	// Don't allow logins for locked out accounts
	$lo = check_lockout($username);
	if ($lo != 0) {
		auth_lockout(NULL, NULL, $username);
		return -1;
	}

	// Authenticate credentials and take lockout actions as required
	$login_id = authenticate_user($username, $password);

	if ($login_id > 0) {
		create_session(NULL, $login_id);
		return $login_id;
	} else {
		destroy_session($session_key);
		// Good user name, bad password
		if ($login_id == -1) auth_lockout(NULL, NULL, $username);
		// Bad user name
		if ($login_id == -2) auth_lockout();
		return -2;
	}
	return -255;
}

//do_login();

//print "\n<br>". (microtime(TRUE) - $time_start);

?>
