-- MySQL dump 10.15  Distrib 10.0.9-MariaDB, for Linux (x86_64)

--
-- Table structure for table `logins`
--

DROP TABLE IF EXISTS `logins`;
CREATE TABLE `logins` (
  `id` smallint(5) NOT NULL AUTO_INCREMENT,
  `active` tinyint(4) NOT NULL COMMENT 'Whether this account is allowed to log in',
  `username` varchar(255) NOT NULL COMMENT 'Login user name',
  `password_hash` varchar(255) NOT NULL COMMENT 'PHP password hash',
  `friendly_name` varchar(255) NOT NULL COMMENT 'Friendly "display name" for this login',
  PRIMARY KEY (`id`),
  UNIQUE KEY `Username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8;


--
-- Table structure for table `sessions`
--

DROP TABLE IF EXISTS `sessions`;
CREATE TABLE `sessions` (
  `login_id` smallint(6) NOT NULL COMMENT 'JOIN to logins.id',
  `lockout` tinyint(4) NOT NULL COMMENT 'Attempt count for lockout',
  `session_key` varchar(64) NOT NULL COMMENT 'Unique session hash (for cookies)',
  `csrf_token` varchar(64) NOT NULL COMMENT 'Token for Cross-Site Request Forgery prevention',
  `network_address` varchar(64) NOT NULL COMMENT 'Usually the IPv4 address',
  `create_time` int(10) unsigned NOT NULL COMMENT 'When the session began',
  `expire_time` int(10) unsigned NOT NULL COMMENT 'When to destroy the session',
  UNIQUE KEY `login_and_address` (`login_id`,`network_address`),
  KEY `expire_time` (`expire_time`),
  KEY `session_key` (`session_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

