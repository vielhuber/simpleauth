<?php
require_once('functions.php');

/* init tables */
db_query("
	CREATE TABLE `users` (
		`id`			bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
		`username`		varchar(32) NOT NULL,
		`password`		char(40) NOT NULL,
		`salt`			char(32) NOT NULL,
		`email`			varchar(100) NOT NULL,
		PRIMARY KEY (`id`)
	);
");
db_query("
	CREATE TABLE `auth` (
		`id`			bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
		`token`			char(32) NOT NULL,
		`valid_until`	datetime NOT NULL,
		`user_id`		bigint(20) UNSIGNED NOT NULL,
		PRIMARY KEY (`id`),
		FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE RESTRICT ON UPDATE RESTRICT, INDEX `user_id` (`user_id`) USING BTREE
	);
");
 
/* create user */
auth_create_user('david','123','david@vielhuber.de');

