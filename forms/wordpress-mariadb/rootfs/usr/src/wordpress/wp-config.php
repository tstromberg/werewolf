<?php
/**
 * wp-config.php for werewolf's wordpress-mariadb form, the wordpress
 * form's but for its database (forms/wordpress-mariadb/README.md).
 *
 * In the image, read-only: what differs per machine comes from the
 * settings leash rendered into /run/svc/php-fpm/site.json, and the salts
 * from the config if it brought them, otherwise from /data, where
 * install.php made them once. The database is MariaDB's `wordpress`, by
 * its socket, as the role php, which MariaDB knows by the process's user
 * (unix_socket): no password exists to steal.
 */
$werewolf_site = json_decode( (string) @file_get_contents( '/run/svc/php-fpm/site.json' ), true );
if ( ! is_array( $werewolf_site ) || empty( $werewolf_site['url'] ) ) {
	http_response_code( 503 );
	exit( "werewolf: no site url in the settings\n" );
}
define( 'WP_HOME', rtrim( $werewolf_site['url'], '/' ) );
define( 'WP_SITEURL', WP_HOME );

// The database: MariaDB, beside it (the mariadb form), by its socket.
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'php' );
define( 'DB_PASSWORD', '' );
define( 'DB_HOST', 'localhost:/run/svc/mariadb/mariadb.sock' );
define( 'DB_CHARSET', 'utf8mb4' );
define( 'DB_COLLATE', '' );
// The installer (install.php, before php-fpm serves) waits for MariaDB,
// which makes its data on the first start, and fails if it never answers:
// WordPress's own error page exits 0, and php-fpm would then serve a site
// not installed, to be claimed by its first visitor once MariaDB answers.
if ( PHP_SAPI === 'cli' ) {
	for ( $werewolf_try = 1; ; $werewolf_try++ ) {
		try {
			mysqli_close( mysqli_connect( 'localhost', DB_USER, DB_PASSWORD, DB_NAME, 0, '/run/svc/mariadb/mariadb.sock' ) );
			break;
		} catch ( mysqli_sql_exception $e ) {
			if ( $werewolf_try >= 120 ) {
				fwrite( STDERR, 'wordpress-install: MariaDB did not answer in 2 minutes: ' . $e->getMessage() . "\n" );
				exit( 1 );
			}
			sleep( 1 );
		}
	}
}
$table_prefix = 'wp_';

// Salts: the config's, or the ones install.php made once on /data.
require file_exists( '/run/svc/php-fpm/salts' ) ? '/run/svc/php-fpm/salts' : '/data/svc/php-fpm/salts.php';

// Plugins, themes and updates come with the image: nothing on the
// machine may change the code, and nothing fetches any.
define( 'DISALLOW_FILE_MODS', true );
define( 'DISALLOW_FILE_EDIT', true );
define( 'AUTOMATIC_UPDATER_DISABLED', true );
define( 'WP_AUTO_UPDATE_CORE', false );

// Nothing leaves the machine but mail (wp-content/mu-plugins/werewolf.php).
// A form whose plugins call an API names the hosts here, and adds
// `connect php tcp/443` to its policy.
define( 'WP_HTTP_BLOCK_EXTERNAL', true );
// define( 'WP_ACCESSIBLE_HOSTS', 'api.example.com' );

// With an https address, the admin and its cookies are HTTPS only.
define( 'FORCE_SSL_ADMIN', str_starts_with( WP_HOME, 'https://' ) );

define( 'WP_MEMORY_LIMIT', '128M' );
define( 'WP_MAX_MEMORY_LIMIT', '256M' );
define( 'WP_DEBUG', false );
define( 'WP_DEBUG_DISPLAY', false );
define( 'WP_DEBUG_LOG', false );
define( 'WP_CACHE', false );
define( 'EMPTY_TRASH_DAYS', 30 );
define( 'WP_POST_REVISIONS', 20 );

if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}
require_once ABSPATH . 'wp-settings.php';
