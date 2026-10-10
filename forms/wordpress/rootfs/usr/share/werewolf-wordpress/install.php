<?php
/**
 * install.php: WordPress set up from the machine's settings before it
 * serves, so that no first visitor claims it (the wordpress form,
 * docs/wordpress.md).
 *
 * leash runs it before each start of php-fpm, as the php user, inside its
 * leash (etc/sv/php-fpm/service). It reads the settings leash rendered
 * (/run/svc/php-fpm/site.json) and the admin's bcrypt password hash the
 * config brought; makes the uploads and database directories on /data,
 * and the salts once, unless the config brought them; and, if the site
 * is not installed, installs it: title, admin and email from the
 * settings, the admin's password the hash given. A site already installed
 * is left as it is. Any fault exits 1, with one line saying why, and
 * php-fpm stays down.
 */

const SITE  = '/run/svc/php-fpm/site.json';
const HASH  = '/run/svc/php-fpm/admin-password-hash';
const DATA  = '/data/svc/php-fpm';
const SALTS = DATA . '/salts.php';

function fail( string $why ): never {
	fwrite( STDERR, "wordpress-install: $why\n" );
	exit( 1 );
}

function say( string $what ): void {
	fwrite( STDOUT, "wordpress-install: $what\n" );
}

$site = json_decode( (string) @file_get_contents( SITE ), true );
if ( ! is_array( $site ) || empty( $site['url'] ) ) {
	fail( 'no site url in the settings (' . SITE . ')' );
}
$hash = rtrim( (string) @file_get_contents( HASH ), "\r\n" );
// bcrypt ($2a$, $2b$, $2y$), as htpasswd -B or PHP's password_hash make,
// or WordPress's own prefixed form; never a plaintext password.
if ( ! preg_match( '~^(\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}|\$wp\$2y\$\d\d\$[./A-Za-z0-9]{53})$~', $hash ) ) {
	fail( HASH . ' is not a bcrypt hash: make one with `htpasswd -nbB x PASSWORD | cut -d: -f2`' );
}
if ( ! is_dir( DATA ) || ! is_writable( DATA ) ) {
	fail( DATA . ' is not there: WordPress keeps its database and uploads on /data' );
}
foreach ( array( DATA . '/uploads' => 0755, DATA . '/database' => 0700 ) as $dir => $mode ) {
	if ( ! is_dir( $dir ) && ! mkdir( $dir, $mode ) ) {
		fail( "cannot make $dir" );
	}
}

// The salts, made once: eight keys of 64 random bytes, written whole and
// renamed into place, 0600.
if ( ! file_exists( '/run/svc/php-fpm/salts' ) && ! file_exists( SALTS ) ) {
	$lines = "<?php\n// Made by werewolf on this machine's first start; a new file logs everyone out.\n";
	foreach ( array( 'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT' ) as $key ) {
		$lines .= sprintf( "define( '%s', '%s' );\n", $key, base64_encode( random_bytes( 64 ) ) );
	}
	$tmp = SALTS . '.tmp';
	if ( file_put_contents( $tmp, $lines ) !== strlen( $lines ) || ! chmod( $tmp, 0600 ) || ! rename( $tmp, SALTS ) ) {
		@unlink( $tmp );
		fail( 'cannot write ' . SALTS );
	}
	say( 'salts made in ' . SALTS );
}

// WordPress, as the installer loads it: no theme, no plugins' hooks but
// the must-use ones, and the request's host the site's.
define( 'WP_INSTALLING', true );
$_SERVER['HTTP_HOST']   = parse_url( $site['url'], PHP_URL_HOST ) ?: 'localhost';
$_SERVER['REQUEST_URI'] = '/';
$_SERVER['SERVER_NAME'] = $_SERVER['HTTP_HOST'];
// No "new site" mail from the installer: the admin set this machine up.
function wp_new_blog_notification( $blog_title, $blog_url, $user_id, $password ) {}
require '/usr/src/wordpress/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/upgrade.php';

if ( is_blog_installed() ) {
	say( 'the site in ' . ( defined( 'DB_DIR' ) ? DB_DIR : 'the database ' . DB_NAME ) . ' is installed; keeping it' );
	exit( 0 );
}

$user   = $site['admin-user'] ?? 'admin';
$result = wp_install( $site['title'] ?? 'werewolf', $user, $site['admin-email'], true, '', wp_generate_password( 48, true, true ) );
if ( is_wp_error( $result ) ) {
	fail( 'wp_install: ' . $result->get_error_message() );
}
// The password is the hash the config gave, never one the installer made.
if ( false === $wpdb->update( $wpdb->users, array( 'user_pass' => $hash ), array( 'ID' => $result['user_id'] ) ) ) {
	fail( 'cannot set the admin password hash' );
}
clean_user_cache( $result['user_id'] );
say( sprintf( 'installed %s at %s, admin %s (user %d) with the password hash from the config', get_option( 'blogname' ), $site['url'], $user, $result['user_id'] ) );
