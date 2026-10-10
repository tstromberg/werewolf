<?php
/**
 * setup.php: MediaWiki set up from the machine's settings before it
 * serves, so that no first visitor claims it (forms/mediawiki).
 *
 * leash runs it before each start of php-fpm, as the php user, inside its
 * leash, with PHP's process functions off. It makes the database, uploads
 * and cache directories on /data, and the secret key once; then runs one
 * of MediaWiki's own maintenance scripts, in this process:
 *
 * - install, if the wiki has never been installed: the wiki's name,
 *   language and address from the settings, its administrator and
 *   password from the config, into database.new, renamed to database
 *   once the installer has finished, so a start cut short leaves nothing
 *   half made;
 * - update, if the code or LocalSettings.php differ from those the
 *   database last met (the image was updated);
 * - nothing otherwise.
 *
 * What it brought the database to is kept beside it, in database/schema,
 * so the rename that ends an install moves both at once.
 * Any fault exits 1, with a line saying why, and php-fpm stays down.
 */

const IP      = '/usr/share/mediawiki';
const CONF    = '/etc/mediawiki/LocalSettings.php';
const PARTS   = '/etc/mediawiki/extensions.php';
const SITE    = '/run/svc/php-fpm/site.json';
const PASS    = '/run/svc/php-fpm/admin-password';
const DATA    = '/data/svc/php-fpm';
const DB      = DATA . '/database';
const SECRETS = DATA . '/secrets.php';
const SCHEMA  = DB . '/schema';

function fail( string $why ): never {
	fwrite( STDERR, "mediawiki-setup: $why\n" );
	exit( 1 );
}

function say( string $what ): void {
	fwrite( STDOUT, "mediawiki-setup: $what\n" );
}

// put writes a file whole, 0600, and renames it into place.
function put( string $path, string $text ): void {
	$tmp = "$path.tmp";
	if ( file_put_contents( $tmp, $text ) !== strlen( $text ) || !chmod( $tmp, 0600 ) || !rename( $tmp, $path ) ) {
		@unlink( $tmp );
		fail( "cannot write $path" );
	}
}

// rmtree removes what an install cut short left.
function rmtree( string $dir ): void {
	foreach ( scandir( $dir ) ?: [] as $f ) {
		if ( $f !== '.' && $f !== '..' ) {
			is_dir( "$dir/$f" ) ? rmtree( "$dir/$f" ) : unlink( "$dir/$f" );
		}
	}
	rmdir( $dir );
}

$site = json_decode( (string)@file_get_contents( SITE ), true );
if ( !is_array( $site ) || empty( $site['url'] ) ) {
	fail( 'no wiki url in the settings (' . SITE . ')' );
}
$lang = $site['language'] ?? 'en';
if ( !preg_match( '/^[a-z]{2,3}(-[a-z0-9]+)*$/', $lang ) ) {
	fail( "language $lang is not a language code, such as en or pt-br" );
}
if ( !is_dir( DATA ) || !is_writable( DATA ) ) {
	fail( DATA . ' is not there: MediaWiki keeps its database and uploads on /data' );
}
foreach ( [ DATA . '/images', DATA . '/cache' ] as $dir ) {
	if ( !is_dir( $dir ) && !mkdir( $dir, 0700 ) ) {
		fail( "cannot make $dir" );
	}
}

// The secret key, made once: sessions and tokens are signed with it, so a
// new one logs everyone out.
if ( !file_exists( SECRETS ) ) {
	put( SECRETS, "<?php\n// Made by werewolf on this machine's first start.\n" .
		sprintf( "\$wgSecretKey = '%s';\n", bin2hex( random_bytes( 32 ) ) ) );
	say( 'secret key made in ' . SECRETS );
}

if ( !preg_match( "/define\( 'MW_VERSION', '([^']+)' \)/", (string)file_get_contents( IP . '/includes/Defines.php' ), $m ) ) {
	fail( 'no MW_VERSION in ' . IP . '/includes/Defines.php' );
}
$want = $m[1] . ' ' . sha1( file_get_contents( CONF ) . file_get_contents( PARTS ) ) . "\n";
$have = @file_get_contents( SCHEMA );

if ( $have === false ) {
	// Never installed, or an install cut short: start again.
	if ( is_dir( DB ) ) {
		fail( DB . ' is there but ' . SCHEMA . ' is not: not knowing what the database holds, setup leaves it be' );
	}
	if ( is_dir( DB . '.new' ) ) {
		rmtree( DB . '.new' );
		say( 'removed ' . DB . '.new, which an install cut short left' );
	}
	if ( !is_readable( PASS ) ) {
		fail( 'no administrator password in the config (' . PASS . ')' );
	}
	$parts = require PARTS;
	$argv = [
		IP . '/maintenance/run.php', 'install',
		'--server', rtrim( $site['url'], '/' ),
		'--scriptpath', '',
		'--lang', $lang,
		'--dbtype', 'sqlite',
		'--dbpath', DB . '.new',
		'--dbname', 'wiki',
		'--passfile', PASS,
		'--confpath', '/run/svc/php-fpm',
		'--skins', implode( ',', $parts['skins'] ),
		'--extensions', implode( ',', $parts['extensions'] ),
		$site['name'] ?? 'Wiki',
		$site['admin'] ?? 'Admin',
	];
	$done = 'installed';
} elseif ( $have !== $want ) {
	define( 'MW_CONFIG_FILE', CONF );
	$argv = [ IP . '/maintenance/run.php', 'update', '--quick' ];
	$done = 'updated';
} else {
	say( 'the wiki in ' . DB . ' is MediaWiki ' . strtok( $want, ' ' ) . '; keeping it' );
	exit( 0 );
}

// MediaWiki's maintenance entry point, run here at file scope, as it
// insists; it exits on any failure and returns on success.
$argc = count( $argv );
$_SERVER['argv'] = $argv;
$_SERVER['argc'] = $argc;
chdir( IP );
require IP . '/maintenance/run.php';

if ( $done === 'installed' ) {
	// The installer's LocalSettings.php is not used: the image's is.
	@unlink( '/run/svc/php-fpm/LocalSettings.php' );
	put( DB . '.new/schema', $want );
	if ( !rename( DB . '.new', DB ) ) {
		fail( 'cannot rename ' . DB . '.new to ' . DB );
	}
} else {
	put( SCHEMA, $want );
}
say( sprintf( '%s MediaWiki %s in %s', $done, strtok( $want, ' ' ), DB ) );
