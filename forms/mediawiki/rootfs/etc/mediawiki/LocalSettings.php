<?php
/**
 * LocalSettings.php for werewolf's mediawiki form (forms/mediawiki).
 *
 * In the image, read-only, outside the code: php-fpm's pool names it in
 * MW_CONFIG_FILE, and setup.php for the updater. What differs per machine
 * comes from the settings leash rendered into /run/svc/php-fpm/site.json
 * (the wiki's address, name, language and whether strangers may read it),
 * and its secret key from /data, where setup.php made it once. The
 * database is SQLite, and uploads are files, both in /data/svc/php-fpm.
 */
if ( !defined( 'MEDIAWIKI' ) ) {
	exit;
}

$werewolf = json_decode( (string)@file_get_contents( '/run/svc/php-fpm/site.json' ), true );
if ( !is_array( $werewolf ) || empty( $werewolf['url'] ) ) {
	http_response_code( 503 );
	exit( "werewolf: no wiki url in the settings\n" );
}

$wgSitename = $werewolf['name'] ?? 'Wiki';
$wgServer = rtrim( $werewolf['url'], '/' );
$wgCanonicalServer = $wgServer;
$wgLanguageCode = $werewolf['language'] ?? 'en';
$wgScriptPath = '';
$wgResourceBasePath = $wgScriptPath;
$wgArticlePath = '/wiki/$1';
$wgUsePathInfo = true;

// The database: SQLite on /data, its busiest tables in files of their
// own, as MediaWiki's installer sets them.
$wgDBtype = 'sqlite';
$wgDBserver = '';
$wgDBname = 'wiki';
$wgDBuser = '';
$wgDBpassword = '';
$wgDBprefix = '';
$wgSQLiteDataDir = '/data/svc/php-fpm/database';
$wgObjectCaches[CACHE_DB] = [
	'class' => SqlBagOStuff::class,
	'loggroup' => 'SQLBagOStuff',
	'server' => [
		'type' => 'sqlite',
		'dbname' => 'wikicache',
		'tablePrefix' => '',
		'variables' => [ 'synchronous' => 'NORMAL' ],
		'dbDirectory' => $wgSQLiteDataDir,
		'trxMode' => 'IMMEDIATE',
		'flags' => 0,
	],
];
$wgJobTypeConf['default'] = [
	'class' => 'JobQueueDB',
	'claimTTL' => 3600,
	'server' => [
		'type' => 'sqlite',
		'dbname' => "{$wgDBname}_jobqueue",
		'tablePrefix' => '',
		'variables' => [ 'synchronous' => 'NORMAL' ],
		'dbDirectory' => $wgSQLiteDataDir,
		'trxMode' => 'IMMEDIATE',
		'flags' => 0,
	],
];
$wgResourceLoaderUseObjectCacheForDeps = true;

// Caches: APCu in php-fpm's memory, which also counts failed logins;
// sessions in the database, so a restart logs no one out; the interface's
// messages in files on /data.
$wgMainCacheType = CACHE_ACCEL;
$wgSessionCacheType = CACHE_DB;
$wgMemCachedServers = [];
$wgCacheDirectory = '/data/svc/php-fpm/cache';

require '/data/svc/php-fpm/secrets.php';
$wgAuthenticationTokenVersion = '1';

// Who may do what. Only accounts edit or upload, and only an
// administrator makes accounts: no one signs up. Reading takes an account
// too unless the settings say public-read, as lab notes are not for
// strangers.
$wgGroupPermissions['*']['read'] = !empty( $werewolf['public-read'] );
$wgGroupPermissions['*']['edit'] = false;
$wgGroupPermissions['*']['createpage'] = false;
$wgGroupPermissions['*']['createtalk'] = false;
$wgGroupPermissions['*']['createaccount'] = false;
$wgGroupPermissions['*']['autocreateaccount'] = false;
$wgGroupPermissions['sysop']['createaccount'] = true;

// Uploads: images and PDFs, files on /data that PHP hands out through
// img_auth.php to whoever may read the wiki, never served straight from
// the disk. No SVG, HTML or anything a browser runs; types checked by
// content, not by name; nothing fetched by URL. Thumbnails by GD, in PHP.
$wgEnableUploads = true;
$wgUploadDirectory = '/data/svc/php-fpm/images';
$wgUploadPath = "$wgScriptPath/img_auth.php";
$wgFileExtensions = [ 'png', 'gif', 'jpg', 'jpeg', 'webp', 'pdf' ];
$wgStrictFileExtensions = true;
$wgVerifyMimeType = true;
$wgAllowCopyUploads = false;
$wgAllowExternalImages = false;
$wgUseInstantCommons = false;
$wgMaxUploadSize = 64 * 1024 * 1024;
$wgUseImageMagick = false;
$wgImgAuthDetails = false;

// No programs: php-fpm.conf refuses PHP's process functions, and the
// leash any exec; these keep MediaWiki from trying.
$wgShellRestrictionMethod = false;
$wgDiff3 = '';
$wgDiff = false;
$wgExternalDiffEngine = false;
$wgGitBin = false;

// Nothing leaves the machine: no usage reports, no mail (an administrator
// resets passwords), and jobs run within requests rather than by an HTTP
// request to the wiki itself.
$wgPingback = false;
$wgEnableEmail = false;
$wgEnableUserEmail = false;
$wgEmailAuthentication = false;
$wgJobRunRate = 1;
$wgRunJobsAsync = false;

// Behind the TLS in front, which says so in X-Forwarded-Proto (nginx.conf):
// with an https address, cookies are sent over HTTPS alone.
$wgCookieSecure = str_starts_with( $wgServer, 'https://' );
$wgForceHTTPS = false;
$wgShowExceptionDetails = false;

$wgDefaultSkin = 'vector-2022';
$werewolfParts = require '/etc/mediawiki/extensions.php';
wfLoadSkins( $werewolfParts['skins'] );
wfLoadExtensions( $werewolfParts['extensions'] );
$wgDefaultUserOptions['visualeditor-enable'] = 1;
