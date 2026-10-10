<?php
// setup.php sets Nextcloud up before php-fpm serves it, at every start, as
// the nextcloud user under its leash (etc/sv/nextcloud/service). It makes
// the directories on /data, writes werewolf.config.php from the machine's
// settings, which Nextcloud reads after its own config.php, so the
// settings win, and the first time installs Nextcloud with the
// administrator and password the config names. A Nextcloud nobody has
// installed is never served: its installer would go to whoever found it.

declare(strict_types=1);

const DATA = '/data/svc/nextcloud';
const RUN = '/run/svc/nextcloud';
const CODE = '/usr/share/nextcloud';
const PG = '/run/svc/postgres';

function say(string $line): void {
	fwrite(STDOUT, "nextcloud-setup: $line\n");
}

function fail(string $line): never {
	say($line);
	exit(1);
}

// What service-config wrote from the settings (render json site.json); a
// missing base URL kept the service down before this ran.
$site = json_decode((string)file_get_contents(RUN . '/site.json'), true);
if (!is_array($site) || !isset($site['base-url'])) {
	fail('no base-url in ' . RUN . '/site.json');
}
$url = rtrim($site['base-url'], '/');
$parts = parse_url($url);
$host = $parts['host'] . (isset($parts['port']) ? ':' . $parts['port'] : '');
$admin = $site['admin'] ?? 'admin';

// Nextcloud wants its data directory 0770; the rest take the mode leash
// gave the service's directory, which its group shares.
foreach (['config', 'data', 'apps', 'tmp'] as $d) {
	if (!is_dir(DATA . "/$d") && !mkdir(DATA . "/$d", 0770)) {
		fail('cannot make ' . DATA . "/$d");
	}
}
chmod(DATA . '/data', 0770);

// The machine's settings, and the policy no administrator changes from the
// web: upgrades by the image alone, logs on the console, Valkey for
// locking and the shared cache.
$conf = [
	'trusted_domains' => [$host],
	'overwrite.cli.url' => $url,
	'overwriteprotocol' => $parts['scheme'],
	'htaccess.RewriteBase' => '/',
	'datadirectory' => DATA . '/data',
	'tempdirectory' => DATA . '/tmp',
	'apps_paths' => [
		['path' => CODE . '/apps', 'url' => '/apps', 'writable' => false],
		['path' => DATA . '/apps', 'url' => '/custom_apps', 'writable' => true],
	],
	'memcache.local' => '\\OC\\Memcache\\APCu',
	'memcache.distributed' => '\\OC\\Memcache\\Redis',
	'memcache.locking' => '\\OC\\Memcache\\Redis',
	'redis' => ['host' => '/run/svc/valkey/valkey.sock', 'port' => 0],
	'upgrade.disable-web' => true,
	'updatechecker' => false,
	'log_type' => 'errorlog',
	'loglevel' => 2,
	'maintenance_window_start' => 1,
];
if (isset($site['phone-region'])) {
	$conf['default_phone_region'] = $site['phone-region'];
}
$file = DATA . '/config/werewolf.config.php';
$text = "<?php\n// Written by setup.php at every start, from the machine's settings: edits are lost.\n"
	. '$CONFIG = ' . var_export($conf, true) . ";\n";
if (!is_file($file) || file_get_contents($file) !== $text) {
	if (file_put_contents("$file.new", $text) === false || !chmod("$file.new", 0640) || !rename("$file.new", $file)) {
		fail("cannot write $file");
	}
}

// PostgreSQL, Valkey: each starts beside this one, and is waited for.
for ($i = 0; ; $i++) {
	try {
		new PDO('pgsql:host=' . PG . ';dbname=postgres', 'nextcloud', null);
		if (file_exists('/run/svc/valkey/valkey.sock')) {
			break;
		}
	} catch (PDOException $e) {
		if ($i >= 120) {
			fail('PostgreSQL does not answer: ' . $e->getMessage());
		}
	}
	if ($i >= 120) {
		fail('Valkey does not answer');
	}
	sleep(1);
}

define('OC_CONSOLE', 1);
require_once CODE . '/lib/base.php';

$system = \OCP\Server::get(\OC\SystemConfig::class);
if (!$system->getValue('installed', false)) {
	$password = rtrim((string)file_get_contents(RUN . '/admin-password'), "\r\n");
	if ($password === '') {
		fail('the config\'s admin-password is empty');
	}
	say("installing Nextcloud for $url, its administrator $admin");
	$errors = \OCP\Server::get(\OC\Setup::class)->install([
		'dbtype' => 'pgsql',
		'dbhost' => PG,
		'dbname' => 'nextcloud',
		'dbuser' => 'nextcloud',
		'dbpass' => '',
		'adminlogin' => $admin,
		'adminpass' => $password,
		'adminemail' => $site['admin-email'] ?? null,
		'directory' => DATA . '/data',
		'trusted_domains' => [$host],
		'passwordsalt' => '',
		'secret' => '',
	]);
	foreach ($errors as $e) {
		say('install: ' . (is_array($e) ? trim($e['error'] . ' ' . ($e['hint'] ?? '')) : $e));
	}
	if ($errors) {
		exit(1);
	}
	// Background jobs by cron (etc/cron/crontab), not by visitors' page
	// loads; no announcements fetched from Nextcloud's servers.
	\OCP\Server::get(\OCP\IAppConfig::class)->setValueString('core', 'backgroundjobs_mode', 'cron');
	\OCP\Server::get(\OCP\App\IAppManager::class)->disableApp('nextcloud_announcements');
	say('installed');
}

// Nothing on this machine turns maintenance on but an upgrade, which turns
// it off; one cut short leaves it on, and the site down.
if ($system->getValue('maintenance', false)) {
	say('maintenance mode was left on: off');
	$system->setValue('maintenance', false);
}

// Nextcloud's commands take ids from a sequence in files, in a directory
// it makes 0700; the background jobs, as nextcloud-cron, take theirs from
// the same files, so the directory is the group's.
$seq = \OCP\Server::get(\OCP\ITempManager::class)->getTempBaseDir() . '/'
	. \OC\Snowflake\FileSequence::LOCK_FILE_DIRECTORY . '_' . \OC_Util::getInstanceId();
if ((!is_dir($seq) && !mkdir($seq, 0770)) || !chmod($seq, 0770)) {
	fail("cannot share $seq with the background jobs");
}
