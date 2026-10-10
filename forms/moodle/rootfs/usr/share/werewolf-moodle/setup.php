<?php
// setup.php: Moodle set up from the machine's settings before it serves,
// so that no first visitor claims it (the moodle form,
// forms/moodle/README.md).
//
// leash runs it before each start of php-fpm, as the moodle user, inside
// its leash (etc/sv/moodle/service). It reads the settings leash rendered
// (/run/svc/moodle/site.json), the administrator's password and the mail
// relay's, which the config brought; makes Moodle's data directory on
// /data; writes /data/svc/moodle/site.json, which config.php reads, for
// the web and cron alike; waits for PostgreSQL; and, if Moodle is not
// installed, installs it: the site's name, the administrator and the
// password from the config. An installed Moodle is left as it is; Moodle's
// own upgrade.php, the next step, upgrades it. Any fault exits 1, with a
// line saying why, and php-fpm stays down.

const RUN  = '/run/svc/moodle';
const DATA = '/data/svc/moodle';
const SITE = DATA . '/site.json';

function fail(string $why): never {
    fwrite(STDERR, "moodle-setup: $why\n");
    exit(1);
}

function say(string $what): void {
    fwrite(STDOUT, "moodle-setup: $what\n");
}

$site = json_decode((string) @file_get_contents(RUN . '/site.json'), true);
if (!is_array($site) || empty($site['base-url'])) {
    fail('no base-url in the settings (' . RUN . '/site.json)');
}
$password = rtrim((string) @file_get_contents(RUN . '/admin-password'), "\r\n");
if ($password === '') {
    fail(RUN . '/admin-password is empty');
}
$admin = $site['admin'] ?? 'admin';
// Moodle's own rule for a username: lower case, and no spaces.
if (!preg_match('/^[a-z0-9_.@-]+$/', $admin) || $admin === 'guest') {
    fail("admin $admin is not a Moodle username: lower-case letters, digits and _.@- alone, and not guest");
}
if (!filter_var($site['admin-email'] ?? '', FILTER_VALIDATE_EMAIL)) {
    fail('admin-email is not an address');
}
if (!is_dir(DATA) || !is_writable(DATA)) {
    fail(DATA . ' is not there: Moodle keeps its files on /data');
}
if (!is_dir(DATA . '/data') && !mkdir(DATA . '/data', 02770)) {
    fail('cannot make ' . DATA . '/data');
}

// What config.php reads, for the web and cron: the address and the mail
// relay, its password too, so the file is its group's alone.
$shared = ['wwwroot' => $site['base-url']];
foreach (['smtp', 'smtp-user', 'mail-from'] as $key) {
    if (!empty($site[$key])) {
        $shared[$key] = $site[$key];
    }
}
if (!empty($site['smtp']) && is_readable(RUN . '/smtp-password')) {
    $shared['smtp-password'] = rtrim((string) file_get_contents(RUN . '/smtp-password'), "\r\n");
}
$json = json_encode($shared, JSON_UNESCAPED_SLASHES) . "\n";
$tmp = SITE . '.tmp';
if (file_put_contents($tmp, $json) !== strlen($json) || !chmod($tmp, 0640) || !rename($tmp, SITE)) {
    @unlink($tmp);
    fail('cannot write ' . SITE);
}

// PostgreSQL starts beside Moodle, and pg-init makes its role and schema
// first: wait for it, two minutes at most.
$dsn = "host=/run/svc/postgres dbname=postgres user=moodle";
for ($i = 0; !($pg = @pg_connect($dsn)); $i++) {
    if ($i >= 120) {
        fail('PostgreSQL does not answer on /run/svc/postgres as moodle');
    }
    sleep(1);
}
$installed = pg_fetch_result(pg_query($pg, "SELECT to_regclass('moodle.mdl_config') IS NOT NULL"), 0, 0) === 't';
pg_close($pg);
if ($installed) {
    say('Moodle is installed in the schema moodle; keeping it');
    exit(0);
}

// Moodle's own installer, as admin/cli/install_database.php runs it, with
// the password from the config rather than the command line.
define('CLI_SCRIPT', true);
define('CACHE_DISABLE_ALL', true);
require '/usr/share/moodle/config.php';
require_once $CFG->libdir . '/clilib.php';
require_once $CFG->libdir . '/installlib.php';
require_once $CFG->libdir . '/adminlib.php';
require_once $CFG->libdir . '/componentlib.class.php';
require_once $CFG->libdir . '/environmentlib.php';
require_once $CFG->libdir . '/upgradelib.php';

$CFG->early_install_lang = true;
get_string_manager(true);
raise_memory_limit(MEMORY_EXTRA);
$CFG->lang = 'en';
$CFG->early_install_lang = false;
get_string_manager(true);

require "$CFG->dirroot/version.php";
[$envstatus, $results] = check_moodle_environment(normalize_version($release), ENV_SELECT_RELEASE);
if (!$envstatus) {
    foreach (environment_get_errors($results) as [$info, $report]) {
        fwrite(STDERR, "moodle-setup: environment: $info: $report\n");
    }
    fail('the environment is not what Moodle needs');
}
$failed = [];
if (!core_plugin_manager::instance()->all_plugins_ok($version, $failed)) {
    fail('plugins not as their versions need: ' . implode(', ', array_unique($failed)));
}

say("installing Moodle $release at {$site['base-url']}");
$name = $site['site-name'] ?? 'Moodle';
// The installer's progress, a line or more for each of hundreds of
// plugins, is not the console's: it is kept, and only if the installer
// stops short are its last lines the console's, to say why.
$done = false;
register_shutdown_function(static function () use (&$done): void {
    if ($done || ($out = ob_get_clean()) === false) {
        return;
    }
    $lines = array_slice(explode("\n", trim(strip_tags($out))), -40);
    fwrite(STDERR, 'moodle-setup: the installer stopped: ' . implode("\nmoodle-setup: ", $lines) . "\n");
});
ob_start();
install_cli_database([
    'lang'         => 'en',
    'adminuser'    => $admin,
    'adminpass'    => $password,
    'adminemail'   => $site['admin-email'],
    'fullname'     => $name,
    'shortname'    => $name,
    'summary'      => '',
    'supportemail' => $site['admin-email'],
    'noreplyemail' => $site['mail-from'] ?? '',
], false);
upgrade_themes();
ob_end_clean();
$done = true;
say("installed Moodle $release, administrator $admin with the password from the config");
