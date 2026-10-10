<?php
// config.php for werewolf's moodle form (forms/moodle/README.md).
//
// In the image, read-only: what differs per machine is in
// /data/svc/moodle/site.json, which setup.php writes from the machine's
// settings before each start of php-fpm, and which cron, of the web's
// group, reads too. Settings named here are forced: Moodle shows them
// greyed out, and no administrator can change them from the web.

unset($CFG);
global $CFG;
$CFG = new stdClass();

$werewolf = json_decode((string) @file_get_contents('/data/svc/moodle/site.json'), true);
if (!is_array($werewolf) || empty($werewolf['wwwroot'])) {
    if (PHP_SAPI === 'cli') {
        fwrite(STDERR, "moodle: no /data/svc/moodle/site.json; setup.php writes it as the web starts\n");
    } else {
        http_response_code(503);
        echo "moodle: not set up yet\n";
    }
    exit(1);
}

// The database: PostgreSQL's socket, peer authentication as the system
// user (moodle, or cron's moodle-cron, which acts as it), the tables in
// the schema moodle of the postgres database.
$CFG->dbtype    = 'pgsql';
$CFG->dblibrary = 'native';
$CFG->dbhost    = 'localhost';
$CFG->dbname    = 'postgres';
$CFG->dbuser    = getenv('MOODLE_DBUSER') ?: 'moodle';
$CFG->dbpass    = '';
$CFG->prefix    = 'mdl_';
$CFG->dboptions = [
    'dbpersist' => false,
    'dbsocket'  => '/run/svc/postgres',
    'dbschema'  => 'moodle',
];

$CFG->wwwroot  = rtrim($werewolf['wwwroot'], '/');
$CFG->dataroot = '/data/svc/moodle/data';
$CFG->admin    = 'admin';
// Caddy sends what is not a file to Moodle's router (etc/caddy/Caddyfile).
$CFG->routerconfigured = true;
// Its group's alone: the web and cron.
$CFG->directorypermissions = 02770;

// The code is the image's: no plugin installed, updated or fetched from
// the web, and no update checks; a new Moodle comes with a new image.
$CFG->disableupdateautodeploy    = true;
$CFG->disableupdatenotifications = true;
// Paths to programs (Ghostscript, du, an antivirus) are set here or not
// at all: from the web, one is a way to run any program. php-fpm may run
// none in any case.
$CFG->preventexecpath = true;

// Accounts are made by an administrator (or an authentication plugin
// they enable), never by a stranger signing up, and there is no guest.
$CFG->registerauth     = '';
$CFG->guestloginbutton = 0;
$CFG->autologinguests  = 0;

// With an https address, cookies are HTTPS only; never readable by scripts.
$CFG->cookiesecure   = str_starts_with($CFG->wwwroot, 'https://');
$CFG->cookiehttponly = true;

// Mail by the relay the settings name, over TLS; without one, none at
// all, rather than a sendmail that is not there.
if (!empty($werewolf['smtp'])) {
    $CFG->smtphosts    = $werewolf['smtp'];
    $CFG->smtpsecure   = str_ends_with($werewolf['smtp'], ':465') ? 'ssl' : 'tls';
    $CFG->smtpauthtype = 'LOGIN';
    $CFG->smtpuser     = $werewolf['smtp-user'] ?? '';
    $CFG->smtppass     = $werewolf['smtp-password'] ?? '';
    if (!empty($werewolf['mail-from'])) {
        $CFG->noreplyaddress = $werewolf['mail-from'];
    }
} else {
    $CFG->noemailever = true;
}

unset($werewolf);

require_once(__DIR__ . '/lib/setup.php');
