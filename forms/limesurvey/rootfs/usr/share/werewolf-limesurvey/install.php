<?php
/**
 * install.php: LimeSurvey set up from the machine's settings before it
 * serves, so that no first visitor claims it (the limesurvey form,
 * forms/limesurvey/README.md).
 *
 * leash runs it before each start of php-fpm, as the php user, inside its
 * leash. It reads the settings leash rendered (/run/svc/php-fpm/site.json)
 * and the admin's bcrypt password hash the config brought; makes
 * LimeSurvey's directories on /data, and its encryption keys once; empties
 * its published assets and cache when the release changed; waits for
 * MariaDB; and then installs LimeSurvey's tables and the admin, whose
 * password is the hash given, or brings the tables of an older release up
 * to this one. A site already installed keeps its admin as it is. Any
 * fault exits 1, with one line saying why, and php-fpm stays down.
 */

const SITE = '/run/svc/php-fpm/site.json';
const HASH = '/run/svc/php-fpm/admin-password-hash';
const DATA = '/data/svc/php-fpm';
const ROOT = '/usr/share/limesurvey';
const SOCK = '/run/svc/mariadb/mariadb.sock';

function fail(string $why): never
{
    fwrite(STDERR, "limesurvey-install: $why\n");
    exit(1);
}

function say(string $what): void
{
    fwrite(STDOUT, "limesurvey-install: $what\n");
}

// release returns the image's LimeSurvey: version, build and database
// version, from a file that fills in a $config of its own.
function release(): array
{
    $config = array();
    return require ROOT . '/application/config/version.php';
}

// emptied removes what is beneath $dir, which stays.
function emptied(string $dir): void
{
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($it as $f) {
        if (!($f->isDir() && !$f->isLink() ? rmdir($f->getPathname()) : unlink($f->getPathname()))) {
            fail('cannot remove ' . $f->getPathname());
        }
    }
}

// written puts $text at $path whole, mode 0600, by a rename.
function written(string $path, string $text): void
{
    $tmp = $path . '.tmp';
    if (file_put_contents($tmp, $text) !== strlen($text) || !chmod($tmp, 0600) || !rename($tmp, $path)) {
        @unlink($tmp);
        fail("cannot write $path");
    }
}

$site = json_decode((string) @file_get_contents(SITE), true);
if (!is_array($site) || empty($site['url'])) {
    fail('no site url in the settings (' . SITE . ')');
}
if (empty($site['admin-email'])) {
    fail('no admin-email in the settings (' . SITE . ')');
}
$hash = rtrim((string) @file_get_contents(HASH), "\r\n");
// bcrypt ($2a$, $2b$, $2y$), as htpasswd -B or PHP's password_hash make;
// never a plaintext password.
if (!preg_match('~^\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}$~', $hash)) {
    fail(HASH . ' is not a bcrypt hash: make one with `htpasswd -nbB x PASSWORD | cut -d: -f2`');
}
if (!is_dir(DATA) || !is_writable(DATA)) {
    fail(DATA . ' is not there: LimeSurvey keeps its uploads and assets on /data');
}

// The image's tmp and upload are links to these. nginx, in php's group,
// serves the published assets and the uploads, but never the cache,
// participants' files in flight, or the keys.
$dirs = array(
    'tmp' => 0750, 'tmp/assets' => 0750, 'tmp/runtime' => 0700, 'tmp/upload' => 0700,
    'upload' => 0750, 'upload/surveys' => 0750, 'upload/labels' => 0750,
    'upload/global' => 0750, 'upload/admintheme' => 0750, 'upload/fonts' => 0750,
    'upload/themes' => 0750, 'upload/themes/survey' => 0750,
    'upload/themes/survey/generalfiles' => 0750, 'upload/themes/question' => 0750,
);
foreach ($dirs as $dir => $mode) {
    if (!is_dir(DATA . "/$dir") && !mkdir(DATA . "/$dir", $mode)) {
        fail('cannot make ' . DATA . "/$dir");
    }
}

// Assets and the cache are the release's: a new one publishes its own.
$release = release();
$stamp = $release['versionnumber'] . '+' . $release['buildnumber'];
if (rtrim((string) @file_get_contents(DATA . '/tmp/release'), "\n") !== $stamp) {
    emptied(DATA . '/tmp/assets');
    emptied(DATA . '/tmp/runtime');
    written(DATA . '/tmp/release', "$stamp\n");
    say("assets and cache emptied for LimeSurvey $stamp");
}

// The encryption keys, made once, as LimeSurvey would make them.
if (!file_exists(DATA . '/security.json')) {
    written(DATA . '/security.json', json_encode(array(
        'encryptionnonce' => bin2hex(random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES)),
        'encryptionsecretboxkey' => bin2hex(sodium_crypto_secretbox_keygen()),
    )) . "\n");
    say('encryption keys made in ' . DATA . '/security.json');
}

// MariaDB makes its data on its first start, beside this: wait for it, or
// fail, so php-fpm never serves a site not installed.
for ($try = 1; ; $try++) {
    try {
        new PDO('mysql:unix_socket=' . SOCK . ';dbname=limesurvey', 'php', '');
        break;
    } catch (PDOException $e) {
        if ($try >= 120) {
            fail('MariaDB did not answer in 2 minutes: ' . $e->getMessage());
        }
        sleep(1);
    }
}

// LimeSurvey's console application, as application/commands/console.php
// makes it, from LimeSurvey's directory, which it takes as its root.
if (!chdir(ROOT)) {
    fail('cannot enter ' . ROOT);
}
define('BASEPATH', '.');
define('EXT', '.php');
define('YII_DEBUG', true);
require ROOT . '/vendor/autoload.php';
require ROOT . '/vendor/yiisoft/yii/framework/yii.php';
$config = require ROOT . '/application/config/internal.php';
$config['components']['session']['class'] = 'ConsoleHttpSession';
$config['components']['session']['cookieMode'] = 'none';
$config['components']['session']['cookieParams'] = array();
unset($config['defaultController'], $config['config']);
$config['runtimePath'] = DATA . '/tmp/runtime';
require ROOT . '/application/core/ConsoleApplication.php';
$app = Yii::createApplication('ConsoleApplication', $config);
define('APPPATH', $app->getBasePath() . DIRECTORY_SEPARATOR);
Yii::import('application.helpers.ClassFactory');
ClassFactory::registerClass('Token_', 'Token');
ClassFactory::registerClass('Response_', 'Response');
Yii::import('application.helpers.common_helper', true);

$db = $app->getDb();
try {
    $db->active = true;
} catch (Exception $e) {
    fail('cannot reach the database limesurvey: ' . $e->getMessage());
}

if ($db->schema->getTable('{{users}}') === null) {
    require_once ROOT . '/installer/create-database.php';
    try {
        populateDatabase($db);
    } catch (Exception $e) {
        fail('cannot make LimeSurvey\'s tables: ' . $e->getMessage());
    }
    $user = $site['admin-user'] ?? 'admin';
    $db->createCommand()->insert($db->tablePrefix . 'users', array(
        'users_name' => $user,
        'password' => $hash,
        'full_name' => $site['admin-name'] ?? 'Administrator',
        'parent_id' => 0,
        'lang' => 'auto',
        'email' => $site['admin-email'],
    ));
    $db->createCommand()->insert($db->tablePrefix . 'permissions', array(
        'entity' => 'global',
        'entity_id' => 0,
        'uid' => 1,
        'permission' => 'superadmin',
        'create_p' => 0,
        'read_p' => 1,
        'update_p' => 0,
        'delete_p' => 0,
        'import_p' => 0,
        'export_p' => 0,
    ));
    say("installed LimeSurvey $stamp at {$site['url']}, admin $user with the password hash from the config");
    exit(0);
}

$current = (int) $app->getConfig('DBVersion');
$wanted = (int) $release['dbversionnumber'];
if ($current === 0) {
    fail('the database limesurvey has a users table but no DBVersion: it is not LimeSurvey\'s, or its install was cut short');
}
if ($current > $wanted) {
    fail("the database is LimeSurvey's version $current, newer than this release's $wanted: boot the slot that made it");
}
if ($current === $wanted) {
    say("the site in the database limesurvey is installed (version $current); keeping it");
    exit(0);
}
Yii::import('application.helpers.update.update_helper', true);
Yii::import('application.helpers.update.updatedb_helper', true);
if (!db_upgrade_all($current)) {
    fail("cannot bring the database from version $current to $wanted");
}
say("brought the database from version $current to $wanted");
