<?php
/**
 * config.php for werewolf's limesurvey form (forms/limesurvey/README.md).
 *
 * In the image, read-only: what differs per machine comes from the
 * settings leash rendered into /run/svc/php-fpm/site.json, and the relay's
 * password from the config if it brought one. Its being here also turns
 * LimeSurvey's web installer off: the site is installed before php-fpm
 * serves (usr/share/werewolf-limesurvey/install.php). The database is
 * MariaDB's `limesurvey`, by its socket, as the role php, which MariaDB
 * knows by the process's user (unix_socket): no password exists to steal.
 */
if (!defined('BASEPATH')) {
    exit('No direct script access allowed');
}

$werewolf = json_decode((string) @file_get_contents('/run/svc/php-fpm/site.json'), true);
if (!is_array($werewolf) || empty($werewolf['url'])) {
    http_response_code(503);
    exit("werewolf: no site url in the settings\n");
}
$werewolfUrl = rtrim($werewolf['url'], '/') . '/';
$werewolfHttps = str_starts_with($werewolfUrl, 'https://');

$werewolfConfig = array(
    'debug' => 0,
    'debugsql' => 0,
    'mysqlEngine' => 'INNODB',
    'sitename' => $werewolf['title'] ?? 'LimeSurvey',
    'siteadminname' => $werewolf['admin-name'] ?? 'Administrator',
    'siteadminemail' => $werewolf['admin-email'] ?? '',
    'siteadminbounce' => $werewolf['admin-email'] ?? '',
    // Links in mail are built from the site's address, and a request for
    // any other host is refused: a forged Host header cannot aim a
    // password reset at someone else's site.
    'publicurl' => $werewolfUrl,
    'allowedHosts' => array(parse_url($werewolfUrl, PHP_URL_HOST)),
    // Nothing fetched or installed at run time: no update checks, no
    // plugin uploads (a plugin is PHP), no Twig extensions from upload/.
    // Themes may be uploaded, but LimeSurvey unpacks no code from them.
    'updatecheckperiod' => 0,
    'disablePluginUpload' => true,
    'use_custom_twig_extensions' => false,
    'showEmailInError' => false,
);

// Mail, through the relay the settings name, over STARTTLS; without one,
// LimeSurvey has no way to send and says so when it tries.
if (!empty($werewolf['smtp'])) {
    $werewolfConfig['emailmethod'] = 'smtp';
    $werewolfConfig['emailsmtphost'] = $werewolf['smtp'];
    $werewolfConfig['emailsmtpssl'] = 'tls';
    $werewolfConfig['emailsmtpuser'] = $werewolf['smtp-user'] ?? '';
    $werewolfConfig['emailsmtppassword'] = rtrim((string) @file_get_contents('/run/svc/php-fpm/smtp-password'), "\r\n");
    if (!empty($werewolf['mail-from'])) {
        $werewolfConfig['siteadminemail'] = $werewolf['mail-from'];
    }
}

return array(
    'components' => array(
        'db' => array(
            'connectionString' => 'mysql:unix_socket=/run/svc/mariadb/mariadb.sock;dbname=limesurvey',
            'emulatePrepare' => true,
            'username' => 'php',
            'password' => '',
            'charset' => 'utf8mb4',
            'tablePrefix' => 'lime_',
        ),
        'urlManager' => array(
            'urlFormat' => 'path',
            'rules' => array(),
            'showScriptName' => true,
        ),
        // With an https address, cookies go over HTTPS alone.
        'session' => array(
            'cookieParams' => array(
                'httponly' => true,
                'secure' => $werewolfHttps,
                'samesite' => 'Lax',
            ),
        ),
        // Plugins load from the image alone, core and plugins/: none from
        // upload/ on /data, where a file someone managed to write would
        // become code. The list replaces LimeSurvey's whole.
        'pluginManager' => array(
            'pluginDirs' => array(
                'user' => 'webroot.plugins',
                'core' => 'application.core.plugins',
                'upload' => '',
            ),
        ),
    ),
    'config' => $werewolfConfig,
);
