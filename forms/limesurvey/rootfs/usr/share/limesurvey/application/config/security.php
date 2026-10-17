<?php
/**
 * security.php for werewolf's limesurvey form: LimeSurvey's encryption
 * keys, which it would write here itself, read from the JSON install.php
 * made once on /data (0600, php's), as data rather than PHP. Losing them
 * loses every encrypted answer and participant field.
 */
if (!defined('BASEPATH')) {
    exit('No direct script access allowed');
}

$werewolfKeys = json_decode((string) @file_get_contents('/data/svc/php-fpm/security.json'), true);
return is_array($werewolfKeys) ? $werewolfKeys : array();
