<?php
// cron.php runs Nextcloud's background jobs, every five minutes, as
// nextcloud-cron under the cron service's leash (etc/cron/crontab).
// Nextcloud runs them only as the owner of its config.php, which is the
// web's user, nextcloud; so this copies the web's config, which its group
// may read, into the cron service's own directory, the config directory
// it names (NEXTCLOUD_CONFIG_DIR), and runs Nextcloud's cron.php on the
// copy. What a job would write to the config is not kept; jobs write the
// database. Until Nextcloud is installed there is nothing to run.

declare(strict_types=1);

const WEB = '/data/svc/nextcloud/config/';

$own = getenv('NEXTCLOUD_CONFIG_DIR');
if (!is_string($own) || $own === '') {
	fwrite(STDERR, "nextcloud-cron: no NEXTCLOUD_CONFIG_DIR\n");
	exit(1);
}
$own = rtrim($own, '/') . '/';
if (!is_file(WEB . 'config.php')) {
	exit(0);
}
if (!is_dir($own) && !mkdir($own, 0700)) {
	fwrite(STDERR, "nextcloud-cron: cannot make $own\n");
	exit(1);
}

// Each file under Nextcloud's own lock, which it takes to write one.
$names = [];
foreach (glob(WEB . '*config.php') as $from) {
	$name = basename($from);
	$names[] = $name;
	$in = fopen($from, 'r');
	if ($in === false || !flock($in, LOCK_SH)) {
		fwrite(STDERR, "nextcloud-cron: cannot read $from\n");
		exit(1);
	}
	$ok = file_put_contents("$own$name.new", stream_get_contents($in)) !== false
		&& rename("$own$name.new", "$own$name");
	fclose($in);
	if (!$ok) {
		fwrite(STDERR, "nextcloud-cron: cannot copy $from\n");
		exit(1);
	}
}
foreach (glob($own . '*config.php') as $stale) {
	if (!in_array(basename($stale), $names, true)) {
		unlink($stale);
	}
}

require '/usr/share/nextcloud/cron.php';
