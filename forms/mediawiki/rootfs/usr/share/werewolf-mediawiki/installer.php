<?php
/**
 * installer.php: what setup.php gives MediaWiki's installer before an
 * install. Installer::apacheModulePresent asks phpinfo() whether Apache's
 * mod_security is loaded. This PHP has no phpinfo() without its debug
 * allowance, which php-fpm is not granted, and nginx has no Apache modules:
 * so the installer's own namespace gets a phpinfo() that reports none.
 */

namespace MediaWiki\Installer;

function phpinfo( int $flags = INFO_ALL ): bool {
	return true;
}
