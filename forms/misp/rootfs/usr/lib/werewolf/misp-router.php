<?php
// misp-router: the front for PHP's built-in server. An existing file is
// served as itself. Anything else is MISP's index. A path with ".." is
// refused. PHP is bound to loopback; Caddy is what the network sees.
$path = parse_url($_SERVER["REQUEST_URI"] ?? "/", PHP_URL_PATH);
if (!is_string($path) || str_contains($path, "..")) {
    http_response_code(400);
    return true;
}
$file = "/var/www/MISP/app/webroot" . $path;
if ($path !== "/" && is_file($file)) {
    return false;
}
// Every application route executes this front controller. PHP's built-in
// server otherwise leaves the requested route in PHP_SELF, so Cake invents
// a different base directory on each page and produces invalid form URLs.
$_SERVER["SCRIPT_NAME"] = "/index.php";
$_SERVER["PHP_SELF"] = "/index.php";
unset($_SERVER["PATH_INFO"]);
require "/var/www/MISP/app/webroot/index.php";
