<?php
// Code lives in the verified image. No downloads or writes at startup.
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
header('Content-Type: text/plain; charset=utf-8');
if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    header('Allow: GET');
    echo "method not allowed\n";
} elseif ($path === '/health') {
    echo "ok\n";
} elseif ($path === '/' || $path === '/index.php') {
    echo "Hello from PHP on werewolf!\n";
} else {
    http_response_code(404);
    echo "not found\n";
}
