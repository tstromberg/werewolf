<?php
// Test-only entrypoint: exercise the live FPM identity, never run commands.
header('Content-Type: text/plain');
$ok = false;
switch ($_GET['case'] ?? '') {
case 'state':
    $path = '/run/svc/php-fpm/armory-probe';
    $ok = file_put_contents($path, 'data') === 4
        && file_get_contents($path) === 'data' && unlink($path);
    break;
case 'immutable':
    $ok = true;
    foreach (['/usr/share/nginx/html/mangoapi.php', '/usr/bin/dbus-authd',
        '/etc/sudoers', '/etc/php/php-fpm.conf'] as $path) {
        // Open existing config without truncation; no successful probe alters it.
        $fd = @fopen($path, 'c');
        if ($fd !== false) {
            fclose($fd);
            $ok = false;
        }
    }
    break;
case 'privileges':
    $status = file_get_contents('/proc/self/status');
    $ok = preg_match('/^Uid:\s+[1-9][0-9]*\s+[1-9][0-9]*\s+/m', $status)
        && preg_match('/^NoNewPrivs:\s+1$/m', $status)
        && preg_match('/^CapEff:\s+0+$/m', $status);
    break;
case 'network':
    $errno = 0;
    $error = '';
    $listen = @stream_socket_server('tcp://127.0.0.1:19800', $errno, $error);
    $connect = @stream_socket_client('tcp://127.0.0.1:80', $errno, $error, 1);
    $ok = $listen === false && $connect === false;
    if (is_resource($listen)) fclose($listen);
    if (is_resource($connect)) fclose($connect);
    break;
case 'config':
    $ok = @file_get_contents('/etc/nginx/nginx.conf') === false
        && @file_get_contents('/run/config/data.key') === false;
    break;
case 'ini':
    $ok = ini_get('user_ini.filename') === ''
        && ini_get('cgi.fix_pathinfo') === '0'
        && !ini_get('allow_url_include') && !ini_get('enable_dl');
    break;
case 'runtime':
    $ok = PHP_VERSION_ID >= 80500;
    break;
case 'eval':
    try {
        @eval('return 7;');
    } catch (Error $error) {
        $ok = str_contains($error->getMessage(), 'php:inline');
    }
    break;
case 'include':
    $path = '/run/svc/php-fpm/armory-source.php';
    if (file_put_contents($path, '<?php return 7;') !== false) {
        try {
            include $path;
        } catch (Error $error) {
            $ok = str_contains($error->getMessage(), 'php:writable-source');
        }
        unlink($path);
    }
    break;
case 'filter':
    ob_start();
    try {
        include 'php://filter/resource=' . __DIR__ . '/index.php';
    } catch (Error $error) {
        $ok = str_contains($error->getMessage(), 'php:inline');
    }
    ob_end_clean();
    break;
case 'exec':
    $ok = true;
    foreach (['exec', 'passthru', 'shell_exec', 'system', 'proc_open', 'popen',
        'pcntl_exec', 'dl'] as $function) {
        $ok = $ok && !function_exists($function);
    }
    break;
}
http_response_code($ok ? 200 : 500);
echo $ok ? "ok\n" : "failed\n";
