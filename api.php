<?php
/**
 * terra_validator_secure_v2.php
 * Validador IMAP com Retry Inteligente, Backoff Exponencial e Diagnóstico Real
 * Data: 31 de julho de 2026
 */
declare(strict_types=1);

session_start([
    'cookie_httponly' => true,
    'cookie_samesite' => 'Lax',
    'cookie_secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
]);

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Access-Control-Allow-Origin: https://seu-dominio-seguro.com.br');
header('Access-Control-Allow-Methods: POST');

// ============================================================================
// CONFIGURAÇÕES CRÍTICAS
// ============================================================================

define('IMAP_SERVER', '{imap.terra.com.br:993/imap/ssl}');
define('IMAP_TIMEOUT', 15);           // Aumentado de 10 para 15 segundos
define('MAX_RETRIES', 3);             // Número de tentativas
define('INITIAL_BACKOFF', 1);         // 1 segundo inicial
define('MAX_BACKOFF', 8);             // Máximo 8 segundos
define('RATE_LIMIT_PER_MIN', 3);      // 3 requisições por minuto (não 5)
define('CA_BUNDLE_PATH', '/etc/ssl/certs/ca-certificates.crt'); // Linux/Docker

// ============================================================================
// FUNÇÕES AUXILIARES
// ============================================================================

function validate_email(string $email): bool
{
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false &&
           preg_match('/@terra\.com\.br$/i', $email);
}

function check_rate_limit(): bool
{
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }

    $now = time();
    if (!isset($_SESSION['attempts'])) {
        $_SESSION['attempts'] = [];
    }

    $_SESSION['attempts'] = array_filter($_SESSION['attempts'], function($ts) use ($now) {
        return ($now - $ts) < 60;
    });

    if (count($_SESSION['attempts']) >= RATE_LIMIT_PER_MIN) {
        return false;
    }

    $_SESSION['attempts'][] = $now;
    return true;
}

function log_event(string $email, string $status, string $message, ?int $retry_count = null): void
{
    $timestamp = date('Y-m-d H:i:s');
    $retry_info = $retry_count !== null ? " [RETRY: $retry_count]" : '';
    $log_entry = "[$timestamp] EMAIL: $email | STATUS: $status | MSG: $message$retry_info" . PHP_EOL;
    error_log($log_entry, 3, 'auth_audit.log');
}

/**
 * Valida a conectividade SSL/TLS do servidor IMAP
 */
function test_ssl_connectivity(string $host = 'imap.terra.com.br', int $port = 993): array
{
    $context = stream_context_create([
        'ssl' => [
            'verify_peer' => true,
            'verify_peer_name' => true,
            'allow_self_signed' => false,
            'cafile' => CA_BUNDLE_PATH,
        ]
    ]);

    $errno = 0;
    $errstr = '';
    $timeout = 10;

    $socket = @stream_socket_client(
        "ssl://$host:$port",
        $errno,
        $errstr,
        $timeout,
        STREAM_CLIENT_CONNECT,
        $context
    );

    if ($socket === false) {
        return [
            'status' => 'error',
            'message' => "SSL Connection Failed: $errstr (errno: $errno)",
            'error_code' => 'SSL_HANDSHAKE_FAILED'
        ];
    }

    fclose($socket);
    return [
        'status' => 'success',
        'message' => 'SSL/TLS handshake successful',
        'error_code' => null
    ];
}

/**
 * Tenta autenticação IMAP com retry exponencial
 */
function authenticate_imap_with_retry(
    string $email,
    string $password,
    int $max_retries = MAX_RETRIES
): array
{
    $attempt = 0;
    $last_error = null;
    $backoff = INITIAL_BACKOFF;

    while ($attempt < $max_retries) {
        $attempt++;

        // Aguarda antes de tentar (exceto na primeira tentativa)
        if ($attempt > 1) {
            sleep($backoff);
            $backoff = min($backoff * 2, MAX_BACKOFF); // Exponencial até MAX_BACKOFF
        }

        // Define timeouts globais para IMAP
        if (function_exists('imap_timeout')) {
            imap_timeout(IMAP_OPENTIMEOUT, IMAP_TIMEOUT);
            imap_timeout(IMAP_READTIMEOUT, IMAP_TIMEOUT);
            imap_timeout(IMAP_WRITETIMEOUT, IMAP_TIMEOUT);
            imap_timeout(IMAP_CLOSETIMEOUT, IMAP_TIMEOUT);
        }

        // Tenta abrir conexão IMAP
        $mbox = @imap_open(
            IMAP_SERVER . 'INBOX',
            $email,
            $password,
            OP_HALFOPEN,
            1
        );

        if ($mbox !== false) {
            imap_close($mbox);
            return [
                'status' => 'live',
                'message' => 'Credencial válida',
                'error_code' => null,
                'attempts' => $attempt,
                'response_time_ms' => 0
            ];
        }

        // Captura erro específico
        $imap_error = imap_last_error() ?: 'Unknown IMAP error';
        $last_error = $imap_error;

        // Determina se deve fazer retry
        $should_retry = false;
        $error_code = 'AUTH_FAILED';

        if (stripos($imap_error, 'Timed out') !== false) {
            $error_code = 'TIMEOUT';
            $should_retry = $attempt < $max_retries;
        } elseif (stripos($imap_error, 'Connection refused') !== false) {
            $error_code = 'CONNECTION_REFUSED';
            $should_retry = $attempt < $max_retries;
        } elseif (stripos($imap_error, 'Certificate failure') !== false) {
            $error_code = 'SSL_CERT_ERROR';
            $should_retry = false; // Não faz retry em erro de certificado
        } elseif (
            stripos($imap_error, 'Authentication failed') !== false ||
            stripos($imap_error, 'invalid user or password') !== false ||
            stripos($imap_error, 'LOGIN failed') !== false
        ) {
            $error_code = 'AUTH_FAILED';
            $should_retry = false; // Não faz retry em falha de autenticação
        }

        if (!$should_retry) {
            break;
        }

        log_event($email, 'retry', "Tentativa $attempt/$max_retries falhou: $imap_error", $attempt);
    }

    // Determina o código de erro final
    $final_error_code = 'AUTH_FAILED';
    if (stripos($last_error, 'Timed out') !== false) {
        $final_error_code = 'TIMEOUT';
    } elseif (stripos($last_error, 'Connection refused') !== false) {
        $final_error_code = 'CONNECTION_REFUSED';
    } elseif (stripos($last_error, 'Certificate failure') !== false) {
        $final_error_code = 'SSL_CERT_ERROR';
    }

    return [
        'status' => 'die',
        'message' => "Credencial inválida ou servidor indisponível: $last_error",
        'error_code' => $final_error_code,
        'attempts' => $attempt,
        'response_time_ms' => 0
    ];
}

/**
 * Valida credencial com diagnóstico completo
 */
function validate_credential(string $email, string $password): array
{
    $start_time = microtime(true);

    // Validação de email
    if (!validate_email($email)) {
        return [
            'email' => $email,
            'result' => 'error',
            'message' => 'Formato de e-mail inválido ou não é @terra.com.br',
            'error_code' => 'INVALID_EMAIL',
            'time_ms' => 0,
            'diagnostic' => null
        ];
    }

    // Validação de rate limit
    if (!check_rate_limit()) {
        return [
            'email' => $email,
            'result' => 'error',
            'message' => 'Limite de tentativas excedido. Aguarde 1 minuto.',
            'error_code' => 'RATE_LIMITED',
            'time_ms' => 0,
            'diagnostic' => null
        ];
    }

    // Teste de conectividade SSL (diagnóstico)
    $ssl_test = test_ssl_connectivity();
    $diagnostic = $ssl_test;

    if ($ssl_test['status'] === 'error') {
        log_event($email, 'error', $ssl_test['message']);
        return [
            'email' => $email,
            'result' => 'error',
            'message' => $ssl_test['message'],
            'error_code' => $ssl_test['error_code'],
            'time_ms' => round((microtime(true) - $start_time) * 1000),
            'diagnostic' => $diagnostic
        ];
    }

    // Autenticação com retry
    $auth_result = authenticate_imap_with_retry($email, $password);

    $end_time = microtime(true);
    $duration_ms = round(($end_time - $start_time) * 1000);

    log_event($email, $auth_result['status'], $auth_result['message'], $auth_result['attempts']);

    return [
        'email' => $email,
        'result' => $auth_result['status'],
        'message' => $auth_result['message'],
        'error_code' => $auth_result['error_code'],
        'time_ms' => $duration_ms,
        'attempts' => $auth_result['attempts'],
        'diagnostic' => $diagnostic
    ];
}

// ============================================================================
// PROCESSAMENTO DA REQUISIÇÃO
// ============================================================================

$input = json_decode(file_get_contents('php://input'), true) ?? $_POST;
$email = trim((string)($input['email'] ?? ''));
$password = (string)($input['password'] ?? '');

if (empty($email) || empty($password)) {
    http_response_code(400);
    echo json_encode([
        'status' => 'error',
        'message' => 'Email e senha são obrigatórios',
        'error_code' => 'MISSING_FIELDS'
    ]);
    exit;
}

$result = validate_credential($email, $password);

http_response_code($result['result'] === 'error' ? 400 : 200);
echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
exit;
?>
