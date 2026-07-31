<?php
/**
 * terra_validator_secure.php — VALIDAÇÃO REAL COM RETRY AUTOMÁTICO
 * Implementação corrigida para validar credenciais IMAP de forma real
 * Data: 31 de julho de 2026
 */

declare(strict_types=1);

// ============================================================================
// CONFIGURAÇÃO DE LOGGING
// ============================================================================
define('LOG_FILE', __DIR__ . '/validator_audit.log');
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
define('CONNECT_TIMEOUT', 30);      // ✅ Aumentado de 10 para 30
define('TOTAL_TIMEOUT', 60);        // ✅ Aumentado de 30 para 60
define('MAX_RETRIES', 3);           // ✅ Retry automático

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

    // Remove tentativas com mais de 60 segundos
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
 * Tenta conexão IMAP com retry automático
 */
function validate_imap_credentials(string $email, string $password, int $attempt = 1): array
{
    $start_time = microtime(true);

    try {
        // ✅ Define timeout global para funções imap
        if (function_exists('imap_timeout')) {
            imap_timeout(IMAP_OPENTIMEOUT, CONNECT_TIMEOUT);
            imap_timeout(IMAP_READTIMEOUT, CONNECT_TIMEOUT);
        }

        log_event('INFO', "Tentativa $attempt/" . MAX_RETRIES . " de conexão IMAP para $email");

        // ✅ Tenta abrir conexão IMAP
        $mbox = @imap_open(IMAP_SERVER, $email, $password, OP_HALFOPEN, 1);

        if ($mbox) {
            // ✅ Conexão bem-sucedida
            $mailbox_info = @imap_mailboxmsginfo($mbox);
            @imap_close($mbox);

            $duration_ms = round((microtime(true) - $start_time) * 1000);
            log_event('INFO', "Credencial VÁLIDA para $email (${duration_ms}ms)");

            return [
                'email' => $email,
                'result' => 'live',
                'message' => 'Credencial válida',
                'time_ms' => $duration_ms,
                'error_code' => null,
                'mailbox_info' => $mailbox_info ? [
                    'messages' => $mailbox_info->Nmsgs ?? 0,
                    'recent' => $mailbox_info->Recent ?? 0,
                    'unread' => $mailbox_info->Unread ?? 0,
                ] : null,
            ];
        }

        // ✅ Falha na conexão — analisa erro
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
            // ✅ Timeout — tenta novamente
            if ($attempt < MAX_RETRIES) {
                log_event('WARN', "Timeout na tentativa $attempt, retentando...");
                sleep(2 * $attempt); // Backoff exponencial
                return validate_imap_credentials($email, $password, $attempt + 1);
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
            // ✅ Erro de rede — tenta novamente
            if ($attempt < MAX_RETRIES) {
                log_event('WARN', "Erro de rede na tentativa $attempt, retentando...");
                sleep(2 * $attempt);
                return validate_imap_credentials($email, $password, $attempt + 1);
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
            return validate_imap_credentials($email, $password, $attempt + 1);
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
    ];
}

// ============================================================================
// PROCESSAMENTO DA REQUISIÇÃO
// ============================================================================

$input = json_decode(file_get_contents('php://input'), true) ?? $_POST;

$email = trim((string)($input['email'] ?? ''));
$password = (string)($input['password'] ?? '');

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

// ✅ Valida credenciais com retry automático
$result = validate_imap_credentials($email, $password);

// ✅ Log do resultado
log_event($result['result'] === 'live' ? 'INFO' : 'WARN', "Resultado: {$result['result']}", [
    'email' => $email,
    'time_ms' => $result['time_ms'],
    'error_code' => $result['error_code'],
]);

// ✅ Resposta final
http_response_code($result['result'] === 'error' ? 400 : 200);
echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
?>
