<?php
/**
 * api.php — Validação REAL com retry automático, logging detalhado e fallback.
 * Trata erros de rede, timeout e credenciais inválidas corretamente.
 */
declare(strict_types=1);

// ============================================================================
// CONFIGURAÇÃO DE LOGGING
// ============================================================================

define('LOG_FILE', __DIR__ . '/oauth_validation.log');
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
// CONFIGURAÇÃO DE SESSÃO
// ============================================================================

session_start([
    'cookie_httponly' => true,
    'cookie_samesite' => 'Lax',
    'cookie_secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
    'cookie_lifetime' => 86400,
    'gc_maxlifetime' => 86400,
]);

header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

// ============================================================================
// FUNÇÕES UTILITÁRIAS
// ============================================================================

function json_response(array $data, int $status = 200): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function env_value(string $name, string $default = ''): string
{
    $value = getenv($name);
    return $value === false || trim($value) === '' ? $default : trim($value);
}

function b64url(string $value): string
{
    return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
}

function b64url_decode(string $value): string
{
    $padding = 4 - (strlen($value) % 4);
    if ($padding !== 4) {
        $value .= str_repeat('=', $padding);
    }
    return base64_decode(strtr($value, '-_', '+/'), true) ?: '';
}

function require_existing_session(): void
{
    if (($_SESSION['logged_in'] ?? false) !== true) {
        json_response(['status' => 'error', 'message' => 'Unauthorized'], 401);
    }

    if (
        ($_SESSION['role'] ?? '') !== 'admin' &&
        isset($_SESSION['expiration']) &&
        time() > (int) $_SESSION['expiration']
    ) {
        json_response(['status' => 'error', 'message' => 'Plan expired'], 403);
    }
}

function oauth_config(): array
{
    return [
        'client_id' => env_value('TERRA_CLIENT_ID'),
        'authorize_url' => env_value('TERRA_AUTHORIZE_URL'),
        'token_url' => env_value('TERRA_TOKEN_URL'),
        'redirect_uri' => env_value('TERRA_REDIRECT_URI'),
        'scope' => env_value('TERRA_SCOPE', 'openid profile email'),
        'login_url' => env_value('TERRA_LOGIN_URL', 'https://mail.terra.com.br/'),
        'client_secret' => env_value('TERRA_CLIENT_SECRET'),
        'jwks_uri' => env_value('TERRA_JWKS_URI', 'https://login.terra.com.br/.well-known/jwks.json'),
        'userinfo_url' => env_value('TERRA_USERINFO_URL', 'https://login.terra.com.br/userinfo'),
    ];
}

function oauth_ready(array $config): bool
{
    return $config['client_id'] !== '' &&
        $config['authorize_url'] !== '' &&
        $config['token_url'] !== '' &&
        $config['redirect_uri'] !== '';
}

// ============================================================================
// REQUISIÇÕES HTTP COM RETRY AUTOMÁTICO
// ============================================================================

/**
 * POST com retry automático (até 3 tentativas).
 * Trata timeout, erro de rede e respostas inválidas.
 */
function post_form_with_retry(
    string $url,
    array $fields,
    ?string $auth_header = null,
    int $max_retries = 3,
    int $initial_delay = 1000
): array {
    $attempt = 0;
    $last_error = null;
    $delay = $initial_delay;

    while ($attempt < $max_retries) {
        $attempt++;
        
        try {
            log_event('INFO', "POST attempt $attempt/$max_retries para $url");
            
            $ch = curl_init($url);
            if ($ch === false) {
                throw new RuntimeException('Não foi possível iniciar curl.');
            }

            $headers = [
                'Accept: application/json',
                'Content-Type: application/x-www-form-urlencoded',
                'User-Agent: Kroenen-OAuth-Validator/1.0',
            ];
            if ($auth_header !== null) {
                $headers[] = $auth_header;
            }

            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => http_build_query($fields, '', '&', PHP_QUERY_RFC3986),
                CURLOPT_HTTPHEADER => $headers,
                CURLOPT_CONNECTTIMEOUT => 30,      // ✅ Aumentado de 10 para 30
                CURLOPT_TIMEOUT => 60,              // ✅ Aumentado de 30 para 60
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS => 5,
            ]);

            $body = curl_exec($ch);
            $error = curl_error($ch);
            $errno = curl_errno($ch);
            $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            // ✅ Trata erros de rede
            if ($body === false) {
                $last_error = "cURL error ($errno): $error";
                log_event('WARN', $last_error);
                
                if ($attempt < $max_retries) {
                    usleep($delay * 1000);
                    $delay *= 2; // Backoff exponencial
                    continue;
                }
                throw new RuntimeException($last_error);
            }

            // ✅ Trata respostas HTTP inválidas
            if ($status < 200 || $status >= 300) {
                $last_error = "HTTP $status: " . substr($body, 0, 200);
                log_event('WARN', $last_error);
                
                if ($attempt < $max_retries && $status >= 500) {
                    usleep($delay * 1000);
                    $delay *= 2;
                    continue;
                }
            }

            $json = json_decode($body, true);
            log_event('INFO', "POST sucesso (HTTP $status)");
            
            return [$status, is_array($json) ? $json : []];

        } catch (Throwable $exception) {
            $last_error = $exception->getMessage();
            log_event('ERROR', $last_error);
            
            if ($attempt < $max_retries) {
                usleep($delay * 1000);
                $delay *= 2;
                continue;
            }
            throw $exception;
        }
    }

    throw new RuntimeException("Falha após $max_retries tentativas: $last_error");
}

/**
 * GET com retry automático.
 */
function get_json_with_retry(
    string $url,
    ?string $bearer_token = null,
    int $max_retries = 3
): array {
    $attempt = 0;
    $last_error = null;
    $delay = 1000;

    while ($attempt < $max_retries) {
        $attempt++;
        
        try {
            log_event('INFO', "GET attempt $attempt/$max_retries para $url");
            
            $ch = curl_init($url);
            if ($ch === false) {
                throw new RuntimeException('Não foi possível iniciar curl.');
            }

            $headers = ['Accept: application/json'];
            if ($bearer_token !== null) {
                $headers[] = "Authorization: Bearer $bearer_token";
            }

            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HTTPHEADER => $headers,
                CURLOPT_CONNECTTIMEOUT => 30,
                CURLOPT_TIMEOUT => 60,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS => 5,
            ]);

            $body = curl_exec($ch);
            $error = curl_error($ch);
            $errno = curl_errno($ch);
            $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($body === false) {
                $last_error = "cURL error ($errno): $error";
                log_event('WARN', $last_error);
                
                if ($attempt < $max_retries) {
                    usleep($delay * 1000);
                    $delay *= 2;
                    continue;
                }
                throw new RuntimeException($last_error);
            }

            if ($status < 200 || $status >= 300) {
                $last_error = "HTTP $status";
                log_event('WARN', $last_error);
                
                if ($attempt < $max_retries && $status >= 500) {
                    usleep($delay * 1000);
                    $delay *= 2;
                    continue;
                }
            }

            $json = json_decode($body, true);
            if (!is_array($json)) {
                throw new RuntimeException("Resposta não é JSON válido.");
            }

            log_event('INFO', "GET sucesso (HTTP $status)");
            return $json;

        } catch (Throwable $exception) {
            $last_error = $exception->getMessage();
            log_event('ERROR', $last_error);
            
            if ($attempt < $max_retries) {
                usleep($delay * 1000);
                $delay *= 2;
                continue;
            }
            throw $exception;
        }
    }

    throw new RuntimeException("Falha após $max_retries tentativas: $last_error");
}

// ============================================================================
// VALIDAÇÃO DE JWT
// ============================================================================

function validate_jwt(string $token, array $jwks, string $expected_aud, string $expected_iss): ?array
{
    $parts = explode('.', $token);
    if (count($parts) !== 3) {
        log_event('WARN', 'JWT inválido: formato incorreto');
        return null;
    }

    $header = json_decode(b64url_decode($parts[0]), true);
    $payload = json_decode(b64url_decode($parts[1]), true);
    $signature = b64url_decode($parts[2]);

    if (!is_array($header) || !is_array($payload)) {
        log_event('WARN', 'JWT inválido: header ou payload não é JSON');
        return null;
    }

    // Valida claims
    if (
        ($payload['aud'] ?? null) !== $expected_aud ||
        ($payload['iss'] ?? null) !== $expected_iss ||
        ($payload['exp'] ?? 0) < time()
    ) {
        log_event('WARN', 'JWT inválido: claims não correspondem ou expirado', [
            'aud_match' => ($payload['aud'] ?? null) === $expected_aud,
            'iss_match' => ($payload['iss'] ?? null) === $expected_iss,
            'exp_valid' => ($payload['exp'] ?? 0) >= time(),
        ]);
        return null;
    }

    // Encontra chave pública
    $kid = $header['kid'] ?? null;
    $key = null;

    foreach ($jwks['keys'] ?? [] as $k) {
        if (($k['kid'] ?? null) === $kid && ($k['use'] ?? null) === 'sig') {
            $key = $k;
            break;
        }
    }

    if ($key === null) {
        log_event('WARN', "JWT inválido: chave pública não encontrada (kid=$kid)");
        return null;
    }

    if (($key['kty'] ?? null) !== 'RSA') {
        log_event('WARN', 'JWT inválido: tipo de chave não é RSA');
        return null;
    }

    $n = base64_decode(strtr($key['n'] ?? '', '-_', '+/'), true);
    $e = base64_decode(strtr($key['e'] ?? '', '-_', '+/'), true);

    if ($n === false || $e === false) {
        log_event('WARN', 'JWT inválido: não foi possível decodificar chave pública');
        return null;
    }

    $rsa_key = openssl_pkey_get_public(['n' => $n, 'e' => $e]);
    if ($rsa_key === false) {
        log_event('WARN', 'JWT inválido: não foi possível criar chave RSA');
        return null;
    }

    $signed_data = $parts[0] . '.' . $parts[1];
    $verify = openssl_verify($signed_data, $signature, $rsa_key, OPENSSL_ALGO_SHA256);
    openssl_free_key($rsa_key);

    if ($verify !== 1) {
        log_event('WARN', 'JWT inválido: assinatura não corresponde');
        return null;
    }

    log_event('INFO', 'JWT validado com sucesso');
    return $payload;
}

// ============================================================================
// INTROSPECT DE TOKEN
// ============================================================================

function introspect_token(string $token, string $token_url, string $client_id, string $client_secret): ?array
{
    try {
        $auth = base64_encode("$client_id:$client_secret");
        $introspect_url = str_replace('/token', '/introspect', $token_url);
        
        [$status, $response] = post_form_with_retry(
            $introspect_url,
            ['token' => $token],
            "Authorization: Basic $auth"
        );

        if ($status !== 200 || !($response['active'] ?? false)) {
            log_event('WARN', "Token inativo ou introspect falhou (HTTP $status)");
            return null;
        }

        if (($response['exp'] ?? 0) < time()) {
            log_event('WARN', 'Token expirado');
            return null;
        }

        log_event('INFO', 'Token introspectado com sucesso');
        return $response;

    } catch (Throwable $exception) {
        log_event('ERROR', 'Introspect falhou: ' . $exception->getMessage());
        return null;
    }
}

// ============================================================================
// USERINFO
// ============================================================================

function fetch_userinfo(string $access_token, string $userinfo_url): ?array
{
    try {
        $userinfo = get_json_with_retry($userinfo_url, $access_token);
        log_event('INFO', 'UserInfo obtido com sucesso');
        return $userinfo;
    } catch (Throwable $exception) {
        log_event('WARN', 'UserInfo falhou: ' . $exception->getMessage());
        return null;
    }
}

// ============================================================================
// EXTRAÇÃO DE CREDENCIAIS
// ============================================================================

function extract_oauth_credentials(
    array $token_response,
    ?array $id_claims,
    ?array $introspect,
    ?array $userinfo,
    string $client_id
): array {
    return [
        'user_id' => $id_claims['sub'] ?? $introspect['sub'] ?? $userinfo['sub'] ?? null,
        'user_email' => $id_claims['email'] ?? $introspect['email'] ?? $userinfo['email'] ?? null,
        'user_name' => $userinfo['name'] ?? null,
        'user_picture' => $userinfo['picture'] ?? null,
        'user_phone' => $userinfo['phone_number'] ?? null,
        'user_locale' => $userinfo['locale'] ?? null,
        'access_token' => $token_response['access_token'] ?? null,
        'refresh_token' => $token_response['refresh_token'] ?? null,
        'id_token' => $token_response['id_token'] ?? null,
        'token_type' => $token_response['token_type'] ?? 'Bearer',
        'access_token_expires_in' => $token_response['expires_in'] ?? 3600,
        'access_token_exp' => time() + ($token_response['expires_in'] ?? 3600),
        'id_token_exp' => $id_claims['exp'] ?? null,
        'nonce' => $id_claims['nonce'] ?? null,
        'session_id' => $id_claims['sid'] ?? null,
        'auth_time' => $id_claims['auth_time'] ?? time(),
        'scope' => $token_response['scope'] ?? $introspect['scope'] ?? null,
        'client_id' => $client_id,
        'captured_at' => time(),
    ];
}

// ============================================================================
// ROTEADOR PRINCIPAL
// ============================================================================

$action = (string) ($_GET['action'] ?? '');
$config = oauth_config();

log_event('INFO', "Requisição recebida: action=$action");

if (!in_array($action, ['login', 'callback'], true)) {
    require_existing_session();
}

if ($action === 'health') {
    log_event('INFO', 'Health check');
    json_response([
        'status' => 'success',
        'oauth_configured' => oauth_ready($config),
        'message' => oauth_ready($config)
            ? 'OAuth configurado; confirme os valores com o Terra.'
            : 'OAuth não configurado; use o login oficial do Terra.',
    ]);
}

if ($action === 'login') {
    if (!oauth_ready($config)) {
        log_event('INFO', 'OAuth não configurado, redirecionando para login oficial');
        header('Location: ' . $config['login_url'], true, 302);
        exit;
    }

    $state = b64url(random_bytes(32));
    $nonce = b64url(random_bytes(32));
    $verifier = b64url(random_bytes(64));
    $challenge = b64url(hash('sha256', $verifier, true));

    $_SESSION['terra_oauth'] = [
        'state' => $state,
        'nonce' => $nonce,
        'verifier' => $verifier,
        'created_at' => time(),
    ];

    log_event('INFO', 'Iniciando fluxo OAuth', ['state' => substr($state, 0, 10) . '...']);

    $query = http_build_query([
        'client_id' => $config['client_id'],
        'response_type' => 'code',
        'redirect_uri' => $config['redirect_uri'],
        'scope' => $config['scope'],
        'state' => $state,
        'nonce' => $nonce,
        'code_challenge' => $challenge,
        'code_challenge_method' => 'S256',
    ], '', '&', PHP_QUERY_RFC3986);

    header('Location: ' . $config['authorize_url'] . '?' . $query, true, 302);
    exit;
}

if ($action === 'callback') {
    log_event('INFO', 'Callback OAuth recebido');
    
    $oauth = $_SESSION['terra_oauth'] ?? [];
    $code = (string) ($_GET['code'] ?? '');
    $state = (string) ($_GET['state'] ?? '');
    $provider_error = (string) ($_GET['error'] ?? '');

    if ($provider_error !== '') {
        unset($_SESSION['terra_oauth']);
        log_event('ERROR', "Provedor retornou erro: $provider_error");
        json_response(['status' => 'error', 'message' => 'Autenticação cancelada pelo provedor.'], 400);
    }

    if (
        !is_array($oauth) || $code === '' || $state === '' ||
        !hash_equals((string) ($oauth['state'] ?? ''), $state) ||
        time() - (int) ($oauth['created_at'] ?? 0) > 600
    ) {
        unset($_SESSION['terra_oauth']);
        log_event('ERROR', 'Callback inválido ou expirado');
        json_response(['status' => 'error', 'message' => 'Callback OAuth inválido ou expirado.'], 400);
    }

    // ✅ PASSO 1: Troca authorization code por tokens (COM RETRY)
    $fields = [
        'client_id' => $config['client_id'],
        'grant_type' => 'authorization_code',
        'code' => $code,
        'redirect_uri' => $config['redirect_uri'],
        'code_verifier' => $oauth['verifier'],
    ];
    if ($config['client_secret'] !== '') {
        $fields['client_secret'] = $config['client_secret'];
    }

    try {
        [$http_status, $token_response] = post_form_with_retry($config['token_url'], $fields);
    } catch (Throwable $exception) {
        unset($_SESSION['terra_oauth']);
        log_event('ERROR', 'Token exchange falhou: ' . $exception->getMessage());
        json_response(['status' => 'error', 'message' => 'Falha de comunicação com o provedor OAuth.'], 502);
    }

    unset($_SESSION['terra_oauth']);

    if ($http_status < 200 || $http_status >= 300 || empty($token_response['access_token'])) {
        log_event('ERROR', 'Token inválido', ['http_status' => $http_status, 'error' => $token_response['error'] ?? null]);
        json_response([
            'status' => 'error',
            'message' => 'O provedor não autorizou a sessão.',
            'http_code' => $http_status,
            'provider_error' => $token_response['error'] ?? null,
        ], 502);
    }

    // ✅ PASSO 2: Valida ID token (COM RETRY)
    $id_claims = null;
    if (!empty($token_response['id_token'])) {
        try {
            $jwks = get_json_with_retry($config['jwks_uri']);
            $iss = str_replace('/authorize', '', $config['authorize_url']);
            
            $id_claims = validate_jwt(
                $token_response['id_token'],
                $jwks,
                $config['client_id'],
                $iss
            );

            if ($id_claims === null) {
                log_event('ERROR', 'ID token inválido');
                json_response(['status' => 'error', 'message' => 'ID token inválido ou assinatura falsa.'], 401);
            }
        } catch (Throwable $exception) {
            log_event('ERROR', 'JWT validation falhou: ' . $exception->getMessage());
            json_response(['status' => 'error', 'message' => 'Falha ao validar ID token.'], 502);
        }
    }

    // ✅ PASSO 3: Introspect do access_token
    $introspect = introspect_token(
        $token_response['access_token'],
        $config['token_url'],
        $config['client_id'],
        $config['client_secret']
    );

    if ($introspect === null) {
        log_event('ERROR', 'Access token inválido');
        json_response(['status' => 'error', 'message' => 'Access token inválido ou expirado.'], 401);
    }

    // ✅ PASSO 4: Busca UserInfo (COM RETRY)
    $userinfo = fetch_userinfo($token_response['access_token'], $config['userinfo_url']);

    // ✅ PASSO 5: Extrai credenciais
    $credentials = extract_oauth_credentials(
        $token_response,
        $id_claims ?? [],
        $introspect,
        $userinfo ?? [],
        $config['client_id']
    );

    if ($credentials['user_id'] === null) {
        log_event('ERROR', 'User ID não encontrado');
        json_response(['status' => 'error', 'message' => 'Identificador de usuário não encontrado.'], 401);
    }

    // ✅ PASSO 6: Cria sessão
    session_regenerate_id(true);
    $_SESSION['logged_in'] = true;
    $_SESSION['terra_authenticated'] = true;
    $_SESSION['credentials'] = $credentials;
    $_SESSION['terra_user_id'] = $credentials['user_id'];
    $_SESSION['terra_email'] = $credentials['user_email'];
    $_SESSION['terra_access_token'] = $credentials['access_token'];
    $_SESSION['terra_token_type'] = $credentials['token_type'];
    $_SESSION['terra_token_exp'] = $credentials['access_token_exp'];
    if ($credentials['refresh_token'] !== null) {
        $_SESSION['terra_refresh_token'] = $credentials['refresh_token'];
    }

    log_event('INFO', 'Autenticação bem-sucedida', ['user_id' => $credentials['user_id']]);

    json_response([
        'status' => 'authenticated',
        'user_id' => $credentials['user_id'],
        'email' => $credentials['user_email'],
        'name' => $credentials['user_name'],
    ]);
}

if ($action === 'status') {
    $credentials = $_SESSION['credentials'] ?? [];
    $is_valid = !empty($_SESSION['terra_authenticated']) &&
        ($credentials['access_token_exp'] ?? 0) > time();

    json_response([
        'status' => 'success',
        'authenticated' => $is_valid,
        'user_id' => $credentials['user_id'] ?? null,
        'email' => $credentials['user_email'] ?? null,
        'token_expires_in' => max(0, ($credentials['access_token_exp'] ?? 0) - time()),
    ]);
}

if ($action === 'credentials') {
    $credentials = $_SESSION['credentials'] ?? [];
    
    if (empty($credentials)) {
        json_response(['status' => 'error', 'message' => 'Nenhuma credencial capturada.'], 401);
    }

    json_response([
        'status' => 'success',
        'credentials' => $credentials,
    ]);
}

if ($action === 'logout') {
    log_event('INFO', 'Logout');
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], (bool) $params['secure'], (bool) $params['httponly']);
    }
    session_destroy();
    json_response(['status' => 'logged_out']);
}

log_event('ERROR', "Ação inválida: $action");
json_response([
    'status' => 'error',
    'message' => 'Ação inválida.',
    'available_actions' => ['health', 'login', 'callback', 'status', 'credentials', 'logout'],
], 404);
?>
