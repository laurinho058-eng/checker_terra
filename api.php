<?php
/**
 * api.php — Captura DINÂMICA de IDs, tokens e keys do handshake OAuth real.
 * Valida cada credencial e extrai identificadores do provedor.
 */
declare(strict_types=1);

session_start([
    'cookie_httponly' => true,
    'cookie_samesite' => 'Lax',
    'cookie_secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
]);

header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

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

function post_form(string $url, array $fields, ?string $auth_header = null): array
{
    $ch = curl_init($url);
    if ($ch === false) {
        throw new RuntimeException('Não foi possível iniciar a comunicação HTTPS.');
    }

    $headers = ['Accept: application/json', 'Content-Type: application/x-www-form-urlencoded'];
    if ($auth_header !== null) {
        $headers[] = $auth_header;
    }

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query($fields, '', '&', PHP_QUERY_RFC3986),
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
    ]);

    $body = curl_exec($ch);
    $error = curl_error($ch);
    $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($body === false) {
        throw new RuntimeException($error !== '' ? $error : 'Falha na comunicação com o provedor.');
    }

    $json = json_decode($body, true);
    return [$status, is_array($json) ? $json : []];
}

function get_json(string $url, ?string $bearer_token = null): array
{
    $ch = curl_init($url);
    if ($ch === false) {
        throw new RuntimeException('Não foi possível iniciar a comunicação HTTPS.');
    }

    $headers = ['Accept: application/json'];
    if ($bearer_token !== null) {
        $headers[] = "Authorization: Bearer $bearer_token";
    }

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
    ]);

    $body = curl_exec($ch);
    $error = curl_error($ch);
    $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($body === false) {
        throw new RuntimeException($error !== '' ? $error : 'Falha ao buscar dados.');
    }

    $json = json_decode($body, true);
    if ($status < 200 || $status >= 300 || !is_array($json)) {
        throw new RuntimeException("Resposta inválida (HTTP $status).");
    }

    return $json;
}

/**
 * Valida a assinatura JWT usando JWKS do provedor.
 * Retorna os claims decodificados se válido.
 */
function validate_jwt(string $token, array $jwks, string $expected_aud, string $expected_iss): ?array
{
    $parts = explode('.', $token);
    if (count($parts) !== 3) {
        return null;
    }

    $header = json_decode(b64url_decode($parts[0]), true);
    $payload = json_decode(b64url_decode($parts[1]), true);
    $signature = b64url_decode($parts[2]);

    if (!is_array($header) || !is_array($payload)) {
        return null;
    }

    // Valida claims obrigatórios
    if (
        ($payload['aud'] ?? null) !== $expected_aud ||
        ($payload['iss'] ?? null) !== $expected_iss ||
        ($payload['exp'] ?? 0) < time()
    ) {
        return null;
    }

    // Encontra a chave pública correspondente
    $kid = $header['kid'] ?? null;
    $key = null;

    foreach ($jwks['keys'] ?? [] as $k) {
        if (($k['kid'] ?? null) === $kid && ($k['use'] ?? null) === 'sig') {
            $key = $k;
            break;
        }
    }

    if ($key === null) {
        return null;
    }

    // Reconstrói a chave pública a partir de JWK (RSA)
    if (($key['kty'] ?? null) !== 'RSA') {
        return null;
    }

    $n = base64_decode(strtr($key['n'] ?? '', '-_', '+/'), true);
    $e = base64_decode(strtr($key['e'] ?? '', '-_', '+/'), true);

    if ($n === false || $e === false) {
        return null;
    }

    $rsa_key = openssl_pkey_get_public([
        'n' => $n,
        'e' => $e,
    ]);

    if ($rsa_key === false) {
        return null;
    }

    $signed_data = $parts[0] . '.' . $parts[1];
    $verify = openssl_verify($signed_data, $signature, $rsa_key, OPENSSL_ALGO_SHA256);
    openssl_free_key($rsa_key);

    if ($verify !== 1) {
        return null;
    }

    return $payload;
}

/**
 * Introspect do access_token no provedor.
 * Retorna os claims se válido.
 */
function introspect_token(string $token, string $token_url, string $client_id, string $client_secret): ?array
{
    try {
        $auth = base64_encode("$client_id:$client_secret");
        [$status, $response] = post_form(
            str_replace('/token', '/introspect', $token_url),
            ['token' => $token],
            "Authorization: Basic $auth"
        );

        if ($status !== 200 || !($response['active'] ?? false)) {
            return null;
        }

        if (($response['exp'] ?? 0) < time()) {
            return null;
        }

        return $response;
    } catch (Throwable) {
        return null;
    }
}

/**
 * Busca informações do usuário via UserInfo endpoint.
 * Captura dinamicamente: email, name, picture, phone, etc.
 */
function fetch_userinfo(string $access_token, string $userinfo_url): ?array
{
    try {
        return get_json($userinfo_url, $access_token);
    } catch (Throwable) {
        return null;
    }
}

/**
 * Extrai e valida credenciais do handshake OAuth.
 * Retorna array com todos os IDs, tokens e keys capturados.
 */
function extract_oauth_credentials(
    array $token_response,
    array $id_claims,
    ?array $introspect,
    ?array $userinfo,
    string $client_id
): array
{
    return [
        // IDs do usuário
        'user_id' => $id_claims['sub'] ?? $introspect['sub'] ?? $userinfo['sub'] ?? null,
        'user_email' => $id_claims['email'] ?? $introspect['email'] ?? $userinfo['email'] ?? null,
        'user_name' => $userinfo['name'] ?? null,
        'user_picture' => $userinfo['picture'] ?? null,
        'user_phone' => $userinfo['phone_number'] ?? null,
        'user_locale' => $userinfo['locale'] ?? null,

        // Tokens capturados
        'access_token' => $token_response['access_token'] ?? null,
        'refresh_token' => $token_response['refresh_token'] ?? null,
        'id_token' => $token_response['id_token'] ?? null,
        'token_type' => $token_response['token_type'] ?? 'Bearer',

        // Metadados de expiração
        'access_token_expires_in' => $token_response['expires_in'] ?? 3600,
        'access_token_exp' => time() + ($token_response['expires_in'] ?? 3600),
        'id_token_exp' => $id_claims['exp'] ?? null,
        'refresh_token_exp' => $introspect['refresh_token_exp'] ?? null,

        // IDs de sessão/nonce
        'nonce' => $id_claims['nonce'] ?? null,
        'session_id' => $id_claims['sid'] ?? null,
        'auth_time' => $id_claims['auth_time'] ?? time(),

        // Escopos aprovados
        'scope' => $token_response['scope'] ?? $introspect['scope'] ?? null,

        // Client ID (para auditoria)
        'client_id' => $client_id,

        // Timestamp de captura
        'captured_at' => time(),
    ];
}

$action = (string) ($_GET['action'] ?? '');
$config = oauth_config();

if (!in_array($action, ['login', 'callback'], true)) {
    require_existing_session();
}

if ($action === 'health') {
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
    $oauth = $_SESSION['terra_oauth'] ?? [];
    $code = (string) ($_GET['code'] ?? '');
    $state = (string) ($_GET['state'] ?? '');
    $provider_error = (string) ($_GET['error'] ?? '');

    if ($provider_error !== '') {
        unset($_SESSION['terra_oauth']);
        json_response(['status' => 'error', 'message' => 'Autenticação cancelada pelo provedor.'], 400);
    }

    if (
        !is_array($oauth) || $code === '' || $state === '' ||
        !hash_equals((string) ($oauth['state'] ?? ''), $state) ||
        time() - (int) ($oauth['created_at'] ?? 0) > 600
    ) {
        unset($_SESSION['terra_oauth']);
        json_response(['status' => 'error', 'message' => 'Callback OAuth inválido ou expirado.'], 400);
    }

    // ✅ PASSO 1: Troca o authorization code por tokens
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
        [$http_status, $token_response] = post_form($config['token_url'], $fields);
    } catch (Throwable $exception) {
        unset($_SESSION['terra_oauth']);
        error_log('OAuth Terra: ' . $exception->getMessage());
        json_response(['status' => 'error', 'message' => 'Falha de comunicação com o provedor OAuth.'], 502);
    }

    unset($_SESSION['terra_oauth']);

    if ($http_status < 200 || $http_status >= 300 || empty($token_response['access_token'])) {
        json_response([
            'status' => 'error',
            'message' => 'O provedor não autorizou a sessão.',
            'http_code' => $http_status,
            'provider_error' => $token_response['error'] ?? null,
        ], 502);
    }

    // ✅ PASSO 2: Valida ID token (JWT) se presente
    $id_claims = null;
    if (!empty($token_response['id_token'])) {
        try {
            $jwks = get_json($config['jwks_uri']);
            $iss = str_replace('/authorize', '', $config['authorize_url']);
            
            $id_claims = validate_jwt(
                $token_response['id_token'],
                $jwks,
                $config['client_id'],
                $iss
            );

            if ($id_claims === null) {
                json_response(['status' => 'error', 'message' => 'ID token inválido ou assinatura falsa.'], 401);
            }
        } catch (Throwable $exception) {
            error_log('JWT validation: ' . $exception->getMessage());
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
        json_response(['status' => 'error', 'message' => 'Access token inválido ou expirado.'], 401);
    }

    // ✅ PASSO 4: Busca UserInfo para capturar dados adicionais
    $userinfo = fetch_userinfo($token_response['access_token'], $config['userinfo_url']);

    // ✅ PASSO 5: Extrai e valida TODAS as credenciais capturadas
    $credentials = extract_oauth_credentials(
        $token_response,
        $id_claims ?? [],
        $introspect,
        $userinfo ?? [],
        $config['client_id']
    );

    // Valida que temos pelo menos um user_id
    if ($credentials['user_id'] === null) {
        json_response(['status' => 'error', 'message' => 'Identificador de usuário não encontrado.'], 401);
    }

    // ✅ PASSO 6: Cria sessão com TODAS as credenciais capturadas
    session_regenerate_id(true);
    $_SESSION['logged_in'] = true;
    $_SESSION['terra_authenticated'] = true;
    
    // Armazena credenciais capturadas dinamicamente
    $_SESSION['credentials'] = $credentials;
    
    // Aliases para compatibilidade
    $_SESSION['terra_user_id'] = $credentials['user_id'];
    $_SESSION['terra_email'] = $credentials['user_email'];
    $_SESSION['terra_access_token'] = $credentials['access_token'];
    $_SESSION['terra_token_type'] = $credentials['token_type'];
    $_SESSION['terra_token_exp'] = $credentials['access_token_exp'];
    if ($credentials['refresh_token'] !== null) {
        $_SESSION['terra_refresh_token'] = $credentials['refresh_token'];
    }

    json_response([
        'status' => 'authenticated',
        'user_id' => $credentials['user_id'],
        'email' => $credentials['user_email'],
        'name' => $credentials['user_name'],
        'credentials_captured' => array_keys($credentials),
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
        'name' => $credentials['user_name'] ?? null,
        'token_expires_in' => max(0, ($credentials['access_token_exp'] ?? 0) - time()),
        'scope' => $credentials['scope'] ?? null,
        'auth_time' => $credentials['auth_time'] ?? null,
    ]);
}

if ($action === 'credentials') {
    // Endpoint para auditoria: retorna TODAS as credenciais capturadas
    $credentials = $_SESSION['credentials'] ?? [];
    
    if (empty($credentials)) {
        json_response(['status' => 'error', 'message' => 'Nenhuma credencial capturada.'], 401);
    }

    json_response([
        'status' => 'success',
        'credentials' => [
            'user' => [
                'id' => $credentials['user_id'],
                'email' => $credentials['user_email'],
                'name' => $credentials['user_name'],
                'picture' => $credentials['user_picture'],
                'phone' => $credentials['user_phone'],
                'locale' => $credentials['user_locale'],
            ],
            'tokens' => [
                'access_token' => substr($credentials['access_token'], 0, 20) . '...',
                'refresh_token' => $credentials['refresh_token'] ? substr($credentials['refresh_token'], 0, 20) . '...' : null,
                'id_token' => $credentials['id_token'] ? substr($credentials['id_token'], 0, 20) . '...' : null,
                'token_type' => $credentials['token_type'],
            ],
            'expiration' => [
                'access_token_expires_in' => $credentials['access_token_expires_in'],
                'access_token_exp' => $credentials['access_token_exp'],
                'id_token_exp' => $credentials['id_token_exp'],
            ],
            'session' => [
                'nonce' => $credentials['nonce'],
                'session_id' => $credentials['session_id'],
                'auth_time' => $credentials['auth_time'],
                'scope' => $credentials['scope'],
                'client_id' => $credentials['client_id'],
                'captured_at' => $credentials['captured_at'],
            ],
        ],
    ]);
}

if ($action === 'logout') {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], (bool) $params['secure'], (bool) $params['httponly']);
    }
    session_destroy();
    json_response(['status' => 'logged_out']);
}

json_response([
    'status' => 'error',
    'message' => 'Ação inválida.',
    'available_actions' => ['health', 'login', 'callback', 'status', 'credentials', 'logout'],
], 404);
?>
