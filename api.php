<?php
// api.php - Endpoint seguro de autenticação OAuth 2.0 com PKCE

declare(strict_types=1);

session_start([
    'cookie_httponly' => true,
    'cookie_secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
    'cookie_samesite' => 'Lax',
]);

header('Cache-Control: no-store');
header('Pragma: no-cache');

function jsonResponse(array $payload, int $status = 200): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function oauthConfig(): array
{
    $config = [
        'client_id' => getenv('TERRA_CLIENT_ID') ?: '',
        'authorize_url' => getenv('TERRA_AUTHORIZE_URL') ?: '',
        'token_url' => getenv('TERRA_TOKEN_URL') ?: '',
        'scope' => getenv('TERRA_SCOPE') ?: 'openid profile email offline_access',
        'redirect_uri' => getenv('TERRA_REDIRECT_URI') ?: '',
    ];

    foreach (['client_id', 'authorize_url', 'token_url', 'redirect_uri'] as $key) {
        if ($config[$key] === '') {
            jsonResponse([
                'status' => 'error',
                'message' => 'Configuração OAuth incompleta',
            ], 500);
        }
    }

    foreach (['authorize_url', 'token_url'] as $key) {
        $scheme = parse_url($config[$key], PHP_URL_SCHEME);
        if ($scheme !== 'https') {
            jsonResponse([
                'status' => 'error',
                'message' => 'Os endpoints OAuth devem usar HTTPS',
            ], 500);
        }
    }

    return $config;
}

function base64UrlEncode(string $value): string
{
    return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
}

function requireAppSession(): void
{
    if (($_SESSION['logged_in'] ?? false) !== true) {
        jsonResponse(['status' => 'error', 'message' => 'Unauthorized'], 401);
    }

    if (($_SESSION['role'] ?? '') !== 'admin'
        && isset($_SESSION['expiration'])
        && time() > (int) $_SESSION['expiration']) {
        jsonResponse(['status' => 'error', 'message' => 'Plan expired'], 403);
    }
}

$config = oauthConfig();
$action = $_GET['action'] ?? '';

// Inicia o login no provedor OAuth. Nenhuma senha é recebida pelo servidor.
if ($action === 'login') {
    $state = bin2hex(random_bytes(32));
    $nonce = bin2hex(random_bytes(32));
    $codeVerifier = base64UrlEncode(random_bytes(64));
    $codeChallenge = base64UrlEncode(hash('sha256', $codeVerifier, true));

    $_SESSION['oauth_state'] = $state;
    $_SESSION['oauth_nonce'] = $nonce;
    $_SESSION['oauth_code_verifier'] = $codeVerifier;
    $_SESSION['oauth_started_at'] = time();

    $query = http_build_query([
        'client_id' => $config['client_id'],
        'response_type' => 'code',
        'redirect_uri' => $config['redirect_uri'],
        'scope' => $config['scope'],
        'state' => $state,
        'nonce' => $nonce,
        'code_challenge' => $codeChallenge,
        'code_challenge_method' => 'S256',
    ], '', '&', PHP_QUERY_RFC3986);

    header('Location: ' . $config['authorize_url'] . '?' . $query, true, 302);
    exit;
}

// Recebe o callback e troca o código por tokens usando PKCE.
if ($action === 'callback') {
    $code = (string) ($_GET['code'] ?? '');
    $returnedState = (string) ($_GET['state'] ?? '');
    $expectedState = (string) ($_SESSION['oauth_state'] ?? '');
    $startedAt = (int) ($_SESSION['oauth_started_at'] ?? 0);
    $codeVerifier = (string) ($_SESSION['oauth_code_verifier'] ?? '');

    if ($code === '' || $returnedState === '' || $expectedState === '' || $codeVerifier === '') {
        jsonResponse(['status' => 'error', 'message' => 'Callback OAuth inválido'], 400);
    }

    if ($startedAt === 0 || time() - $startedAt > 600) {
        jsonResponse(['status' => 'error', 'message' => 'Callback OAuth expirado'], 400);
    }

    if (!hash_equals($expectedState, $returnedState)) {
        jsonResponse(['status' => 'error', 'message' => 'Falha na validação do state OAuth'], 400);
    }

    if (isset($_GET['error'])) {
        $error = preg_replace('/[^a-zA-Z0-9._-]/', '', (string) $_GET['error']);
        unset($_SESSION['oauth_state'], $_SESSION['oauth_nonce'], $_SESSION['oauth_code_verifier'], $_SESSION['oauth_started_at']);
        jsonResponse(['status' => 'error', 'message' => 'Autorização recusada', 'provider_error' => $error], 400);
    }

    $ch = curl_init($config['token_url']);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_HTTPHEADER => [
            'Accept: application/json',
            'Content-Type: application/x-www-form-urlencoded',
        ],
        CURLOPT_POSTFIELDS => http_build_query([
            'client_id' => $config['client_id'],
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $config['redirect_uri'],
            'code_verifier' => $codeVerifier,
        ], '', '&', PHP_QUERY_RFC3986),
    ]);

    $response = curl_exec($ch);
    $curlError = curl_error($ch);
    $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    unset($_SESSION['oauth_state'], $_SESSION['oauth_nonce'], $_SESSION['oauth_code_verifier'], $_SESSION['oauth_started_at']);

    if ($response === false || $curlError !== '') {
        jsonResponse(['status' => 'error', 'message' => 'Falha de comunicação com o provedor OAuth'], 502);
    }

    $tokens = json_decode($response, true);
    if (!is_array($tokens) || $httpCode < 200 || $httpCode >= 300 || empty($tokens['access_token'])) {
        jsonResponse(['status' => 'error', 'message' => 'Falha ao obter token OAuth'], 502);
    }

    // O nonce deve ser validado contra o claim nonce do id_token quando o
    // provedor retornar um JWT. A validação deve usar as chaves oficiais do
    // provedor; não aceite apenas um JWT decodificado sem verificar assinatura.
    $_SESSION['oauth_token'] = [
        'access_token' => $tokens['access_token'],
        'token_type' => $tokens['token_type'] ?? 'Bearer',
        'expires_at' => time() + (int) ($tokens['expires_in'] ?? 3600),
        'scope' => $tokens['scope'] ?? $config['scope'],
    ];

    jsonResponse(['status' => 'authenticated']);
}

if ($action === 'logout') {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], (bool) $params['secure'], (bool) $params['httponly']);
    }
    session_destroy();
    jsonResponse(['status' => 'logged_out']);
}

if ($action === 'status') {
    requireAppSession();
    $token = $_SESSION['oauth_token'] ?? null;
    jsonResponse([
        'status' => 'authenticated',
        'token_available' => is_array($token) && !empty($token['access_token']),
        'expires_at' => is_array($token) ? ($token['expires_at'] ?? null) : null,
    ]);
}

jsonResponse([
    'status' => 'error',
    'message' => 'Ação inválida',
], 404);
?>
