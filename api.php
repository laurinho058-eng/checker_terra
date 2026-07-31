<?php
/**
 * api.php — integração segura com OAuth 2.0 Authorization Code + PKCE.
 *
 * Não recebe senhas, não testa listas de credenciais, não usa proxies e não
 * grava tokens ou credenciais em arquivos de texto.
 *
 * Variáveis obrigatórias:
 *   TERRA_CLIENT_ID
 *   TERRA_AUTHORIZE_URL
 *   TERRA_TOKEN_URL
 *   TERRA_REDIRECT_URI
 *
 * Variáveis opcionais:
 *   TERRA_SCOPE (padrão: openid profile email)
 *   TERRA_CLIENT_SECRET (somente se o cliente for confidencial)
 */

declare(strict_types=1);

session_start([
    'cookie_httponly' => true,
    'cookie_secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
    'cookie_samesite' => 'Lax',
]);

header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

function json_response(array $payload, int $status = 200): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function env_required(string $name): string
{
    $value = getenv($name);
    if ($value === false || trim($value) === '') {
        json_response([
            'status' => 'error',
            'message' => "Configuração ausente: {$name}"
        ], 500);
    }

    return trim($value);
}

function base64url_encode(string $value): string
{
    return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
}

function http_post_form(string $url, array $fields): array
{
    $ch = curl_init($url);
    if ($ch === false) {
        throw new RuntimeException('Não foi possível iniciar a requisição HTTPS.');
    }

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query($fields, '', '&', PHP_QUERY_RFC3986),
        CURLOPT_HTTPHEADER => [
            'Accept: application/json',
            'Content-Type: application/x-www-form-urlencoded',
        ],
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
    ]);

    $body = curl_exec($ch);
    $curl_error = curl_error($ch);
    $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($body === false) {
        throw new RuntimeException($curl_error !== '' ? $curl_error : 'Falha na comunicação com o provedor.');
    }

    $data = json_decode($body, true);
    if (!is_array($data)) {
        throw new RuntimeException('O provedor retornou uma resposta inválida.');
    }

    return [$status, $data];
}

$client_id = env_required('TERRA_CLIENT_ID');
$authorize_url = env_required('TERRA_AUTHORIZE_URL');
$token_url = env_required('TERRA_TOKEN_URL');
$redirect_uri = env_required('TERRA_REDIRECT_URI');
$scope = trim((string) (getenv('TERRA_SCOPE') ?: 'openid profile email'));
$client_secret = getenv('TERRA_CLIENT_SECRET');
$action = (string) ($_GET['action'] ?? '');

// Mantenha a proteção da área administrativa existente, exceto nas rotas
// OAuth, que precisam estar acessíveis para iniciar e concluir o login.
$public_actions = ['login', 'callback'];
if (!in_array($action, $public_actions, true)) {
    if (($_SESSION['logged_in'] ?? false) !== true) {
        json_response(['status' => 'error', 'message' => 'Unauthorized'], 401);
    }

    if (($_SESSION['role'] ?? '') !== 'admin'
        && isset($_SESSION['expiration'])
        && time() > (int) $_SESSION['expiration']) {
        json_response(['status' => 'error', 'message' => 'Plan expired'], 403);
    }
}

if ($action === 'login') {
    // PKCE e state são novos em cada tentativa e ficam vinculados à sessão.
    $state = base64url_encode(random_bytes(32));
    $nonce = base64url_encode(random_bytes(32));
    $code_verifier = base64url_encode(random_bytes(64));
    $code_challenge = base64url_encode(hash('sha256', $code_verifier, true));

    $_SESSION['oauth_state'] = $state;
    $_SESSION['oauth_nonce'] = $nonce;
    $_SESSION['oauth_code_verifier'] = $code_verifier;
    $_SESSION['oauth_started_at'] = time();

    $query = http_build_query([
        'client_id' => $client_id,
        'response_type' => 'code',
        'redirect_uri' => $redirect_uri,
        'scope' => $scope,
        'state' => $state,
        'nonce' => $nonce,
        'code_challenge' => $code_challenge,
        'code_challenge_method' => 'S256',
    ], '', '&', PHP_QUERY_RFC3986);

    header('Location: ' . $authorize_url . '?' . $query, true, 302);
    exit;
}

if ($action === 'callback') {
    $error = (string) ($_GET['error'] ?? '');
    if ($error !== '') {
        $description = (string) ($_GET['error_description'] ?? 'Autorização cancelada.');
        unset($_SESSION['oauth_state'], $_SESSION['oauth_nonce'], $_SESSION['oauth_code_verifier'], $_SESSION['oauth_started_at']);
        json_response(['status' => 'error', 'message' => $description], 400);
    }

    $code = (string) ($_GET['code'] ?? '');
    $state = (string) ($_GET['state'] ?? '');
    $saved_state = (string) ($_SESSION['oauth_state'] ?? '');
    $code_verifier = (string) ($_SESSION['oauth_code_verifier'] ?? '');
    $started_at = (int) ($_SESSION['oauth_started_at'] ?? 0);

    if ($code === '' || $state === '' || $saved_state === '' || $code_verifier === '') {
        json_response(['status' => 'error', 'message' => 'Callback OAuth incompleto.'], 400);
    }

    if ($started_at === 0 || (time() - $started_at) > 600) {
        json_response(['status' => 'error', 'message' => 'Solicitação OAuth expirada.'], 400);
    }

    if (!hash_equals($saved_state, $state)) {
        json_response(['status' => 'error', 'message' => 'Falha na validação do state OAuth.'], 400);
    }

    $fields = [
        'grant_type' => 'authorization_code',
        'client_id' => $client_id,
        'code' => $code,
        'redirect_uri' => $redirect_uri,
        'code_verifier' => $code_verifier,
    ];

    // Clientes públicos não devem enviar segredo. Clientes confidenciais podem
    // usar TERRA_CLIENT_SECRET conforme exigido pelo provedor.
    if ($client_secret !== false && trim((string) $client_secret) !== '') {
        $fields['client_secret'] = trim((string) $client_secret);
    }

    try {
        [$http_status, $token] = http_post_form($token_url, $fields);
    } catch (Throwable $exception) {
        unset($_SESSION['oauth_state'], $_SESSION['oauth_nonce'], $_SESSION['oauth_code_verifier'], $_SESSION['oauth_started_at']);
        json_response(['status' => 'error', 'message' => 'Falha de comunicação com o provedor OAuth.'], 502);
    }

    unset($_SESSION['oauth_state'], $_SESSION['oauth_nonce'], $_SESSION['oauth_code_verifier'], $_SESSION['oauth_started_at']);

    if ($http_status < 200 || $http_status >= 300 || empty($token['access_token'])) {
        json_response([
            'status' => 'error',
            'message' => 'O provedor não autorizou a sessão.',
            'provider_error' => $token['error'] ?? null,
        ], 502);
    }

    session_regenerate_id(true);
    $_SESSION['logged_in'] = true;
    $_SESSION['oauth_token_type'] = (string) ($token['token_type'] ?? 'Bearer');
    $_SESSION['oauth_access_token'] = (string) $token['access_token'];

    if (!empty($token['refresh_token'])) {
        $_SESSION['oauth_refresh_token'] = (string) $token['refresh_token'];
    }

    json_response([
        'status' => 'authenticated',
        'expires_in' => isset($token['expires_in']) ? (int) $token['expires_in'] : null,
    ]);
}

if ($action === 'status') {
    json_response([
        'status' => 'authenticated',
        'has_access_token' => !empty($_SESSION['oauth_access_token']),
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
    'status' => 'ok',
    'message' => 'Endpoint OAuth disponível.',
    'actions' => ['login', 'callback', 'status', 'logout'],
]);
?>
