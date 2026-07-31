<?php
/**
 * api.php — integração segura com o login oficial do Terra Mail.
 *
 * Não recebe, testa ou armazena senhas e não processa listas de credenciais.
 * Configure OAuth apenas se o Terra fornecer oficialmente esses parâmetros.
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
    ];
}

function oauth_ready(array $config): bool
{
    return $config['client_id'] !== '' &&
        $config['authorize_url'] !== '' &&
        $config['token_url'] !== '' &&
        $config['redirect_uri'] !== '';
}

function post_form(string $url, array $fields): array
{
    $ch = curl_init($url);
    if ($ch === false) {
        throw new RuntimeException('Não foi possível iniciar a comunicação HTTPS.');
    }

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => http_build_query($fields, '', '&', PHP_QUERY_RFC3986),
        CURLOPT_HTTPHEADER => ['Accept: application/json', 'Content-Type: application/x-www-form-urlencoded'],
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

$action = (string) ($_GET['action'] ?? '');
$config = oauth_config();

// O callback e o início do login precisam ser públicos.
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
    // Sem credenciais OAuth oficiais, abre somente o login oficial.
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
        [$http_status, $token] = post_form($config['token_url'], $fields);
    } catch (Throwable $exception) {
        unset($_SESSION['terra_oauth']);
        error_log('OAuth Terra: ' . $exception->getMessage());
        json_response(['status' => 'error', 'message' => 'Falha de comunicação com o provedor OAuth.'], 502);
    }

    unset($_SESSION['terra_oauth']);

    if ($http_status < 200 || $http_status >= 300 || empty($token['access_token'])) {
        json_response([
            'status' => 'error',
            'message' => 'O provedor não autorizou a sessão.',
            'http_code' => $http_status,
            'provider_error' => $token['error'] ?? null,
        ], 502);
    }

    session_regenerate_id(true);
    $_SESSION['logged_in'] = true;
    $_SESSION['terra_authenticated'] = true;
    $_SESSION['terra_access_token'] = (string) $token['access_token'];
    $_SESSION['terra_token_type'] = (string) ($token['token_type'] ?? 'Bearer');
    if (!empty($token['refresh_token'])) {
        $_SESSION['terra_refresh_token'] = (string) $token['refresh_token'];
    }

    json_response(['status' => 'authenticated']);
}

if ($action === 'status') {
    json_response([
        'status' => 'success',
        'authenticated' => !empty($_SESSION['terra_authenticated']),
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
    'available_actions' => ['health', 'login', 'callback', 'status', 'logout'],
], 404);
?>
