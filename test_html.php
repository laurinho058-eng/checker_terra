<?php
function test_html_parser($email, $password) {
    $client_id = '9199bf20-a13f-4107-85dc-02114787ef48';
    $scope = 'https://outlook.office.com/.default openid profile offline_access';
    $nonce = md5(uniqid(rand(), true));
    $state = md5(uniqid(rand(), true));
    $code_challenge = rtrim(strtr(base64_encode(hash('sha256', random_bytes(32), true)), '+/', '-_'), '=');
    
    $url = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?' . http_build_query([
        'client_id' => $client_id,
        'response_type' => 'code',
        'redirect_uri' => 'https://login.microsoftonline.com/common/oauth2/nativeclient',
        'response_mode' => 'query',
        'scope' => $scope,
        'state' => $state,
        'nonce' => $nonce,
        'code_challenge' => $code_challenge,
        'code_challenge_method' => 'S256'
    ]);

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_HEADER, true);
    curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
    curl_setopt($ch, CURLOPT_COOKIEJAR, 'cookies5.txt');
    curl_setopt($ch, CURLOPT_COOKIEFILE, 'cookies5.txt');
    
    $response = curl_exec($ch);
    $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $body = substr($response, $header_size);
    curl_close($ch);

    preg_match('/"sFT":"([^"]+)"/', $body, $sft_match);
    $sft = $sft_match[1] ?? '';
    preg_match('/"urlPost":"([^"]+)"/', $body, $urlPost_match);
    $urlPost = $urlPost_match[1] ?? '';
    $urlPost = json_decode('"' . $urlPost . '"'); // Decode \u0026
    
    preg_match('/"sCtx":"([^"]+)"/', $body, $ctx_match);
    $ctx = $ctx_match[1] ?? '';
    preg_match('/"canary":"([^"]+)"/', $body, $canary_match);
    $canary = $canary_match[1] ?? '';
    
    if (!preg_match('/^http/', $urlPost)) {
        $urlPost = 'https://login.microsoftonline.com' . $urlPost;
    }

    $ch2 = curl_init($urlPost);
    curl_setopt($ch2, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch2, CURLOPT_POST, true);
    curl_setopt($ch2, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch2, CURLOPT_HEADER, true);
    curl_setopt($ch2, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
    curl_setopt($ch2, CURLOPT_COOKIEJAR, 'cookies5.txt');
    curl_setopt($ch2, CURLOPT_COOKIEFILE, 'cookies5.txt');
    curl_setopt($ch2, CURLOPT_POSTFIELDS, http_build_query([
        'login' => $email,
        'loginfmt' => $email,
        'passwd' => $password,
        'flowToken' => $sft,
        'ctx' => $ctx,
        'canary' => $canary
    ]));
    
    $output = curl_exec($ch2);
    curl_close($ch2);
    
    file_put_contents('dump3_' . $email . '.html', $output);
    return "Saved";
}

echo "Testing HTML Parser:\n";
echo "Correct: " . test_html_parser('marciorubens065@outlook.com', '89317578Ma#') . "\n";
echo "Wrong: " . test_html_parser('marciorubens065@outlook.com', '89317578') . "\n";
?>
