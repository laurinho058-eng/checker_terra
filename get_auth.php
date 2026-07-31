<?php
$client_id = '9199bf20-a13f-4107-85dc-02114787ef48';
$scope = 'https://outlook.office.com/.default openid profile offline_access';
$nonce = md5(uniqid(rand(), true));
$state = md5(uniqid(rand(), true));
$code_challenge = rtrim(strtr(base64_encode(hash('sha256', random_bytes(32), true)), '+/', '-_'), '=');
$url = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?' . http_build_query(['client_id' => $client_id, 'response_type' => 'code', 'redirect_uri' => 'https://login.microsoftonline.com/common/oauth2/nativeclient', 'response_mode' => 'query', 'scope' => $scope, 'state' => $state, 'nonce' => $nonce, 'code_challenge' => $code_challenge, 'code_challenge_method' => 'S256']);
$ch = curl_init($url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
$res = curl_exec($ch);
curl_close($ch);
file_put_contents('auth_page.html', $res);
?>
