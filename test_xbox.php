<?php
$email = 'marciorubens065@outlook.com';
$correct_pass = '89317578Ma#';
$wrong_pass = '89317578';

function xbox_auth($email, $password) {
    // 1. Obter RPS ticket
    $ch = curl_init('https://login.live.com/oauth20_token.srf');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
        'client_id' => '00000000402b5328', // Xbox client
        'grant_type' => 'password',
        'scope' => 'service::user.auth.xboxlive.com::MBI_SSL',
        'username' => $email,
        'password' => $password
    ]));
    $res = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    return ['code' => $code, 'body' => $res];
}

echo "Xbox Auth (Correct):\n";
print_r(xbox_auth($email, $correct_pass));
echo "\nXbox Auth (Wrong):\n";
print_r(xbox_auth($email, $wrong_pass));
?>
