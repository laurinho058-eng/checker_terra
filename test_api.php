<?php

$email = 'marciorubens065@outlook.com';
$correct_pass = '89317578Ma#';
$wrong_pass = '89317578';

function test_oauth($email, $password) {
    $url = 'https://login.live.com/oauth20_token.srf';
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_USERAGENT, 'Dalvik/2.1.0 (Linux; U; Android 11; SM-G998B Build/RP1A.200720.012)');
    
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
        'client_id' => '0000000040182E9B', // Android App Client ID
        'scope' => 'service::eas.outlook.com::EAS::BIT', // Escopo essencial para teste de login
        'grant_type' => 'password',
        'username' => $email,
        'password' => $password
    ]));
    
    $output = curl_exec($ch);
    curl_close($ch);
    
    return json_decode($output, true);
}

echo "Testing Correct Pass:\n";
print_r(test_oauth($email, $correct_pass));

echo "\nTesting Wrong Pass:\n";
print_r(test_oauth($email, $wrong_pass));

?>
