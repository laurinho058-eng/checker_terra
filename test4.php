<?php
function test_oauth($email, $password) {
    $url = 'https://login.live.com/oauth20_token.srf';
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
        'client_id' => '0000000040182E9B', 
        'scope' => 'https://outlook.office.com/.default', 
        'grant_type' => 'password',
        'username' => $email,
        'password' => $password
    ]));
    
    $output = curl_exec($ch);
    curl_close($ch);
    return json_decode($output, true);
}
print_r(test_oauth('marciorubens065@outlook.com', '89317578Ma#'));
print_r(test_oauth('marciorubens065@outlook.com', '89317578'));
?>
