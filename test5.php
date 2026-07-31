<?php
function test_oauth($email, $password) {
    $url = 'https://login.microsoftonline.com/common/oauth2/v2.0/token';
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
        'client_id' => '27922004-5251-4030-b22d-91ecd9a37ea4', // Outlook Mobile iOS
        'scope' => 'https://outlook.office365.com/.default offline_access', 
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
