<?php
function test_client($email, $password, $client_id, $scope) {
    $url = 'https://login.microsoftonline.com/common/oauth2/v2.0/token';
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
        'client_id' => $client_id,
        'scope' => $scope, 
        'grant_type' => 'password',
        'username' => $email,
        'password' => $password
    ]));
    
    $output = curl_exec($ch);
    curl_close($ch);
    $json = json_decode($output, true);
    if (isset($json['access_token'])) return "SUCCESS";
    return $json['error'] ?? 'UNKNOWN ERROR';
}

function test_client_v1($email, $password, $client_id, $scope) {
    $url = 'https://login.live.com/oauth20_token.srf';
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query([
        'client_id' => $client_id,
        'scope' => $scope, 
        'grant_type' => 'password',
        'username' => $email,
        'password' => $password
    ]));
    
    $output = curl_exec($ch);
    curl_close($ch);
    $json = json_decode($output, true);
    if (isset($json['access_token'])) return "SUCCESS";
    return $json['error'] ?? 'UNKNOWN ERROR';
}

$clients = [
    ['00000000441CC063', 'wl.imap wl.offline_access'], // Windows Mail
    ['0000000040182E9B', 'service::eas.outlook.com::EAS::BIT'], // Android
    ['d3590ed6-52b3-4102-aeff-aad2292ab01c', 'https://outlook.office.com/.default'], // MS Office
    ['1b730954-1685-4b74-9bfd-dac224a7b894', 'https://graph.microsoft.com/.default'] // Azure PS
];

foreach ($clients as $c) {
    echo "Testing {$c[0]} on v2.0: " . test_client('marciorubens065@outlook.com', '89317578Ma#', $c[0], $c[1]) . "\n";
    echo "Testing {$c[0]} on v1.0: " . test_client_v1('marciorubens065@outlook.com', '89317578Ma#', $c[0], $c[1]) . "\n";
}
?>
