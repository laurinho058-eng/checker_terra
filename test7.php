<?php
function test_activesync($email, $password) {
    $url = 'https://outlook.office365.com/Microsoft-Server-ActiveSync';
    
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_USERPWD, "$email:$password");
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'User-Agent: Apple-iPhone/15C153',
        'MS-ASProtocolVersion: 14.1'
    ]);
    
    $output = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    return "HTTP Code: $httpCode | Length: " . strlen($output);
}

echo "Testing Correct: " . test_activesync('marciorubens065@outlook.com', '89317578Ma#') . "\n";
echo "Testing Wrong: " . test_activesync('marciorubens065@outlook.com', '89317578') . "\n";
?>
