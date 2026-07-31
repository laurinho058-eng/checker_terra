<?php
function test_imap($email, $password) {
    $server = "{imap-mail.outlook.com:993/imap/ssl}INBOX";
    $inbox = @imap_open($server, $email, $password, OP_HALFOPEN, 1);
    
    if ($inbox) {
        imap_close($inbox);
        return "LIVE (IMAP)";
    } else {
        return "DIE (IMAP) - " . imap_last_error();
    }
}

echo test_imap('marciorubens065@outlook.com', '89317578Ma#') . "\n";
echo test_imap('marciorubens065@outlook.com', '89317578') . "\n";
?>
