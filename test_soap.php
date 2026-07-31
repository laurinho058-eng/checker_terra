<?php
$email = 'marciorubens065@outlook.com';
$correct_pass = '89317578Ma#';
$wrong_pass = '89317578';

function check_soap($email, $password) {
    $xml = '<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsse="http://schemas.xmlsoap.org/ws/2003/06/secext" xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wssc="http://schemas.xmlsoap.org/ws/2004/04/sc" xmlns:wst="http://schemas.xmlsoap.org/ws/2004/04/trust">
  <Header>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2004/04/trust/RST/Issue</wsa:Action>
    <wsa:To>https://login.live.com/RST2.srf</wsa:To>
    <wsse:Security>
      <wsse:UsernameToken>
        <wsse:Username>'.$email.'</wsse:Username>
        <wsse:Password>'.$password.'</wsse:Password>
      </wsse:UsernameToken>
    </wsse:Security>
  </Header>
  <Body>
    <wst:RequestSecurityToken>
      <wst:RequestType>http://schemas.xmlsoap.org/ws/2004/04/trust/Issue</wst:RequestType>
      <wsp:AppliesTo>
        <wsa:EndpointReference>
          <wsa:Address>http://Passport.NET/tb</wsa:Address>
        </wsa:EndpointReference>
      </wsp:AppliesTo>
    </wst:RequestSecurityToken>
  </Body>
</Envelope>';

    $ch = curl_init('https://login.live.com/RST2.srf');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $xml);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/soap+xml; charset=utf-8'
    ]);
    $result = curl_exec($ch);
    curl_close($ch);
    return $result;
}

echo "Correct Pass:\n";
echo check_soap($email, $correct_pass);
echo "\n\nWrong Pass:\n";
echo check_soap($email, $wrong_pass);
?>
