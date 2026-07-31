<?php
$html = file_get_contents('pwd_error.html');
preg_match_all('/.{0,40}senha.*?incorreta.{0,40}/i', $html, $matches);
print_r($matches[0]);
