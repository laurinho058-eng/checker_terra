<?php
$lines = file('C:\Users\maarc\.gemini\antigravity\brain\631af49e-eef8-4078-922f-d816ee58a3db\.system_generated\logs\overview.txt');
$found = [];
foreach ($lines as $line) {
    if (strpos($line, 'login.microsoftonline.com') !== false) {
        $found[] = substr($line, 0, 500);
    }
}
file_put_contents('found.txt', implode("\n", $found));
echo "Done";
?>
