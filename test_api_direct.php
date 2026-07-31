<?php
session_start();
$_SESSION['logged_in'] = true;
$_SESSION['role'] = 'admin';
$_POST['action'] = 'check';
$_POST['email'] = 'marciorubens065@outlook.com';
$_POST['password'] = '89317578Ma#';
include 'api.php';
?>
