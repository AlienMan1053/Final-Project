<?php
$DATABASE_HOST = 'localhost';
$DATABASE_USER = 'reza';
$DATABASE_PASS = 'aaa';
$DATABASE_NAME = 'finance_database';

$conn = new mysqli($DATABASE_HOST, $DATABASE_USER, $DATABASE_PASS, $DATABASE_NAME);
if ($conn->connect_error) {
    exit('Error Connecting to the DATABASE form' . $conn->connect_error);
}
?>
