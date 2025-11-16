<?php 
session_start();
$error = '';

$DATABASE_HOST = 'localhost';
$DATABASE_USER = 'reza';
$DATABASE_PASS = 'aaa';
$DATABASE_NAME = 'finance_database';

$conn = new mysqli($DATABASE_HOST, $DATABASE_USER, $DATABASE_PASS, $DATABASE_NAME);
if ($conn->connect_error) {
    exit('Error Connecting to the DATABASE form' . $conn->connect_error);
}

if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['submit'])) {

    $username = trim($_POST['username']);
    $password = trim($_POST['password']);

    // validate if email is empty
    if (empty($username)) {
        $error .= '<p class="error">Please enter username.</p>';
    }

    // validate if password is empty
    if (empty($password)) {
        $error .= '<p class="error">Please enter your password.</p>';
    }

    if (empty($error)) {
        if($query = $conn->prepare("SELECT id, username, password, accesslevel, employeerole FROM users WHERE username = ?")) {
            $query->bind_param('s', $username);
            $query->execute();
            $result = $query->get_result();

            if ($result && $result->num_rows ===1){
                $row = $result->fetch_assoc();
            }
            
            if (password_verify($password, $row['password'])) {
                 $_SESSION["userid"] = $row['id'];
                 $_SESSION["username"] = $row['username'];
                 $_SESSION["accesslevel"] = $row['accesslevel'];
                 $_SESSION["employeerole"] = $row['employeerole'];

                 $query->close();   
                 header("Location: register.html");
                 exit;
             } else {
                 $error .= '<p class="error">The password is not valid.</p>';
            }
            $query->close();
         } else {
            $error .= '<p class="error">No User exist with that username address.</p>';
        }
        
        
    }
    // Close connection
    $conn->close();
}
?>
