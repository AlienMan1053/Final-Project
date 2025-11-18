<?php


$DATABASE_HOST = 'localhost';
$DATABASE_USER = 'reza';
$DATABASE_PASS = 'aaa';
$DATABASE_NAME = 'finance_database';

$conn = new mysqli($DATABASE_HOST, $DATABASE_USER, $DATABASE_PASS, $DATABASE_NAME);
if ($conn->connect_error) {
    exit('Error Connecting to the DATABASE form' . $conn->connect_error);
}

function addAuditLog($conn, $action) {
    if ($stmt = $conn->prepare('UPDATE users SET auditlog = CONCAT(IFNULL(auditlog, ""), ?) WHERE username = ?')) {
        $logEntry = "\n" . date('Y-m-d H:i:s') . " - {$_SESSION['username']} {$action}";
        $stmt->bind_param('ss', $logEntry, $_SESSION['username']);
        $stmt->execute();
        $stmt->close();
    }
}

// Require action
if (!isset($_POST['action']) || $_POST['action'] === '') {
    exit('Empty Field(s)');
}

$action = strtolower(trim($_POST['action']));

session_start();

if (!isset($_SESSION['userid'], $_SESSION['accesslevel'])) {
    $conn->close();
    exit('Need to login.');
}

$currentAccess = $_SESSION['accesslevel'];
$allowedActions = [];

switch ($currentAccess) {
    case 'admin':
        $allowedActions = ['create', 'read', 'update', 'delete'];
        break;
    case 'editor':
        $allowedActions = ['read', 'update'];
        break;
    case 'viewer':
        $allowedActions = ['read'];
        break;
}

if (!in_array($action, $allowedActions, true)){
    $conn->close();
    exit('You are not authorized to perform that action.');
}

// ----------------------- CREATE -----------------------
if ($action === 'create') {
    if (!isset($_POST['username'], $_POST['password'], $_POST['email'])) {
        exit('Empty Field(s)');
    }
    if ($_POST['username'] === '' || $_POST['password'] === '' || $_POST['email'] === '') {
        exit('Value Empty!');
    }

    // Duplicate check
    if ($stmt = $conn->prepare('SELECT id FROM users WHERE username = ?')) {
        $stmt->bind_param('s', $_POST['username']);
        $stmt->execute();
        $stmt->store_result();
        if ($stmt->num_rows > 0) {
            $stmt->close();
            $conn->close();
            exit('Error: Username already exists. Try again!');
            addAuditLog($conn, ' tried to create a user that already exists');
        }
        $stmt->close();
    } else {
        $conn->close();
        exit('Error Occurred!');
    }

    if ($stmt = $conn->prepare('INSERT INTO users (username, id, password, email, accesslevel, employeerole) VALUES (?, ?, ?, ?, ?, ?)')) {
        $password = password_hash($_POST['password'], PASSWORD_DEFAULT);
        $stmt->bind_param('ssssss', $_POST['username'],$_POST['id'], $password, $_POST['email'], $_POST['accesslevel'], $_POST['employeerole']);
        if ($stmt->execute()) {
            echo 'Successfully Registered!';
            addAuditLog($conn, ' created ' . $_POST['username']);
        } else {
            echo 'Error Occurred!';
        }
        $stmt->close();
    } else {
        echo 'Error Occurred!';
    }

    $conn->close();
    exit();
}

// ----------------------- READ (email only) -----------------------
if ($action === 'read') {
    // Accept username OR id (prefer username if both provided)
    $byUsername = isset($_POST['username']) && $_POST['username'] !== '';
    $byId       = isset($_POST['id']) && $_POST['id'] !== '';

    if (!$byUsername && !$byId) {
        $conn->close();
        exit('Empty Field(s)');
    }

    if ($byUsername) {
        if ($stmt = $conn->prepare('SELECT email FROM users WHERE username = ?')) {
            $stmt->bind_param('s', $_POST['username']);
            addAuditLog($conn, ' viewed email of ' . $_POST['username']);
        } else { $conn->close(); exit('Error Occurred!'); }
    } else {
        if ($stmt = $conn->prepare('SELECT email FROM users WHERE id = ?')) {
            $stmt->bind_param('i', $_POST['id']);
        } else { $conn->close(); exit('Error Occurred!'); }
    }

    $stmt->execute();
    $result = $stmt->get_result();
    if ($row = $result->fetch_assoc()) {
        header('Content-Type: application/json');
        echo json_encode(['email' => $row['email']]);
    } else {
        echo 'No Record Found!';
    }
    $stmt->close();
    $conn->close();
    exit();
}

// ----------------------- UPDATE (email only) -----------------------
if ($action === 'update') {
    // Only allow updating email (require username + email)
    if (!isset($_POST['username'], $_POST['email'])) {
        $conn->close();
        exit('Empty Field(s)');
    }
    if ($_POST['username'] === '' || $_POST['email'] === '') {
        $conn->close();
        exit('Value Empty!');
    }

    // Ensure target user exists
    if ($stmt = $conn->prepare('SELECT id FROM users WHERE username = ?')) {
        $stmt->bind_param('s', $_POST['username']);
        $stmt->execute();
        $stmt->store_result();
        if ($stmt->num_rows === 0) {
            $stmt->close();
            $conn->close();
            exit('No Record Found!');
            addAuditLog($conn, ' tried to update a user that does not exist');
        }
        $stmt->close();
    } else {
        $conn->close();
        exit('Error Occurred!');
    }

    // Update email only
    if ($stmt = $conn->prepare('UPDATE users SET email = ? WHERE username = ?')) {
        $stmt->bind_param('ss', $_POST['email'], $_POST['username']);
        if ($stmt->execute()) {
            echo 'Successfully Updated!';
            addAuditLog($conn, ' updated email of ' . $_POST['username']);
        } else {
            echo 'Error Occurred!';
        }
        $stmt->close();
    } else {
        echo 'Error Occurred!';
    }

    $conn->close();
    exit();
}

// ----------------------- DELETE -----------------------
if ($action === 'delete') {
    if (!isset($_POST['username']) || $_POST['username'] === '') {
        $conn->close();
        exit('Value Empty!');
    }

    // Ensure exists
    if ($stmt = $conn->prepare('SELECT id FROM users WHERE username = ?')) {
        $stmt->bind_param('s', $_POST['username']);
        $stmt->execute();
        $stmt->store_result();
        if ($stmt->num_rows === 0) {
            $stmt->close();
            $conn->close();
            exit('No Record Found!');
            addAuditLog($conn, ' tried to delete a user that does not exist');
        }
        $stmt->close();
    } else {
        $conn->close();
        exit('Error Occurred!');
    }

    if ($stmt = $conn->prepare('DELETE FROM users WHERE username = ?')) {
        $stmt->bind_param('s', $_POST['username']);
        if ($stmt->execute()) {
            echo 'Successfully Deleted!';
            addAuditLog($conn, ' deleted ' . $_POST['username']);
        } else {
            echo 'Error Occurred!';
        }
        $stmt->close();
    } else {
        echo 'Error Occurred!';
    }

    $conn->close();
    exit();
}

// Fallback
$conn->close();
exit('Error Occurred!');
?>
