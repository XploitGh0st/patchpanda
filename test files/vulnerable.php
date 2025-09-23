<!-- Vulnerable PHP Test Code for Patch Panda -->
<!-- DO NOT USE IN PRODUCTION! -->

<?php
// 1. HARDCODED SECRETS
$api_key = "sk-php123456789";
$db_password = "admin123";
$encryption_key = "myPHPSecret2024";

// 2. SQL INJECTION
function getUserData($user_id) {
    global $db_password;
    
    $connection = new mysqli("localhost", "root", $db_password, "myapp");
    
    // VULNERABLE: Direct string concatenation
    $query = "SELECT * FROM users WHERE id = '$user_id'";
    $result = $connection->query($query);
    
    return $result->fetch_all();
}

// 3. CROSS-SITE SCRIPTING (XSS)
if (isset($_GET['name'])) {
    $name = $_GET['name'];
    // VULNERABLE: Direct output without escaping
    echo "<h1>Welcome $name!</h1>";
}

// 4. COMMAND INJECTION
function pingHost($hostname) {
    // VULNERABLE: Direct command execution
    $output = shell_exec("ping -c 3 $hostname");
    return $output;
}

// 5. PATH TRAVERSAL
function readFile($filename) {
    // VULNERABLE: No path validation
    $filepath = "uploads/" . $filename;
    return file_get_contents($filepath);
}

// 6. WEAK CRYPTOGRAPHY
function hashPassword($password) {
    // VULNERABLE: Using MD5
    return md5($password);
}

// 7. INSECURE RANDOMNESS
function generateToken() {
    // VULNERABLE: Weak random generation
    return md5(rand());
}

// 8. LOCAL FILE INCLUSION (LFI)
if (isset($_GET['page'])) {
    $page = $_GET['page'];
    // VULNERABLE: Direct file inclusion
    include($page . ".php");
}

// 9. REMOTE FILE INCLUSION (RFI)
if (isset($_GET['template'])) {
    $template = $_GET['template'];
    // VULNERABLE: Remote file inclusion
    include($template);
}

// 10. INSECURE DESERIALIZATION
function loadSession($session_data) {
    // VULNERABLE: Unserializing untrusted data
    return unserialize($session_data);
}

// 11. LDAP INJECTION
function searchLDAP($username) {
    $ldap_host = "ldap://localhost";
    $ldap_conn = ldap_connect($ldap_host);
    
    // VULNERABLE: String concatenation in LDAP filter
    $filter = "(uid=$username)";
    
    $search = ldap_search($ldap_conn, "dc=example,dc=com", $filter);
    return ldap_get_entries($ldap_conn, $search);
}

// 12. XXE (XML External Entity)
function parseXML($xml_data) {
    // VULNERABLE: No XXE protection
    $dom = new DOMDocument();
    $dom->loadXML($xml_data);
    return $dom;
}

// 13. CSRF VULNERABILITY
if ($_POST['action'] == 'transfer') {
    $from = $_POST['from_account'];
    $to = $_POST['to_account'];
    $amount = $_POST['amount'];
    
    // VULNERABLE: No CSRF token validation
    transferMoney($from, $to, $amount);
}

// 14. SESSION FIXATION
session_start();
if (isset($_GET['session_id'])) {
    // VULNERABLE: Accepting session ID from user
    session_id($_GET['session_id']);
}

// 15. INFORMATION DISCLOSURE
function debugInfo() {
    // VULNERABLE: Exposing sensitive information
    return array(
        'php_version' => phpversion(),
        'server_info' => $_SERVER,
        'environment' => $_ENV,
        'api_key' => $GLOBALS['api_key'],
        'db_password' => $GLOBALS['db_password']
    );
}

// 16. WEAK SESSION MANAGEMENT
function createSession($user_id) {
    // VULNERABLE: Predictable session IDs
    $session_id = md5($user_id . time());
    setcookie("session", $session_id, time() + 3600, "/", "", false, false);
}

// 17. AUTHENTICATION BYPASS
function authenticate($username, $password) {
    // VULNERABLE: Logic flaw
    if ($username == "admin" || strlen($password) > 5) {
        return true;
    }
    return false;
}

// 18. TIMING ATTACK
function compareSecrets($user_secret, $actual_secret) {
    // VULNERABLE: Early return reveals timing
    for ($i = 0; $i < strlen($actual_secret); $i++) {
        if ($i >= strlen($user_secret) || $user_secret[$i] !== $actual_secret[$i]) {
            return false;
        }
    }
    return strlen($user_secret) === strlen($actual_secret);
}

// 19. OPEN REDIRECT
if (isset($_GET['redirect'])) {
    $redirect_url = $_GET['redirect'];
    // VULNERABLE: No URL validation
    header("Location: $redirect_url");
    exit();
}

// 20. REGEX DENIAL OF SERVICE
function validateEmail($email) {
    // VULNERABLE: Catastrophic backtracking
    $pattern = '/^(a+)+$/';
    return preg_match($pattern, $email);
}

// 21. TYPE CONFUSION
function processData($data) {
    // VULNERABLE: No type checking
    if ($data == "admin") {
        return "Admin access granted";
    }
    return "Regular user";
}

// 22. MASS ASSIGNMENT
if ($_POST['update_profile']) {
    $user = new User();
    
    // VULNERABLE: Mass assignment without filtering
    foreach ($_POST as $key => $value) {
        $user->$key = $value;
    }
    
    $user->save();
}

// 23. INSECURE DIRECT OBJECT REFERENCE
function getUserProfile($user_id) {
    // VULNERABLE: No authorization check
    return getUserData($user_id);
}

// 24. HTTP RESPONSE SPLITTING
if (isset($_GET['name'])) {
    $name = $_GET['name'];
    // VULNERABLE: No header injection protection
    header("Set-Cookie: username=$name; Path=/");
}

// 25. CLICKJACKING
// VULNERABLE: No X-Frame-Options header set
?>

<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable PHP Application</title>
</head>
<body>
    <h1>Test Application</h1>
    
    <!-- VULNERABLE: Inline JavaScript with user data -->
    <script>
        var userInput = "<?php echo $_GET['input'] ?? ''; ?>";
        console.log(userInput);
    </script>
    
    <!-- VULNERABLE: Direct user input in HTML -->
    <p>Hello <?php echo $_GET['user'] ?? 'Guest'; ?>!</p>
    
    <!-- VULNERABLE: Unsafe file upload -->
    <form method="post" enctype="multipart/form-data">
        <input type="file" name="upload">
        <input type="submit" value="Upload">
    </form>
    
    <?php
    if ($_FILES['upload']) {
        $upload_dir = "uploads/";
        $upload_file = $upload_dir . basename($_FILES['upload']['name']);
        
        // VULNERABLE: No file type validation
        move_uploaded_file($_FILES['upload']['tmp_name'], $upload_file);
        echo "File uploaded: " . $upload_file;
    }
    ?>
</body>
</html>