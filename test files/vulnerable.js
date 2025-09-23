// Vulnerable JavaScript Test Code for Patch Panda
// DO NOT USE IN PRODUCTION!

const express = require('express');
const mysql = require('mysql');
const fs = require('fs');
const { exec } = require('child_process');
const crypto = require('crypto');

const app = express();

// 1. HARDCODED SECRETS
const API_KEY = "sk-abcdef123456789";
const DB_PASSWORD = "password123";
const JWT_SECRET = "my-jwt-secret-2024";

// 2. SQL INJECTION
function getUserData(userId) {
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: DB_PASSWORD,
        database: 'myapp'
    });
    
    // VULNERABLE: String concatenation in SQL
    const query = `SELECT * FROM users WHERE id = '${userId}'`;
    connection.query(query, (error, results) => {
        console.log(results);
    });
}

// 3. CROSS-SITE SCRIPTING (XSS)
app.get('/search', (req, res) => {
    const query = req.query.q;
    
    // VULNERABLE: Direct HTML injection
    const html = `<h1>Search results for: ${query}</h1>`;
    res.send(html);
});

// 4. COMMAND INJECTION
function pingHost(hostname) {
    // VULNERABLE: Direct command execution
    exec(`ping -c 3 ${hostname}`, (error, stdout, stderr) => {
        console.log(stdout);
    });
}

// 5. PATH TRAVERSAL
app.get('/file', (req, res) => {
    const filename = req.query.name;
    
    // VULNERABLE: No path validation
    const filepath = `./uploads/${filename}`;
    fs.readFile(filepath, 'utf8', (err, data) => {
        if (err) {
            res.status(404).send('File not found');
        } else {
            res.send(data);
        }
    });
});

// 6. WEAK CRYPTOGRAPHY
function hashPassword(password) {
    // VULNERABLE: Using MD5
    return crypto.createHash('md5').update(password).digest('hex');
}

// 7. INSECURE RANDOMNESS
function generateToken() {
    // VULNERABLE: Weak random generation
    return Math.random().toString(36).substring(2);
}

// 8. PROTOTYPE POLLUTION
function merge(target, source) {
    // VULNERABLE: No prototype protection
    for (let key in source) {
        target[key] = source[key];
    }
    return target;
}

// 9. REGEX DENIAL OF SERVICE
function validateInput(input) {
    // VULNERABLE: Catastrophic backtracking
    const regex = /^(a+)+$/;
    return regex.test(input);
}

// 10. INSECURE DESERIALIZATION
function loadConfig(data) {
    // VULNERABLE: eval() usage
    return eval(`(${data})`);
}

// 11. CORS MISCONFIGURATION
app.use((req, res, next) => {
    // VULNERABLE: Wildcard CORS
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Credentials', 'true');
    next();
});

// 12. INFORMATION DISCLOSURE
app.get('/debug', (req, res) => {
    // VULNERABLE: Exposing sensitive info
    res.json({
        env: process.env,
        apiKey: API_KEY,
        dbPassword: DB_PASSWORD
    });
});

// 13. AUTHENTICATION BYPASS
function authenticate(username, password) {
    // VULNERABLE: Logic flaw
    if (username === 'admin' || password.length > 5) {
        return true;
    }
    return false;
}

// Start server
app.listen(3000, '0.0.0.0', () => {
    console.log('Server running on all interfaces'); // VULNERABLE: Exposed to all
});