#!/usr/bin/env python3
"""
Vulnerable Test Code for Patch Panda Security Scanner
This file contains intentionally vulnerable code to test security detection.
DO NOT USE IN PRODUCTION!
"""

import os
import sqlite3
import subprocess
import pickle
import hashlib
from flask import Flask, request, render_template_string
import mysql.connector

app = Flask(__name__)

# 1. HARDCODED SECRETS VULNERABILITY
API_KEY = "sk-1234567890abcdef"  # Hardcoded API key
DATABASE_PASSWORD = "admin123"   # Hardcoded database password
SECRET_KEY = "my-super-secret-key-2024"

# 2. SQL INJECTION VULNERABILITY
def get_user_data(user_id):
    """Vulnerable to SQL injection"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # VULNERABLE: Direct string concatenation
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    
    return cursor.fetchall()

def mysql_login(username, password):
    """Another SQL injection example"""
    config = {
        'user': 'root',
        'password': DATABASE_PASSWORD,  # Using hardcoded password
        'host': 'localhost',
        'database': 'myapp'
    }
    
    conn = mysql.connector.connect(**config)
    cursor = conn.cursor()
    
    # VULNERABLE: String formatting in SQL
    sql = "SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, password)
    cursor.execute(sql)
    
    return cursor.fetchone()

# 3. CROSS-SITE SCRIPTING (XSS) VULNERABILITY
@app.route('/profile')
def user_profile():
    """Vulnerable to XSS attacks"""
    username = request.args.get('name', 'Guest')
    
    # VULNERABLE: Direct rendering of user input
    template = f"<h1>Welcome {username}!</h1>"
    return render_template_string(template)

@app.route('/search')
def search():
    """Another XSS vulnerability"""
    query = request.args.get('q', '')
    
    # VULNERABLE: No escaping of user input
    html = f"""
    <html>
        <body>
            <h2>Search Results for: {query}</h2>
            <script>alert('Search: {query}');</script>
        </body>
    </html>
    """
    return html

# 4. COMMAND INJECTION VULNERABILITY
def backup_file(filename):
    """Vulnerable to command injection"""
    # VULNERABLE: Direct execution with user input
    command = f"tar -czf backup.tar.gz {filename}"
    result = subprocess.run(command, shell=True, capture_output=True)
    return result.stdout

def ping_host(hostname):
    """Another command injection example"""
    # VULNERABLE: No input validation
    os.system(f"ping -c 3 {hostname}")

# 5. INSECURE DESERIALIZATION VULNERABILITY
def load_user_session(session_data):
    """Vulnerable to pickle deserialization attacks"""
    # VULNERABLE: Unpickling untrusted data
    user_session = pickle.loads(session_data)
    return user_session

def save_config(config_data):
    """Another deserialization vulnerability"""
    with open('config.pkl', 'wb') as f:
        pickle.dump(config_data, f)
    
    # VULNERABLE: Loading without validation
    with open('config.pkl', 'rb') as f:
        loaded_config = pickle.load(f)
    
    return loaded_config

# 6. PATH TRAVERSAL VULNERABILITY
@app.route('/download')
def download_file():
    """Vulnerable to path traversal attacks"""
    filename = request.args.get('file')
    
    # VULNERABLE: No path validation
    file_path = f"/uploads/{filename}"
    
    try:
        with open(file_path, 'r') as f:
            return f.read()
    except FileNotFoundError:
        return "File not found"

def read_log_file(log_name):
    """Another path traversal example"""
    # VULNERABLE: Direct path construction
    log_path = f"logs/{log_name}"
    
    with open(log_path, 'r') as f:
        return f.read()

# 7. WEAK CRYPTOGRAPHY VULNERABILITY
def hash_password(password):
    """Vulnerable cryptographic implementation"""
    # VULNERABLE: Using MD5 for passwords
    return hashlib.md5(password.encode()).hexdigest()

def generate_token():
    """Weak random token generation"""
    import random
    
    # VULNERABLE: Predictable random number generation
    token = ""
    for i in range(32):
        token += chr(random.randint(65, 90))
    
    return token

# 8. INFORMATION DISCLOSURE VULNERABILITY
@app.route('/debug')
def debug_info():
    """Leaks sensitive information"""
    # VULNERABLE: Exposing internal information
    debug_data = {
        'database_password': DATABASE_PASSWORD,
        'api_key': API_KEY,
        'secret_key': SECRET_KEY,
        'environment_vars': dict(os.environ),
        'python_path': os.sys.path
    }
    
    return str(debug_data)

# 9. AUTHENTICATION BYPASS VULNERABILITY
def authenticate_user(username, password, is_admin=False):
    """Vulnerable authentication logic"""
    # VULNERABLE: Logic flaw in admin check
    if username == "admin" or is_admin:
        return True
    
    # Weak password check
    if len(password) > 3:  # Too simple requirement yrp
        return True
    
    return False

# 10. RACE CONDITION VULNERABILITY
import threading

balance = 1000
balance_lock = threading.Lock()

def withdraw_money(amount):
    """Vulnerable to race conditions"""
    global balance
    
    # VULNERABLE: No proper locking
    if balance >= amount:
        # Simulate processing time
        import time
        time.sleep(0.1)
        balance -= amount
        return True
    
    return False

# 11. BUFFER OVERFLOW SIMULATION (Python equivalent)
def process_data(data):
    """Simulates buffer overflow vulnerability"""
    # VULNERABLE: No bounds checking
    buffer = [0] * 100
    
    for i, byte in enumerate(data):
        buffer[i] = byte  # No bounds checking
    
    return buffer

# 12. XXSS (Cross-Site Script Inclusion)
@app.route('/jsonp')
def jsonp_endpoint():
    """Vulnerable JSONP implementation"""
    callback = request.args.get('callback', 'callback')
    data = {'user': 'john', 'secret': 'abc123'}
    
    # VULNERABLE: No callback validation
    return f"{callback}({data})"

# 13. LDAP INJECTION VULNERABILITY
def ldap_search(username):
    """Vulnerable to LDAP injection"""
    import ldap3
    
    # VULNERABLE: Direct string concatenation
    search_filter = f"(uid={username})"
    
    # This would be vulnerable in real LDAP implementation
    print(f"LDAP Search: {search_filter}")

# 14. XML EXTERNAL ENTITY (XXE) VULNERABILITY
def parse_xml(xml_data):
    """Vulnerable to XXE attacks"""
    import xml.etree.ElementTree as ET
    
    # VULNERABLE: No XXE protection
    root = ET.fromstring(xml_data)
    return root.text

# 15. INSECURE DIRECT OBJECT REFERENCE
@app.route('/user/<user_id>')
def get_user(user_id):
    """Vulnerable to IDOR attacks"""
    # VULNERABLE: No authorization check
    user_data = get_user_data(user_id)  # Using vulnerable function from above
    return str(user_data)

# 16. CSRF VULNERABILITY
@app.route('/transfer', methods=['POST'])
def transfer_money():
    """Vulnerable to CSRF attacks"""
    from_account = request.form.get('from')
    to_account = request.form.get('to')
    amount = request.form.get('amount')
    
    # VULNERABLE: No CSRF token validation
    # Simulate money transfer
    print(f"Transferring ${amount} from {from_account} to {to_account}")
    
    return "Transfer completed"

# 17. SENSITIVE DATA EXPOSURE
def log_user_activity(username, password, ssn):
    """Logs sensitive data insecurely"""
    # VULNERABLE: Logging sensitive information
    log_message = f"User {username} logged in with password {password} and SSN {ssn}"
    
    with open('activity.log', 'a') as f:
        f.write(log_message + "\n")

# 18. INSECURE RANDOMNESS
import random

def generate_session_id():
    """Generates predictable session IDs"""
    # VULNERABLE: Using weak random number generator
    return str(random.randint(1000, 9999))

# 19. REGEX DENIAL OF SERVICE (ReDoS)
import re

def validate_email(email):
    """Vulnerable to ReDoS attacks"""
    # VULNERABLE: Catastrophic backtracking regex
    pattern = r'^(a+)+b$'
    
    if re.match(pattern, email):
        return True
    return False

# 20. TIMING ATTACK VULNERABILITY
def compare_secrets(user_secret, actual_secret):
    """Vulnerable to timing attacks"""
    # VULNERABLE: Early return reveals information
    for i in range(len(actual_secret)):
        if i >= len(user_secret) or user_secret[i] != actual_secret[i]:
            return False
    
    return len(user_secret) == len(actual_secret)

if __name__ == "__main__":
    # VULNERABLE: Debug mode enabled in production
    app.run(debug=True, host='0.0.0.0')  # Exposed to all interfaces