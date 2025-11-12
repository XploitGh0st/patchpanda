import sqlite3

# WARNING: This function is insecure and vulnerable to SQL injection.
def insecure_login(username, password):
    # Create a connection to a database (in-memory for this example)
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()

    # Create a table and insert a user
    cursor.execute("CREATE TABLE users (username TEXT, password TEXT)")
    cursor.execute("INSERT INTO users VALUES ('admin', 'password123')")
    conn.commit()

    # --- THIS IS THE VULNERABLE LINE ---
    # It builds the query by directly inserting user input.
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    print(f"Executing: {query}")

    try:
        cursor.execute(query)
        user = cursor.fetchone()

        if user:
            print(f"\n[SUCCESS] Logged in as: {user[0]}")
        else:
            print("\n[FAILURE] Invalid username or password.")
    except sqlite3.Error as e:
        print(f"\n[ERROR] An error occurred: {e}")
    
    conn.close()

# --- Example Attack ---
# An attacker doesn't enter a real username.
# Instead, they enter a string that modifies the SQL query.
attacker_username = "' OR '1'='1" 
attacker_password = "password" # The password doesn't even matter

print("--- Running Insecure Login Attempt ---")
insecure_login(attacker_username, attacker_password)
