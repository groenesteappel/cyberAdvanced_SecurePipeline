import os
import sqlite3
from flask import Flask, request

app = Flask(__name__)

# Command Injection (CWE-78)
@app.route('/cmd')
def run_command():
    user_input = request.args.get('cmd')  # Get input from user
    os.system(user_input)  # Vulnerable to command injection
    return f"Command {user_input} executed!"

# SQL Injection (CWE-89)
@app.route('/sql')
def sql_injection():
    user_input = request.args.get('id')  # Get input from user
    query = f"SELECT * FROM users WHERE id = {user_input}"  # Unsafe query
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute(query)  # Vulnerable to SQL injection
    return "SQL query executed."

# Unsafe Deserialization (CWE-502)
@app.route('/deserialize')
def deserialize():
    user_input = request.args.get('data')  # User-supplied serialized data
    eval(user_input)  # Unsafe deserialization
    return "Data deserialized."

# Hardcoded API Key (CWE-798)
API_KEY = "12345-SECRET-KEY"

# Weak Cryptography (CWE-327)
@app.route('/hash')
def weak_hash():
    import hashlib
    user_input = request.args.get('data')  # Get input from user
    hashed_value = hashlib.md5(user_input.encode()).hexdigest()  # Weak hashing algorithm
    return f"MD5 hash: {hashed_value}"

if __name__ == "__main__":
    app.run(debug=True)


