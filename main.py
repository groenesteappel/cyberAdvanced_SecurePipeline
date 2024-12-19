import os
import hashlib
import sqlite3
from flask import Flask, request

app = Flask(__name__)

# Hardcoded Secret (Triggers TruffleHog and CodeQL secret scanning)
API_KEY = "12345-SECRET-API-KEY"
PASSWORD = "super-secret-password"

# Command Injection (CWE-78 - Triggers CodeQL)
@app.route('/cmd', methods=['GET'])
def command_injection():
    user_input = request.args.get('cmd')
    os.system(user_input)  # Vulnerable to command injection
    return f"Executed: {user_input}"

# SQL Injection (CWE-89 - Triggers CodeQL)
@app.route('/sql', methods=['GET'])
def sql_injection():
    user_input = request.args.get('id')
    query = f"SELECT * FROM users WHERE id = {user_input}"  # Unsafe query
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute(query)  # Vulnerable to SQL injection
    return "SQL query executed."

# Weak Cryptographic Hashing (CWE-327 - Triggers CodeQL)
@app.route('/hash', methods=['GET'])
def weak_hash():
    user_input = request.args.get('data', 'default')
    hashed_value = hashlib.md5(user_input.encode()).hexdigest()  # Weak hashing algorithm
    return f"MD5 hash: {hashed_value}"

# Arbitrary File Upload (Triggers CodeQL)
@app.route('/upload', methods=['POST'])
def file_upload():
    file = request.files['file']
    file.save(f"/tmp/{file.filename}")  # No validation on file type or content
    return f"Uploaded: {file.filename}"

# Unsafe Deserialization (CWE-502 - Triggers CodeQL)
@app.route('/deserialize', methods=['POST'])
def unsafe_deserialization():
    serialized_data = request.data
    eval(serialized_data)  # Insecure deserialization
    return "Data deserialized."

# Hardcoded Dependency Vulnerability
# Flask version <1.0 has known security issues
try:
    from flask import Flask
    print("Flask module loaded successfully.")
except ImportError:
    print("Flask module is not installed!")

if __name__ == "__main__":
    app.run(debug=True)
