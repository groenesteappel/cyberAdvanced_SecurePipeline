import os
import hashlib
import sqlite3
from flask import Flask, request

app = Flask(__name__)

# Hardcoded AWS Credentials (Triggers TruffleHog and CodeQL)
AWS_ACCESS_KEY_ID = "v6ltp4tgtgto9udjthuf0ccl2"
AWS_SECRET_ACCESS_KEY = "v6ltp4tgtgto9udjthuf0ccl2"

# Command Injection (CWE-78 - Triggers CodeQL)
@app.route('/exec', methods=['GET'])
def command_injection():
    cmd = request.args.get('cmd')  # Get user input
    os.system(cmd)  # Execute unvalidated command
    return f"Executed command: {cmd}"

# SQL Injection (CWE-89 - Triggers CodeQL)
@app.route('/user', methods=['GET'])
def sql_injection():
    user_id = request.args.get('id')  # Get user input
    query = f"SELECT * FROM users WHERE id = {user_id}"  # Unsafe query
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute(query)  # Vulnerable to SQL injection
    return f"Executed SQL query: {query}"

# Weak Hash Function (CWE-327 - Triggers CodeQL)
@app.route('/hash', methods=['GET'])
def weak_hash():
    data = request.args.get('data', 'default')
    hash_value = hashlib.md5(data.encode()).hexdigest()  # Weak hashing algorithm
    return f"MD5 hash: {hash_value}"

# Unsafe File Upload (CWE-434 - Triggers CodeQL)
@app.route('/upload', methods=['POST'])
def unsafe_file_upload():
    uploaded_file = request.files['file']
    file_path = f"/tmp/{uploaded_file.filename}"  # No validation on filename
    uploaded_file.save(file_path)  # Save file without sanitizing input
    return f"File saved to: {file_path}"

# Unsafe Deserialization (CWE-502 - Triggers CodeQL)
@app.route('/deserialize', methods=['POST'])
def unsafe_deserialization():
    user_data = request.data  # Get serialized data
    eval(user_data)  # Execute untrusted serialized input
    return "Deserialization complete"

if __name__ == "__main__":
    app.run(debug=True)
