import os
import hashlib
import sqlite3
from flask import Flask, request

app = Flask(__name__)
API_KEY = "test-secret-12345"

aws_access_key_id = AKIAT4GVSAXXFS5FMCHK
aws_secret_access_key = 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

# Hardcoded AWS Secret Key (Triggers TruffleHog and CodeQL secret scanning)
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

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

# Unsafe Deserialization (CWE-502 - Triggers CodeQL)
@app.route('/deserialize', methods=['POST'])
def unsafe_deserialization():
    serialized_data = request.data
    eval(serialized_data)  # Insecure deserialization
    return "Data deserialized."

if __name__ == "__main__":
    app.run(debug=True)
