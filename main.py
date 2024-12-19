import os
import hashlib
import sqlite3
import pickle
from flask import Flask, request

app = Flask(__name__)

# Weak Authentication (Hardcoded credentials - CWE-798)
USER_CREDENTIALS = {"admin": "12345"}  # Hardcoded username and password

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    if username in USER_CREDENTIALS and USER_CREDENTIALS[username] == password:
        return "Welcome, admin!"  # Insecure login system
    else:
        return "Access Denied"

# Arbitrary File Upload (CWE-434)
@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    file.save(os.path.join('/tmp', file.filename))  # Insecure: Doesn't validate file type or content
    return f"File {file.filename} uploaded."

# Insecure Direct Object Reference (CWE-639)
@app.route('/download/<filename>')
def download_file(filename):
    with open(f'/tmp/{filename}', 'rb') as f:
        return f.read()  # Exposes files in /tmp without validation

# Weak Cryptographic Practices (CWE-326)
@app.route('/hash')
def weak_hash():
    user_input = request.args.get('data', 'default')
    hashed_value = hashlib.md5(user_input.encode()).hexdigest()  # Weak MD5 hashing
    return f"MD5 hash: {hashed_value}"

# Unsafe Deserialization (CWE-502)
@app.route('/deserialize', methods=['POST'])
def deserialize_data():
    serialized_data = request.form.get('data')
    deserialized = pickle.loads(serialized_data.encode())  # Vulnerable: Executes malicious serialized input
    return f"Deserialized: {deserialized}"


# Command Injection (CWE-78)
@app.route('/exec', methods=['GET'])
def execute_command():
    user_input = request.args.get('cmd')
    os.system(user_input)  # Executes user input as a command
    return f"Executed: {user_input}"

# SQL Injection (CWE-89)
@app.route('/user/<int:id>')
def get_user(id):
    query = f"SELECT * FROM users WHERE id = {id}"  # Unsafe query construction
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute(query)  # Vulnerable to SQL Injection
    return "Query executed."

# XML External Entity Injection (XXE) (CWE-611)
@app.route('/xml', methods=['POST'])
def parse_xml():
    from lxml import etree
    xml_data = request.data
    parser = etree.XMLParser(resolve_entities=True)
    tree = etree.fromstring(xml_data, parser)  # Vulnerable to XXE
    return etree.tostring(tree)

# Information Exposure in Logs (CWE-532)
@app.route('/debug')
def debug():
    secret = request.args.get('secret', 'default-secret')
    print(f"Debug mode active. Secret: {secret}")  # Logs sensitive information
    return "Debug mode active."

if __name__ == "__main__":
    app.run(debug=True)
