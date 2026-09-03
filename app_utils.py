# app_utils.py — demo file with intentional vulnerabilities for scanner testing

import sqlite3
import hashlib
import subprocess
import os

# --- 1. SQL Injection ---
def get_user_by_username(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()

# --- 2. Hardcoded secret ---
API_KEY = "sk_live_51Hh3k2ExampleFakeKeyDoNotUse12345"

# --- 3. Weak cryptography (MD5 for password hashing) ---
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# --- 4. Command Injection ---
def ping_host(hostname):
    command = "ping -c 1 " + hostname
    result = subprocess.run(command, shell=True, capture_output=True)
    return result.stdout

# --- 5. Path Traversal ---
def read_user_file(filename):
    base_path = "/var/app/uploads/"
    with open(base_path + filename, "r") as f:
        return f.read()
