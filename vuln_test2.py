# vuln_test2.py — vulnerabilities matching our custom Semgrep rules

import sqlite3
import os

DATABASE_PASSWORD = "SuperSecret123!"
API_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"

def get_user(username):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()

def search_products(keyword):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE name = '" + keyword + "'")
    return cursor.fetchall()

def check_host(hostname):
    os.system(f"ping -c 1 {hostname}")
