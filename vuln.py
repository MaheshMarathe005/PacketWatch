# vulnerable file edited for testing
# hello
import os
import sqlite3

API_KEY = "sk-1234567890abcdef1234567890abcdef"

def get_user(username):
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()

def run_command(user_input):
    os.system("ping " + user_input)
