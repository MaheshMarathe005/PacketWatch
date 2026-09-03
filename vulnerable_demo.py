# vulnerable_demo.py — patterns Semgrep OSS reliably detects
# just some changes for tp

import subprocess
import yaml
import pickle
import os

# --- 1. Command Injection via subprocess with shell=True ---
def run_ping(host):
    subprocess.run("ping " + host, shell=True)

# --- 2. Insecure deserialization — yaml.load without SafeLoader ---
def load_config(raw_yaml):
    return yaml.load(raw_yaml, Loader=yaml.Loader)

# --- 3. Insecure deserialization — pickle.loads on untrusted data ---
def load_session(data):
    return pickle.loads(data)

# --- 4. eval() on user input ---
def calculate(expression):
    return eval(expression)

# --- 5. os.system with string concatenation ---
def cleanup(filename):
    os.system("rm -rf " + filename)

# --- 6. Flask-style debug mode left on (if flask is importable in your env) ---
# from flask import Flask
# app = Flask(__name__)
# app.run(debug=True)
