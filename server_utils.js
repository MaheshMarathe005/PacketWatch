// server_utils.js — demo file with intentional vulnerabilities for scanner testing

// just making some changes

const express = require('express');
const fs = require('fs');
const { exec } = require('child_process');
const jwt = require('jsonwebtoken');

const app = express();

// --- 1. Cross-Site Scripting (XSS) — unescaped user input rendered directly ---
app.get('/greet', (req, res) => {
  const name = req.query.name;
  res.send(`<h1>Welcome, ${name}!</h1>`);
});

// --- 2. Hardcoded JWT secret ---
const JWT_SECRET = "super-secret-key-2024-do-not-use";

function generateToken(userId) {
  return jwt.sign({ userId }, JWT_SECRET, { expiresIn: '7d' });
}

// --- 3. Command Injection ---
app.get('/lookup', (req, res) => {
  const domain = req.query.domain;
  exec(`nslookup ${domain}`, (error, stdout) => {
    res.send(stdout);
  });
});

// --- 4. Insecure Direct Object Reference (no ownership check) ---
app.get('/invoice/:id', (req, res) => {
  const invoiceId = req.params.id;
  const invoice = fs.readFileSync(`./invoices/${invoiceId}.json`, 'utf8');
  res.json(JSON.parse(invoice));
});

// --- 5. Insecure CORS configuration ---
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  next();
});

// --- 6. Open Redirect ---
app.get('/redirect', (req, res) => {
  const target = req.query.url;
  res.redirect(target);
});

module.exports = app;
