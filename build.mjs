// Assembles the self-contained dist/ that Tauri bundles. The single source of
// truth is "Command Runner.dc.html"; this copies its <x-dc> template and logic
// script into an index.html that loads React + the dc runtime locally (no CDN),
// then copies the styles, fonts and icons the page references.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createCipheriv, createHash, randomBytes } from 'node:crypto';

const root = path.dirname(fileURLToPath(import.meta.url));
const dist = path.join(root, 'dist');
const factoryDir = path.join(root, 'src-tauri', 'config');
const factoryKey = randomBytes(32);
const adminSalt = randomBytes(32);
const adminHash = createHash('sha256').update(adminSalt).update('admin').digest('base64');
const factoryConfig = Buffer.from(JSON.stringify({
  version: 1,
  admin_salt: adminSalt.toString('base64'),
  admin_hash: adminHash,
  settings: {},
}));
const factoryNonce = randomBytes(12);
const factoryCipher = createCipheriv('aes-256-gcm', factoryKey, factoryNonce);
const factoryEncrypted = Buffer.concat([factoryCipher.update(factoryConfig), factoryCipher.final(), factoryCipher.getAuthTag()]);
fs.rmSync(factoryDir, { recursive: true, force: true });
fs.mkdirSync(factoryDir, { recursive: true });
fs.writeFileSync(path.join(factoryDir, 'command-runner.config.enc'), Buffer.concat([factoryNonce, factoryEncrypted]));
fs.writeFileSync(path.join(factoryDir, '.command-runner.key'), factoryKey);

const src = fs.readFileSync(path.join(root, 'Command Runner.dc.html'), 'utf8');

const xdc = src.slice(src.indexOf('<x-dc>'), src.indexOf('</x-dc>') + '</x-dc>'.length);
const scriptOpen = src.indexOf('<script type="text/x-dc"');
const script = src.slice(scriptOpen, src.indexOf('</script>', scriptOpen) + '</script>'.length);
if (!xdc || scriptOpen < 0) throw new Error('build.mjs: could not locate <x-dc> / data-dc-script block');

const html = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Command Runner</title>
<script src="./vendor/react.production.min.js"></script>
<script src="./vendor/react-dom.production.min.js"></script>
<script src="./support.js"></script>
</head>
<body>
${xdc}
${script}
</body>
</html>
`;

fs.rmSync(dist, { recursive: true, force: true });
fs.mkdirSync(dist, { recursive: true });
fs.writeFileSync(path.join(dist, 'index.html'), html);
fs.copyFileSync(path.join(root, 'support.js'), path.join(dist, 'support.js'));
fs.copyFileSync(path.join(root, 'styles.css'), path.join(dist, 'styles.css'));
fs.cpSync(path.join(root, 'vendor'), path.join(dist, 'vendor'), { recursive: true });
const toolsDir = path.join(root, 'tools');
if (fs.existsSync(toolsDir)) {
  fs.cpSync(toolsDir, path.join(dist, 'tools'), { recursive: true, force: true });
}

console.log('build.mjs: wrote dist/ (index.html, support.js, styles.css, vendor/' + (fs.existsSync(toolsDir) ? ', tools/' : '') + ')');
