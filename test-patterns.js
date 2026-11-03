// node test-patterns.js : the shipped default must expand, must match real files, and must not reach secrets.
const assert = require('assert');
const fs = require('fs'), os = require('os'), path = require('path');
const glob = require('@actions/glob');
const { expandPatterns, isSecretFile, isConfigFile, redact } = require('./patterns');

// Read the real default out of action.yml so this test cannot drift from what ships.
const yml = fs.readFileSync(path.join(__dirname, 'action.yml'), 'utf8');
const block = yml.split('\n'); const i0 = block.findIndex(l => /^  scan-patterns:/.test(l));
const d0 = block.findIndex((l, i) => i > i0 && /^\s+default: \|/.test(l));
const DEF = []; for (let i = d0 + 1; i < block.length && /^\s{6}\S/.test(block[i]); i++) DEF.push(block[i].trim());
const DEFAULT = DEF.join('\n');

let pass = 0; const ok = (n, c) => { assert.ok(c, n); pass++; console.log('  ok  ' + n); };
const ex = expandPatterns(DEFAULT);
ok('default expands: 10 extensions + 2 excludes, no braces left', ex.length === 12 && ex.every(p => !p.includes('{')));
ok('default does not scan .env, .ini, .cfg or .conf', !ex.some(p => /\.(env|ini|cfg|conf)$/.test(p)));
ok('default excludes node_modules and .git', ex.includes('!**/node_modules/**') && ex.includes('!**/.git/**'));
ok('multi-line input accepted, blanks dropped', expandPatterns('**/*.js\n\n  **/*.md  ').length === 2);
ok('exclude prefix survives expansion', expandPatterns('!**/*.{min.js,map}').every(p => p.startsWith('!')) && expandPatterns('!**/*.{min.js,map}').length === 2);
ok('empty input gives no patterns', expandPatterns('').length === 0);

for (const f of ['.env', 'app/.env.local', 'id_rsa', 'keys/server.pem', 'aws-credentials.json', 'infra/terraform.tfvars', 'prod.tfstate', 'secrets.yaml', 'a/b/.npmrc', 'cert.p12'])
  ok('secret-bearing: ' + f, isSecretFile(f) === true);
for (const f of ['src/app.js', 'README.md', 'docs/environment.md', 'main.tf', 'package.json', 'src/keyboard.js'])
  ok('not secret-bearing: ' + f, isSecretFile(f) === false);
ok('config files recognised', isConfigFile('a/b.conf') && isConfigFile('x.ini') && !isConfigFile('x.js'));
const h = 'a'.repeat(64);
ok('an unverified hash is redacted, never echoed', !redact({ type: 'sha256', value: h }).includes('a'.repeat(20)) && redact({ type: 'sha256', value: h }).includes('redacted'));
ok('an IP is shown as is', redact({ type: 'ipv4', value: '203.0.113.9' }) === '203.0.113.9');

(async () => {
  const d = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'dgaction-')));
  fs.mkdirSync(path.join(d, 'node_modules'), { recursive: true });
  for (const f of ['a.js', 'b.md', 'c.tf', 'd.env', 'e.png', 'f.conf', '.env', 'node_modules/x.js']) fs.writeFileSync(path.join(d, f), 'x');
  const prev = process.cwd(); process.chdir(d);
  const g = await glob.create(ex.join('\n'), { followSymbolicLinks: false });
  const files = (await g.glob()).map(f => path.relative(d, f)).sort();
  process.chdir(prev);
  ok('default matches a.js, b.md, c.tf only', files.join(',') === 'a.js,b.md,c.tf');
  console.log('\n' + pass + ' passed');
})().catch(e => { console.error('FAIL', e.message); process.exit(1); });
