// node test-patterns.js : the default pattern must expand and must match real files. Zero is a failure.
const assert = require('assert');
const fs = require('fs'), os = require('os'), path = require('path');
const glob = require('@actions/glob');
const { expandPatterns } = require('./patterns');
const DEF = '**/*.{js,ts,py,json,yml,yaml,conf,cfg,ini,env,md,txt,tf,hcl}';
let pass = 0; const ok = (n, c) => { assert.ok(c, n); pass++; console.log('  ok  ' + n); };
const ex = expandPatterns(DEF);
ok('default pattern expands to 14 patterns', ex.length === 14 && ex.includes('**/*.tf') && ex.every(p => !p.includes('{')));
ok('multi-line input is accepted and blank lines dropped', expandPatterns('**/*.js\n\n  **/*.md  ').length === 2);
ok('exclude prefix survives expansion', expandPatterns('!**/*.{min.js,map}').every(p => p.startsWith('!')) && expandPatterns('!**/*.{min.js,map}').length === 2);
ok('empty input gives no patterns', expandPatterns('').length === 0);
(async () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'dgaction-'));
  for (const f of ['a.js', 'b.md', 'c.tf', 'd.env', 'e.png']) fs.writeFileSync(path.join(d, f), 'x');
  const prev = process.cwd(); process.chdir(d);
  const g = await glob.create(expandPatterns(DEF).join('\n'), { followSymbolicLinks: false });
  const files = (await g.glob()).map(f => path.basename(f)).sort();
  process.chdir(prev);
  ok('default pattern matches the 4 scannable files and not the png', files.join(',') === 'a.js,b.md,c.tf,d.env');
  const raw = await (await glob.create(DEF, { followSymbolicLinks: false })).glob();
  console.log('  (info) the UNEXPANDED default matches', raw.length, 'file(s) in the repo: the bug this release fixes)');
  console.log('\n' + pass + ' passed');
})().catch(e => { console.error('FAIL', e.message); process.exit(1); });
