// scan-patterns handling. @actions/glob does NOT expand braces ({js,ts} matches nothing), so the
// action's own default pattern silently matched zero files from v1.0.0 until 1.4.2. Expand braces
// here, accept one pattern per line, and keep a leading "!" (exclude) intact.
const expand = require('brace-expansion');

function expandPatterns(input) {
  const out = [];
  for (const raw of String(input || '').split('\n')) {
    const p = raw.trim();
    if (!p) continue;
    const neg = p.startsWith('!');
    const body = neg ? p.slice(1) : p;
    for (const e of expand(body)) out.push((neg ? '!' : '') + e);
  }
  return out;
}

module.exports = { expandPatterns };
