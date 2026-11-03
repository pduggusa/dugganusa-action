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

// Files that routinely hold secrets are skipped by name even when a pattern matches them, unless the
// workflow sets include-secret-files: true. A 64-character hex string in one of them is far more likely
// to be a token than a file hash, and candidates are sent to the lookup API.
const SECRET_FILE = /(^|\/)(\.env(\..*)?|\.npmrc|\.netrc|\.pypirc|\.git-credentials|id_(rsa|dsa|ecdsa|ed25519)(\.pub)?|[^/]*credentials[^/]*|[^/]*secrets?\.[a-z]+|terraform\.tfvars|[^/]*\.auto\.tfvars|[^/]*\.tfstate(\.backup)?)$|\.(pem|key|p12|pfx|jks|keystore|kdbx)$/i;
const isSecretFile = (f) => SECRET_FILE.test(String(f || '').replace(/\\/g, '/'));

// Config-style files are scanned for IPs and domains, but a bare 64-hex string there is not treated as a hash.
const CONFIG_FILE = /\.(ini|cfg|conf|properties|toml|env)$/i;
const isConfigFile = (f) => CONFIG_FILE.test(String(f || ''));

// An UNVERIFIED hash may be a secret: never echo it into a log or job summary (public in public repos).
const redact = (r) => (r && r.type === 'sha256')
  ? String(r.value).slice(0, 8) + '\u2026 (64 hex characters, redacted)'
  : (r && r.value);

module.exports = { expandPatterns, isSecretFile, isConfigFile, redact };
