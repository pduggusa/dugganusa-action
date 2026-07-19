const core = require('@actions/core');
const glob = require('@actions/glob');
const fs = require('fs');
const https = require('https');

// Inline IOC patterns (self-contained, no external core dep for Action reliability)
const PATTERNS = {
  ipv4: /\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b/g,
  domain: /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ai|dev|xyz|info|biz|co|me|app|cloud|online|site|tech|ru|cn|ir|kp|de|fr|nl|uk|au|br|jp|kr|sg|il|sa|ae)\b/gi,
  sha256: /\b[a-fA-F0-9]{64}\b/g,
  cve: /CVE-\d{4}-\d{4,7}/gi,
  onion: /\b[a-z2-7]{56}\.onion\b/g,
};

const SKIP_IPS = new Set(['0.0.0.0','127.0.0.1','255.255.255.255','10.0.0.1','192.168.0.1','192.168.1.1','172.16.0.1','8.8.8.8','8.8.4.4','1.1.1.1','1.0.0.1','9.9.9.9']);
const SKIP_DOMAINS = new Set(['github.com','google.com','microsoft.com','apple.com','amazon.com','cloudflare.com','mozilla.org','apache.org','example.com','localhost','npmjs.com','nodejs.org','w3.org','schema.org','dugganusa.com','youtube.com','twitter.com','linkedin.com','stackoverflow.com','wikipedia.org','reddit.com']);

function extractIOCs(text) {
  const iocs = [];
  for (const [type, regex] of Object.entries(PATTERNS)) {
    for (const m of text.matchAll(regex)) {
      if (type === 'ipv4' && SKIP_IPS.has(m[0])) continue;
      if (type === 'domain' && SKIP_DOMAINS.has(m[0].toLowerCase())) continue;
      iocs.push({ value: m[0], type });
    }
  }
  const seen = new Set();
  return iocs.filter(i => { if (seen.has(i.value.toLowerCase())) return false; seen.add(i.value.toLowerCase()); return true; });
}

function httpGet(url, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers, timeout: 10000 }, (res) => {
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => {
        // A non-2xx response (401 expired key, 429 rate limit, 5xx outage) often
        // still carries a parseable JSON error body. Parsing it and reading the
        // absent `correlations` as "no hits" is how an outage used to read as
        // clean. Treat any non-2xx as a failed lookup, not an empty one.
        if (res.statusCode < 200 || res.statusCode >= 300) {
          return reject(new Error('HTTP ' + res.statusCode));
        }
        try { resolve(JSON.parse(body)); } catch { reject(new Error('Invalid JSON')); }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
  });
}

function httpPostJson(url, headers, payload) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const body = JSON.stringify(payload);
    const opts = {
      method: 'POST',
      hostname: u.hostname,
      path: u.pathname + u.search,
      timeout: 10000,
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body), ...headers },
    };
    const req = https.request(opts, (res) => {
      let b = '';
      res.on('data', c => b += c);
      res.on('end', () => { try { resolve({ status: res.statusCode, json: JSON.parse(b) }); } catch { resolve({ status: res.statusCode, json: null }); } });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    req.write(body);
    req.end();
  });
}

// Report confirmed indicators back to the DugganUSA feed-efficacy (liveness) axis.
// PRIVACY CONTRACT: we send ONLY the indicators we already published (the threat
// infra found in scanned source) — never repo names, file paths, branch, actor, or
// any other workflow context. action='observed' (the scanner saw our indicator in
// source, it did not block live traffic); direction='unknown'. Non-fatal: a failed
// report never fails the Action. Requires an api-key (hits must be attributable).
async function reportFeedHit(found, apiKey) {
  if (!apiKey || !found.length) return;
  const ts = Date.now();
  const hits = found.map(r => ({ indicator: r.value, action: 'observed', direction: 'unknown', count: 1, ts }));
  try {
    const { status } = await httpPostJson(
      'https://analytics.dugganusa.com/api/v1/feed/hit',
      { Authorization: 'Bearer ' + apiKey },
      { consumer_kind: 'action', hits }
    );
    if (status >= 200 && status < 300) {
      core.info('DugganUSA: reported ' + hits.length + ' indicator hit(s) to the feed-efficacy axis.');
    } else {
      core.info('DugganUSA: feed-hit report returned HTTP ' + status + ' (non-fatal).');
    }
  } catch (e) {
    core.info('DugganUSA: feed-hit report skipped (' + e.message + ', non-fatal).');
  }
}

async function lookupIOC(value, apiKey) {
  const url = new URL('https://analytics.dugganusa.com/api/v1/search/correlate');
  url.searchParams.set('q', value);
  const headers = {};
  if (apiKey) headers['Authorization'] = 'Bearer ' + apiKey;
  try {
    const json = await httpGet(url.toString(), headers);
    const correlations = json.data?.correlations || {};
    const hits = Object.values(correlations).reduce((s, h) => s + (Array.isArray(h) ? h.length : 0), 0);
    return hits > 0
      ? { ok: true, status: 'found', found: true, hits, data: correlations }
      : { ok: true, status: 'not-found', found: false, hits: 0 };
  } catch (e) {
    // FAIL-CLOSED. Absence of evidence is not evidence of safety. This used to
    // return a bare { found: false }, which is byte-identical to a verified-clean
    // lookup -- so an expired key, a 429, a timeout, or a full API outage turned a
    // customer's PR security check GREEN. `status: 'unknown'` keeps the failure
    // distinguishable all the way up to the gate decision in run().
    // Some socket errors (ECONNREFUSED) carry an empty .message, so fall back to
    // .code -- the reason string is the operator's only clue about what broke.
    return { ok: false, status: 'unknown', found: false, hits: 0, error: e.message || e.code || 'unknown error' };
  }
}

function summarize(data) {
  if (!data) return '';
  const parts = [];
  for (const [idx, hits] of Object.entries(data)) {
    if (!Array.isArray(hits) || !hits.length) continue;
    const f = hits[0];
    if (idx === 'iocs') parts.push((f.malware_family || f.threat_type || '?') + ' (via ' + (f.source || '?') + ')');
    else if (idx === 'block_events') parts.push('Blocked ' + hits.length + 'x');
    else if (idx === 'pulses') parts.push(hits.length + ' pulse(s)');
    else if (idx === 'cisa_kev') parts.push('CISA KEV');
  }
  return parts.join(' | ');
}

async function run() {
  try {
    const apiKey = core.getInput('api-key');
    const scanPatterns = core.getInput('scan-patterns');
    const failOnMatch = core.getInput('fail-on-match') === 'true';
    // Defaults to whatever fail-on-match is set to: if you are using this Action as
    // a blocking gate, a lookup you could not complete is a gate you cannot honor.
    const failOnUnknownInput = core.getInput('fail-on-unknown');
    const failOnUnknown = failOnUnknownInput === '' ? failOnMatch : failOnUnknownInput === 'true';
    const reportHits = core.getInput('report-hits') !== 'false';
    const format = core.getInput('format');

    core.info('DugganUSA Threat Intel Scan — 1.5M+ IOCs');
    core.info('Scan pattern: ' + scanPatterns);

    // Find files
    const globber = await glob.create(scanPatterns, { followSymbolicLinks: false });
    const files = await globber.glob();
    core.info('Found ' + files.length + ' files to scan');

    // Extract IOCs from all files
    const allIOCs = new Map(); // value -> { type, files: [] }
    for (const file of files) {
      const text = fs.readFileSync(file, 'utf8');
      const iocs = extractIOCs(text);
      for (const ioc of iocs) {
        if (!allIOCs.has(ioc.value.toLowerCase())) {
          allIOCs.set(ioc.value.toLowerCase(), { value: ioc.value, type: ioc.type, files: [] });
        }
        allIOCs.get(ioc.value.toLowerCase()).files.push(file);
      }
    }

    core.info('Found ' + allIOCs.size + ' unique IOC candidates');

    if (!allIOCs.size) {
      core.info('No IOC candidates found. All clean.');
      core.setOutput('found', '0');
      core.setOutput('scanned', '0');
      return;
    }

    // Look up each IOC (cap at 50)
    const values = [...allIOCs.values()].slice(0, 50);
    const results = [];
    for (const ioc of values) {
      const r = await lookupIOC(ioc.value, apiKey);
      results.push({ ...ioc, ...r });
    }

    // Three outcomes, not two: confirmed threat / verified clean / LOOKUP FAILED.
    // `unknown` indicators were never actually checked -- the API did not answer.
    // Folding them in with the clean ones (the old `filter(r => r.found)` alone)
    // is what let an outage pass the gate silently.
    const found = results.filter(r => r.ok && r.found);
    const unknown = results.filter(r => !r.ok);
    const clean = results.filter(r => r.ok && !r.found);

    core.setOutput('found', String(found.length));
    core.setOutput('scanned', String(results.length));
    core.setOutput('unknown', String(unknown.length));
    core.setOutput('clean', String(clean.length));

    // Surface every unverified indicator as an annotation. Silence here would be
    // indistinguishable from a clean bill of health, which is the whole defect.
    if (unknown.length) {
      core.warning('DugganUSA: ' + unknown.length + ' indicator(s) could NOT be checked (lookup failed). These are UNVERIFIED, not clean.');
      for (const r of unknown) {
        core.warning(r.value + ' -- lookup failed: ' + (r.error || 'unknown error') + ' (in: ' + r.files.slice(0, 3).join(', ') + ')', {
          title: 'Threat Lookup Failed (unverified)',
        });
      }
    }

    // Output results
    if (found.length) {
      core.warning('DugganUSA: ' + found.length + ' threat indicator(s) found!');
      for (const r of found) {
        const summary = summarize(r.data);
        const fileList = r.files.slice(0, 3).join(', ');
        core.warning(r.value + ' — ' + summary + ' (in: ' + fileList + ')', {
          title: 'Threat Indicator Detected',
        });
      }

      if (failOnMatch) {
        core.setFailed('DugganUSA: ' + found.length + ' threat indicator(s) found in scanned files. See annotations above.');
      }
    } else if (unknown.length && unknown.length === results.length) {
      // Nothing was verified at all -- do NOT say "all clean".
      core.warning('DugganUSA: NO indicators could be verified (' + unknown.length + ' lookup failure(s)). This scan proves nothing.');
    } else {
      core.info('All clean. ' + clean.length + ' IOC candidate(s) verified clean, 0 matches.');
    }

    // A gate that could not complete its check must not report a pass. If the
    // caller asked us to block on threats, they are relying on this step to be a
    // real control -- and an unverified indicator is exactly the case where we
    // cannot honestly say the code is clean. Opt out with `fail-on-unknown: false`
    // (accepting that an API outage will then let the PR through).
    if (unknown.length && failOnUnknown) {
      core.setFailed('DugganUSA: ' + unknown.length + ' indicator(s) could not be verified (lookup failed). Failing closed -- absence of evidence is not evidence of safety. Set fail-on-unknown: false to override.');
    }

    // Report confirmed indicators to the feed-efficacy (liveness) axis.
    // Opt out with `report-hits: 'false'`. Non-fatal; indicator-only (see reportFeedHit).
    if (reportHits && found.length) {
      await reportFeedHit(found, apiKey);
    }

    // Summary
    core.summary
      .addHeading('DugganUSA Threat Intel Scan')
      .addTable([
        [{ data: 'Metric', header: true }, { data: 'Value', header: true }],
        ['Files scanned', String(files.length)],
        ['IOC candidates', String(allIOCs.size)],
        ['Checked against API', String(results.length)],
        ['Verified clean', String(clean.length)],
        ['Threat indicators found', String(found.length)],
        ['Unverified (lookup failed)', String(unknown.length)],
      ]);

    if (unknown.length) {
      core.summary.addHeading('Unverified Indicators', 3);
      const urows = [
        [{ data: 'Indicator', header: true }, { data: 'Reason', header: true }, { data: 'File(s)', header: true }],
      ];
      for (const r of unknown) {
        urows.push([r.value, r.error || 'unknown error', r.files.slice(0, 3).join(', ')]);
      }
      core.summary.addTable(urows);
      core.summary.addRaw('These indicators were NOT checked -- the lookup failed. They are unverified, not clean.');
    }

    if (found.length) {
      core.summary.addHeading('Threats Detected', 3);
      const rows = [
        [{ data: 'Indicator', header: true }, { data: 'Hits', header: true }, { data: 'Summary', header: true }, { data: 'File(s)', header: true }],
      ];
      for (const r of found) {
        rows.push([r.value, String(r.hits), summarize(r.data), r.files.slice(0, 3).join(', ')]);
      }
      core.summary.addTable(rows);
    }

    core.summary.addLink('DugganUSA STIX Feed', 'https://analytics.dugganusa.com/api/v1/stix-feed');
    core.summary.addLink('Free API Key', 'https://analytics.dugganusa.com/stix/register');
    await core.summary.write();

  } catch (error) {
    core.setFailed('DugganUSA Action error: ' + error.message);
  }
}

run();
