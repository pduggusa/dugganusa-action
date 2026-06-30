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
      res.on('end', () => { try { resolve(JSON.parse(body)); } catch { reject(new Error('Invalid JSON')); } });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
  });
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
    return hits > 0 ? { found: true, hits, data: correlations } : { found: false, hits: 0 };
  } catch (e) { return { found: false, hits: 0, error: e.message }; }
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

    const found = results.filter(r => r.found);
    core.setOutput('found', String(found.length));
    core.setOutput('scanned', String(results.length));

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
    } else {
      core.info('All clean. ' + results.length + ' IOC candidates checked, 0 matches.');
    }

    // Summary
    core.summary
      .addHeading('DugganUSA Threat Intel Scan')
      .addTable([
        [{ data: 'Metric', header: true }, { data: 'Value', header: true }],
        ['Files scanned', String(files.length)],
        ['IOC candidates', String(allIOCs.size)],
        ['Checked against API', String(results.length)],
        ['Threat indicators found', String(found.length)],
      ]);

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
