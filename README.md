# DugganUSA Threat Intel Scan — GitHub Action

Scan PRs for IPs, domains, SHA256 hashes, and CVEs against 1.5M+ threat indicators. Block merges containing known-bad indicators.

## What's New (v1.3.0)

- **The liveness loop is now wired.** When the scan finds indicators that match our corpus, the Action reports them back to `POST /api/v1/feed/hit` (`consumer_kind: action`, `action: observed`) so the [feed-efficacy](https://analytics.dugganusa.com/api/v1/feed-efficacy) axis reflects real consumption. Opt out with `report-hits: 'false'`. It sends **only the matched indicator** — never repo, file, branch, or actor — and never fails your build.
- **Supply-chain detection is the headline.** The corpus now ingests OSV malicious-package feeds for **both npm and PyPI** — named-malicious packages, zero-heuristic, daily — alongside daily GitHub Hunt detections of malware-staging repos and install-time execution signatures. Scan your `package.json`, `requirements.txt`, lockfiles, and CI config in the PR and catch a poisoned dependency before it merges.
- **Four live, no-auth, deploy-durable validation endpoints** prove feed quality behind the action:
  - **Novelty** — [feed-uniqueness](https://analytics.dugganusa.com/api/v1/feed-uniqueness): ~75%+ of what we publish ThreatFox doesn't have.
  - **Timeliness** — [kev-lead](https://analytics.dugganusa.com/api/v1/kev-lead): a live ledger of how far ahead of CISA KEV we flagged each exploited CVE — positive leads, same-day, and no-receipt all shown honestly, with receipts.
  - **Accuracy** — [spamhaus-validation](https://analytics.dugganusa.com/api/v1/spamhaus-validation): Spamhaus independently corroborates our first-hand contributions.
  - **Liveness** — [feed-efficacy](https://analytics.dugganusa.com/api/v1/feed-efficacy): consumer reports of when our indicators actually fire on real traffic — proof the feed is operationally live, not just large. **This Action reports to it** (see `report-hits` below): only the matched indicator is sent, never victim data.
- **STIX feed is now API-key-enforced** — pass a **free registered key** as `api-key` (anonymous requests get 401, unregistered Bearer gets 429). Register at [analytics.dugganusa.com/stix/register](https://analytics.dugganusa.com/stix/register).

## Usage

```yaml
name: Threat Scan
on: [pull_request, push]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pduggusa/dugganusa-action@v1
        with:
          api-key: ${{ secrets.DUGGANUSA_API_KEY }}  # free registered key — see below
          fail-on-match: 'true'
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `api-key` | DugganUSA API key — free registered key ([register](https://analytics.dugganusa.com/stix/register)) | `''` |
| `scan-patterns` | Glob pattern for files to scan | `**/*.{js,ts,py,json,yml,yaml,conf,cfg,ini,env,md,txt,tf,hcl}` |
| `fail-on-match` | Fail the action if threats found | `true` |
| `report-hits` | Report matched indicators to the [feed-efficacy](https://analytics.dugganusa.com/api/v1/feed-efficacy) liveness axis (`POST /api/v1/feed/hit`). Indicator-only — never repo/file/actor context. Requires `api-key`; non-fatal. Set `false` to opt out. | `true` |
| `format` | Output format: table, json, markdown | `table` |

## Outputs

| Output | Description |
|--------|-------------|
| `found` | Number of threat indicators found |
| `scanned` | Number of IOC candidates scanned |

## What It Does

1. Scans matched files for IOC patterns (IPv4, domain, SHA256, CVE)
2. Deduplicates and checks each against the DugganUSA correlation API
3. Annotates the PR with warnings for each match
4. Writes a GitHub Actions summary table
5. Optionally fails the check to block merge

## Free API Key

The STIX feed is API-key-enforced: anonymous requests get `401`, an unregistered Bearer gets `429`. The **free tier is a free *registered* key** — register at [analytics.dugganusa.com/stix/register](https://analytics.dugganusa.com/stix/register) and pass it as `api-key`.

## Part of the DugganUSA Ecosystem

- [VS Code Extension](https://marketplace.visualstudio.com/items?itemName=DugganUSALLC.dugganusa-threat-intel)
- [CLI Tool](https://github.com/pduggusa/dugganusa-cli) — `npx dugganusa-cli`
- [STIX Feed](https://analytics.dugganusa.com/api/v1/stix-feed)
- [dugganusa.com](https://www.dugganusa.com)

## License

MIT — [DugganUSA LLC](https://www.dugganusa.com)

---

<!-- DUGGANUSA-FAMILY-FOOTER-V1 -->
## DugganUSA Defender Family

Same threat corpus, surfaced wherever you live. Open source, MIT licensed, receipts on every repo.

| Plugin | Surface |
|---|---|
| [dugganusa-scanner-core](https://github.com/pduggusa/dugganusa-scanner-core) | Core IOC scanning engine |
| [dugganusa-vscode](https://github.com/pduggusa/dugganusa-vscode) | VS Code extension |
| [dugganusa-splunk](https://github.com/pduggusa/dugganusa-splunk) | Splunk Technology Add-on |
| [dugganusa-slack](https://github.com/pduggusa/dugganusa-slack) | Slack bot |
| [dugganusa-raycast](https://github.com/pduggusa/dugganusa-raycast) | Raycast extension |
| [dugganusa-sentinel](https://github.com/pduggusa/dugganusa-sentinel) | Microsoft Sentinel TAXII connector |
| [dugganusa-obsidian](https://github.com/pduggusa/dugganusa-obsidian) | Obsidian plugin |
| [dugganusa-nvim](https://github.com/pduggusa/dugganusa-nvim) | Neovim plugin |
| [dugganusa-elastic](https://github.com/pduggusa/dugganusa-elastic) | Elastic / OpenSearch integration |
| [dugganusa-edge-shield](https://github.com/pduggusa/dugganusa-edge-shield) | Cloudflare Worker |
| [dugganusa-cli](https://github.com/pduggusa/dugganusa-cli) | CLI scanner |
| [dugganusa-chrome](https://github.com/pduggusa/dugganusa-chrome) | Chrome extension |
| **dugganusa-action** _(this repo)_ | GitHub Action |
| [dredd-mcp](https://github.com/pduggusa/dredd-mcp) | Pre-flight MCP security (this repo) |

Backed by the live DugganUSA threat intel platform: [analytics.dugganusa.com](https://analytics.dugganusa.com).

_Jeevesus saves. Dredd judges._
