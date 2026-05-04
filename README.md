# DugganUSA Threat Intel Scan — GitHub Action

Scan PRs for IPs, domains, SHA256 hashes, and CVEs against 1,080,000+ threat indicators. Block merges containing known-bad indicators.

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
          api-key: ${{ secrets.DUGGANUSA_API_KEY }}  # optional
          fail-on-match: 'true'
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `api-key` | DugganUSA API key (optional) | `''` |
| `scan-patterns` | Glob pattern for files to scan | `**/*.{js,ts,py,json,yml,yaml,conf,cfg,ini,env,md,txt,tf,hcl}` |
| `fail-on-match` | Fail the action if threats found | `true` |
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

[analytics.dugganusa.com/stix/register](https://analytics.dugganusa.com/stix/register) — works without one at reduced rate limits.

## Part of the DugganUSA Ecosystem

- [VS Code Extension](https://marketplace.visualstudio.com/items?itemName=DugganUSALLC.dugganusa-threat-intel)
- [CLI Tool](https://github.com/pduggusa/dugganusa-cli) — `npx dugganusa-lookup`
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
