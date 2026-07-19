# Changelog

## [1.4.0] - 2026-07-19

### Security
- **Fixed a fail-open defect: a failed lookup was reported as "clean" and the gate passed.** Every error path in `lookupIOC` returned a bare `{ found: false }` — byte-identical to a verified-clean result. An expired API key, a 429, a timeout, or a full API outage therefore rendered as "All clean" and exited 0, turning a customer's PR security check GREEN while nothing had actually been checked.
- **`httpGet` never checked `res.statusCode`.** Non-2xx responses (401/429/5xx) carry a parseable JSON error body, which was parsed and its absent `correlations` read as "no hits". This was live: anonymous access to `/api/v1/search/correlate` now returns HTTP 401, so any run without an `api-key` (an optional input, default `''`) was reporting every indicator clean. Non-2xx is now a failed lookup, not an empty one.
- Lookups are now tri-state: `found` / `not-found` / `unknown`, matching `dugganusa-scanner-core` v1.3.0 (`ok`, `status`). `found` retained for backwards compatibility.
- Unverified indicators get their own warning annotations and summary table, and are never counted as clean.

### Added
- New `fail-on-unknown` input (defaults to the value of `fail-on-match`). A gate that could not complete its check does not report a pass. Set to `false` to accept the old behavior of letting outages through.
- New `unknown` and `clean` outputs.

## [1.3.1] - 2026-06-30

### Security
- Cleared all 9 Dependabot alerts (3 high, 4 moderate, 2 low) — all were the transitive `undici` (`< 6.27.0`, WebSocket/fetch paths not exercised by this Action, flagged by version range). Added an `overrides` forcing `undici ^6.27.0` and bumped `@actions/core` to `^1.11.1` / `@actions/glob` to `^0.5.0`. `npm audit` now reports 0 vulnerabilities. Action runs on `node20`, so undici 6 (Node ≥18) is in range.

## [1.3.0] - 2026-06-30

### Added
- **Feed-efficacy hit reporting (liveness loop).** When the scan finds indicators that match the DugganUSA corpus, the Action now reports them to `POST /api/v1/feed/hit` (`consumer_kind: 'action'`, `action: 'observed'`, `direction: 'unknown'`), closing the Liveness validation axis (`/api/v1/feed-efficacy`). Opt out with `report-hits: 'false'`; requires `api-key` (hits must be attributable). Reporting is non-fatal — a failed report never fails your build.
- New `report-hits` input (default `true`).
- **Privacy contract:** the Action sends ONLY the matched indicator values — never repo names, file paths, branch, actor, or any other workflow context. (The platform also drops any victim-side field server-side.)

## [1.2.2] - 2026-06-30

### Fixed
- Aligned in-tool/runtime IOC-count strings to 1.5M+ (the v1.2.1 docs refresh updated the README but missed the strings the tool prints at runtime).

## [1.2.1] - 2026-06-30

### Added
- Documented the fourth live validation axis — Liveness (`/api/v1/feed-efficacy`) — alongside novelty, timeliness, and accuracy. Consumers can opt in to report hits via `POST /api/v1/feed/hit` (privacy-preserving — only the matched indicator is sent, never victim data).

### Changed
- Refreshed IOC corpus copy to 1.5M+ IOCs (~1.57M live) across README, `action.yml`, and `package.json`.
- Reworded the Timeliness validation bullet to point at the live kev-lead ledger instead of a fixed "~31 days ahead" average (the live ledger is the source of truth).

## 1.2.0

- Led with supply-chain PR scanning: the corpus now ingests OSV malicious-package feeds for both npm and PyPI (named-malicious, zero-heuristic, daily) plus daily GitHub Hunt malware-staging-repo and install-time execution-signature detections — scan manifests/lockfiles and block poisoned dependencies before merge.
- Documented the three live, no-auth, deploy-durable validation endpoints: feed-uniqueness (novelty, ~75%+ unique vs ThreatFox), kev-lead (timeliness, ~31 days ahead of CISA KEV), spamhaus-validation (accuracy).
- Corrected for API-key enforcement: the STIX feed returns 401 anonymous / 429 unregistered. The `api-key` input is a free *registered* key — removed "free tier works without one" / "works without one" copy in README and action.yml.
- Aligned IOC count to 1.10M+ across README and action.yml.
- Fixed dead `npx dugganusa-lookup` reference to `npx dugganusa-cli`.

## 1.1.0

- Scan matched files for IOC patterns, dedupe, correlate, annotate PR, write summary table, optional fail-on-match.
