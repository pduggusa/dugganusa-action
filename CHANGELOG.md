# Changelog

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
