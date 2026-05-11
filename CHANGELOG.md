# API Sentinel - Changelog

## [1.2.0] - 2026-05-11
### Added
- Turbo-Charged Concurrency Engine using `ThreadPoolExecutor`.
- Global TCP Connection Pooling via `requests.Session()` to reduce SSL handshake overhead.
- Anti-DDoS Adaptive Rate Limit Backoff (auto-pauses on `429 Too Many Requests`).
- Circuit Breaker Pattern to skip chronically unresponsive endpoints.
- FontAwesome iconography and Cyberpunk styling to the Vis.js Topology Map.

### Fixed
- Eliminated False Positives in `CmdInj` and `NoSQLi` modules by implementing strict regular expressions (`uid=0(root)`).

## [1.1.0] - 2026-05-09
### Added
- Advanced OSINT Reconnaissance engine using the Wayback Machine CDX API.
- Live Differential Firewall tracking to identify hidden shadow APIs.
- Out-of-Band Application Security Testing (OAST) listener integration.
