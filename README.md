# API Sentinel

An Enterprise-Grade Dynamic Application Security Testing (DAST) tool designed for APIs.

## Features
- **Turbo-Charged Concurrency Engine:** Uses `ThreadPoolExecutor` and `requests.Session()` pooling to scan 15 endpoints simultaneously with zero latency.
- **Maltego-Inspired Topology Map:** Visualizes backend architecture with an interactive D3/Vis.js graph.
- **OSINT Shadow API Discovery:** Automatically scrapes the Wayback Machine to find undocumented "shadow" APIs.
- **Out-of-Band (OAST) Listener:** Catch blind Command Injection and blind SSRF callbacks.

## Setup
1. `pip install -r requirements.txt`
2. `python manage.py runserver`
