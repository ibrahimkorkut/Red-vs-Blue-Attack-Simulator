## Cyber Research Lab Platform

This project is an **advanced CyberSecurity Research Lab Platform** designed
**strictly for educational, simulation, and defensive security engineering
purposes**.

- No real exploit generation
- No real brute-force attacks
- No credential harvesting
- No network disruption

All "attack" behaviour is modelled as **synthetic events and logs only** to
support research, detection science, and model training.

### Key Components

- **Red Simulation Agent**: Generates synthetic attack-style patterns
  (brute force, credential stuffing, port scanning, web injection attempts,
  WiFi deauthentication patterns) as structured logs only.
- **Blue Defense Agent**: Consumes logs/datasets, detects suspicious patterns,
  scores risk, and produces JSON + HTML reports.
- **Defensive Modules**:
  - `scan-ports`: safe, rate-limited TCP connect scanning and basic banner probing.
  - `scan-web`: non-destructive same-domain web configuration scanner that
    checks security headers, open directory listings, and sensitive files,
    while respecting `robots.txt` where configured.

### Usage (CLI)

Install dependencies:

```bash
pip install -r requirements.txt
```

Run a synthetic brute-force simulation:

```bash
python cli.py simulate --scenario brute_force --count 200
```

Analyze synthetic logs with the Blue Agent:

```bash
python cli.py analyze-logs --input logs/simulations/brute_force.jsonl --output reports/analysis
```

Run a safe port scan:

```bash
python cli.py scan-ports --target 127.0.0.1 --ports 1-1024
```

Run the non-destructive web scanner:

```bash
python cli.py scan-web --url https://example.com
```

### Legal Disclaimer

This CyberSecurity Research Lab Platform is intended **solely for educational,
research, simulation, and defensive security engineering purposes**.

- It **does not** generate real exploit payloads or perform destructive attacks.
- All "attack" behaviours are **synthetic simulations** (logs, synthetic traffic
  patterns, or static strings) designed to support detection research and
  training.
- Network scanning, web scanning, and packet analysis features are provided
  **exclusively for defensive assessment of systems that you own or are
  explicitly authorised to test**.

By using this software, you agree to:

- Comply with all applicable laws and regulations.
- Obtain proper, written authorisation before assessing any environment.
- Accept full responsibility for any actions performed with this tool.

The authors and contributors assume **no liability** for misuse or damage
caused by this software.

