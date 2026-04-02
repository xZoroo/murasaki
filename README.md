# 紫 - murasaki

A purple team adversary emulation planner powered by agentic AI. Given your industry vertical and asset profile, murasaki identifies the most relevant threat actor groups, prioritizes ATT&CK TTPs by likelihood and impact, and generates a full adversary emulation plan — including Atomic Red Team test GUIDs, Caldera ability IDs, Splunk SPL detection queries, and platform-agnostic detection hypotheses.

Output is four ready-to-use files: a Markdown report, a self-contained HTML report, a Caldera adversary profile (importable directly into the UI), and an Invoke-AtomicRedTeam PowerShell runner.

---

## How it works

murasaki runs a multi-turn agentic loop backed by Claude (via AWS Bedrock or the Anthropic API). The model is given a set of tools to query real threat intelligence data and reasons autonomously about what to look up:

1. **Threat actor identification** — searches MITRE ATT&CK for groups known to target your industry and asset profile
2. **TTP prioritization** — pulls each group's attributed techniques, scores them by likelihood and impact, and selects the top N
3. **Emulation plan assembly** — for each TTP, fetches Atomic Red Team test GUIDs from Red Canary's repo and Caldera stockpile ability IDs from MITRE's repo, then generates Splunk SPL queries and detection hypotheses grounded in ATT&CK data sources

The agent only uses data returned by its tools — it does not fabricate technique IDs, GUIDs, or ability IDs.

Typical run: **8–18 API calls** to Claude for a `--top-n 15` plan. Hard cap is 25 iterations.

---

## Requirements

- Python 3.13
- [uv](https://docs.astral.sh/uv/getting-started/installation/) — for virtual environment and dependency management
- One of the authentication options below

---

## Installation

```bash
git clone https://github.com/NFL-ISO/murasaki.git
cd murasaki
uv venv .venv
source .venv/bin/activate
uv pip install -e .
```

Verify:

```bash
murasaki --help
```

> **Every new terminal session:** run `source .venv/bin/activate` before using `murasaki`. Your prompt will show `(.venv)` when it's active. On Windows: `.venv\Scripts\activate`

---

## Authentication

Pick one method. murasaki checks for credentials in this order:

1. `AWS_BEARER_TOKEN_BEDROCK` env var → Bedrock API key (no IAM needed)
2. `--api-key` / `MURASAKI_API_KEY` env var → Anthropic API directly
3. Default AWS credential chain → Bedrock via IAM

### Option A — AWS Bedrock API key (no IAM credentials needed)

```bash
export AWS_BEARER_TOKEN_BEDROCK=your-bedrock-api-key
```

### Option B — Anthropic API key

```bash
export MURASAKI_API_KEY=sk-ant-...
```

Or pass it inline: `murasaki --api-key sk-ant-... --vertical ...`

### Option C — AWS Bedrock with IAM credentials

Ensure **Claude claude-sonnet-4-6** is enabled in your AWS account under **Amazon Bedrock → Model access**.

```bash
# Environment variables
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-east-1

# Or use a named profile
aws configure --profile my-profile
murasaki --aws-profile my-profile --vertical ...
```

---

## Usage

### Minimal

```bash
murasaki --vertical "financial services" --assets "Active Directory,SWIFT,Bloomberg Terminal,AWS"
```

Reports are written to `./murasaki-output/` by default.

### Named engagement (recommended)

```bash
murasaki --name "BankofMarina-Q2-2026" --vertical "financial services" --assets "Active Directory,SWIFT,Bloomberg Terminal" --top-n 20
```

Produces: `BankofMarina-Q2-2026.md`, `BankofMarina-Q2-2026.html`, `BankofMarina-Q2-2026-caldera.yml`, `BankofMarina-Q2-2026-art-runner.ps1`

### All options

```bash
murasaki --name "Engagement-Name" --vertical "healthcare" --assets "Epic EHR,Active Directory,AWS,VPN" --platforms "Windows,Linux" --top-n 20 --output-dir ./reports --format both --verbose
```

---

## Options reference

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--vertical` | yes | — | Industry vertical. Accepted values: `financial services` \| `healthcare` \| `energy` \| `retail` \| `manufacturing` \| `government` \| `technology` \| `education` |
| `--assets` | yes | — | Comma-separated key assets in your environment (e.g. `Active Directory,AWS,SWIFT`) |
| `--platforms` | no | `Windows,Linux` | Target platforms. Accepted values: `Windows` \| `Linux` \| `macOS` |
| `--top-n` | no | `15` | Number of TTPs to prioritize (1–50) |
| `--name` | no | `murasaki-report` | Engagement name used as the output file stem (e.g. `BankofMarina-Q2-2026`) |
| `--output-dir` | no | `./murasaki-output` | Directory where all output files are written |
| `--format` | no | `both` | Report format: `markdown`, `html`, or `both` |
| `--aws-region` | no | `us-east-1` | AWS region for Bedrock (Options A and C) |
| `--aws-profile` | no | — | AWS named profile (Option C only) |
| `--api-key` | no | — | Anthropic API key (Option B). Also reads `MURASAKI_API_KEY` env var |
| `--no-cache` | no | off | Re-fetch all data from GitHub instead of using local cache |
| `--verbose` | no | off | Print each agent reasoning turn to the console |

---

## Output files

All four files are generated on every run and share the same stem (`--name` or `murasaki-report`):

| File | Description |
|------|-------------|
| `{name}.md` | Full Markdown report — share via Git, Confluence, or any Markdown viewer |
| `{name}.html` | Self-contained HTML with dark/light mode, color-coded scores, and ATT&CK links |
| `{name}-caldera.yml` | Caldera adversary profile — import via **Adversaries → Import** in the Caldera UI |
| `{name}-art-runner.ps1` | Invoke-AtomicRedTeam PowerShell runner with specific test GUIDs per technique |

### Import into Caldera

1. Open Caldera → **Adversaries** → **Import**
2. Select `{name}-caldera.yml`
3. The adversary is created with all mapped ability IDs ready to run

### Run Atomic Red Team tests

```powershell
# Prerequisites (one-time setup)
Install-Module -Name invoke-atomicredteam -Scope CurrentUser
Install-Module -Name powershell-yaml -Scope CurrentUser

# Execute the emulation plan
.\BankofMarina-Q2-2026-art-runner.ps1
```

Each technique block in the runner script uses `-TestGuids` to run only the specific tests identified during planning. Review each block before executing in your environment.

### What's in the reports

- **Executive summary** — narrative overview of the emulation scenario
- **Threat actor context** — identified groups, aliases, and why they're relevant to your vertical
- **Prioritized attack chain** — techniques ordered by kill chain phase, each with:
  - Likelihood and impact scores (1–5) with rationale
  - Atomic Red Team test GUIDs
  - Caldera stockpile ability IDs
  - Splunk SPL detection query
  - Platform-agnostic detection hypothesis
- **Methodology notes**

---

## Local data cache

On first run, murasaki downloads and caches external data to `~/.cache/murasaki/`:

| Cache file | Source | TTL |
|------------|--------|-----|
| `enterprise-attack.json` | MITRE ATT&CK STIX bundle | Permanent (delete to re-download) |
| `art/{technique_id}.json` | Atomic Red Team GitHub | Permanent (`--no-cache` to refresh) |
| `caldera_index.json` | Caldera stockpile GitHub | 24 hours (auto-refreshes) |

---

## Development

```bash
uv pip install -e ".[dev]"
python -m pytest tests/ -q
ruff check murasaki/ tests/
ruff format murasaki/ tests/
```

---

## Data sources

| Source | What it provides |
|--------|-----------------|
| [MITRE ATT&CK](https://attack.mitre.org) | Threat actor groups, technique attribution, data sources |
| [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) | Test GUIDs and executor details per technique |
| [Caldera Stockpile](https://github.com/mitre/stockpile) | Ability IDs for automated adversary emulation |

---

## Author

Built by **Cory** ([@NFL-ISO](https://github.com/NFL-ISO))

---

## Legal disclaimer

This tool is intended for **authorized security testing, purple team exercises, and defensive research only**. Use of murasaki to test systems or networks without explicit written authorization from the system owner is illegal and unethical.

The author is not responsible for any misuse or damage caused by this tool. All emulation activities should be conducted within the scope of an authorized engagement, with proper change-control approval, and in accordance with your organization's security policies and applicable laws.

ATT&CK® is a registered trademark of The MITRE Corporation.

---

## License

MIT
