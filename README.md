# murasaki

A purple team adversary emulation planner powered by agentic AI. Given your industry vertical and asset profile, murasaki identifies the most relevant threat actor groups, prioritizes ATT&CK TTPs by likelihood and impact, and generates a full adversary emulation plan — including Atomic Red Team test GUIDs, Caldera ability IDs, Splunk SPL detection queries, and platform-agnostic detection hypotheses.

Output is a pair of reports (Markdown + self-contained HTML) ready to share with your red and blue teams.

---

## How it works

murasaki runs a two-phase agentic loop backed by Claude:

1. **TTP Prioritization** — the agent calls MITRE ATT&CK to identify threat groups targeting your vertical, pulls their attributed techniques, and scores each one for likelihood and impact against your specific asset profile.
2. **Emulation Plan Generation** — for each prioritized TTP, the agent fetches Atomic Red Team test GUIDs (compatible with Invoke-AtomicRedTeam and Caldera) and Caldera stockpile ability IDs, then generates Splunk SPL detection queries and generic detection hypotheses grounded in ATT&CK data sources.

The agent uses only data returned by its tools — it does not fabricate technique IDs, GUIDs, or ability IDs.

---

## Requirements

- Python 3.13
- [uv](https://docs.astral.sh/uv/getting-started/installation/) — for virtual environment and dependency management
- One of:
  - **AWS account** with Bedrock access and Claude claude-sonnet-4-6 enabled in your region
  - **Anthropic API key** from [console.anthropic.com](https://console.anthropic.com)

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/murasaki.git
cd murasaki

# Create virtual environment
uv venv .venv

# Activate it — you must do this before installing or running murasaki
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# Install murasaki into the active venv
uv pip install -e .
```

Verify the install:

```bash
murasaki --help
```

> **Important:** You need to activate the virtual environment every time you open a new terminal before using `murasaki`:
> ```bash
> source .venv/bin/activate
> ```
> You'll know it's active when your prompt shows `(.venv)`. Without activation, the shell won't find the `murasaki` command.

---

## Authentication

murasaki supports three authentication modes. Use whichever matches your setup.

### Option A — AWS Bedrock API key (simplest — no IAM needed)

If you have a Bedrock API key (Bearer token), just export it and run — no AWS access/secret keys required:

```bash
export AWS_BEARER_TOKEN_BEDROCK=your-bedrock-api-key
```

murasaki detects this variable automatically and routes requests to Bedrock using a Bearer token (`x-amzn-api-key` header). This is the easiest way to use Bedrock without configuring IAM credentials.

### Option B — Anthropic API key

Get an API key from [console.anthropic.com](https://console.anthropic.com) and either pass it on the command line or set the environment variable:

```bash
export MURASAKI_API_KEY=sk-ant-...
```

When `MURASAKI_API_KEY` is set, murasaki calls `api.anthropic.com` directly. No AWS credentials needed.

### Option C — AWS Bedrock IAM credentials

Ensure Claude claude-sonnet-4-6 is enabled in your AWS account under **Amazon Bedrock > Model access**.

Configure credentials using any standard AWS method:

```bash
# Environment variables
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-east-1

# Or AWS CLI profile
aws configure --profile my-profile
```

Then pass `--aws-profile my-profile` (or omit it to use the default credential chain).

---

## Usage

### Basic example

```bash
murasaki --vertical "financial services" --assets "Active Directory,SWIFT,Bloomberg Terminal,AWS"
```

Reports are written to `./murasaki-output/` by default.

### Full example with all options

```bash
murasaki --vertical "healthcare" --assets "Epic EHR,Active Directory,AWS,VPN" --platforms "Windows,Linux" --top-n 20 --output-dir ./reports/healthcare-q2 --format both --verbose
```

### Using a Bedrock API key

```bash
export AWS_BEARER_TOKEN_BEDROCK=your-bedrock-api-key
murasaki --vertical "energy" --assets "SCADA,Historian,Active Directory" --top-n 15
```

### Using an Anthropic API key

```bash
murasaki --api-key sk-ant-... --vertical "energy" --assets "SCADA,Historian,Active Directory" --top-n 15
```

### Using a specific AWS profile

```bash
murasaki --aws-profile security-team --aws-region us-west-2 --vertical "retail" --assets "POS systems,Active Directory,Azure AD"
```

---

## Options reference

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--vertical` | yes | — | Industry vertical. Accepted values: `financial services` \| `healthcare` \| `energy` \| `retail` \| `manufacturing` \| `government` \| `technology` \| `education` |
| `--assets` | yes | — | Comma-separated key assets (e.g. `Active Directory,AWS,SWIFT`) |
| `--platforms` | no | `Windows,Linux` | Comma-separated target platforms. Accepted values: `Windows` \| `Linux` \| `macOS` |
| `--top-n` | no | `15` | Number of TTPs to prioritize (1–50) |
| `--output-dir` | no | `./murasaki-output` | Directory for generated reports |
| `--format` | no | `both` | Output format: `markdown`, `html`, or `both` |
| `--aws-region` | no | `us-east-1` | AWS region for Bedrock |
| `--aws-profile` | no | — | AWS named profile; uses default credential chain if omitted |
| `--api-key` | no | — | Anthropic API key; overrides Bedrock. Also reads `MURASAKI_API_KEY` env var |
| `--no-cache` | no | off | Bypass Atomic Red Team and Caldera local disk cache |
| `--verbose` | no | off | Print each agent reasoning turn to the console |

---

## Output

murasaki writes two files to `--output-dir`:

| File | Description |
|------|-------------|
| `murasaki-report.md` | Full Markdown report — suitable for Git, Confluence, or any Markdown viewer |
| `murasaki-report.html` | Self-contained HTML report with dark/light mode, color-coded scores, and clickable ATT&CK technique links |

Each report contains:

- **Executive summary** — high-level narrative of the emulation scenario
- **Threat actor context** — which groups were identified and why they're relevant to your vertical
- **Prioritized attack chain** — TTPs ordered by kill chain phase, each with:
  - Likelihood and impact scores (1–5)
  - Rationale explaining why the TTP was selected
  - Atomic Red Team test GUIDs (usable with `Invoke-AtomicRedTeam` or Caldera)
  - Caldera stockpile ability IDs (paste directly into an adversary profile)
  - Splunk SPL detection query
  - Generic/platform-agnostic detection hypothesis
- **Methodology notes**

---

## Local data cache

On first run, murasaki downloads and caches data to `~/.cache/murasaki/`:

| Cache file | Source | TTL |
|------------|--------|-----|
| `enterprise-attack.json` | MITRE ATT&CK STIX bundle | Permanent (re-download by deleting the file) |
| `art/{technique_id}.json` | Atomic Red Team GitHub YAML | Permanent (re-download with `--no-cache`) |
| `caldera_index.json` | Caldera stockpile GitHub repo | 24 hours (auto-refreshes) |

Pass `--no-cache` to bypass all cached data and re-fetch everything fresh.

---

## Development

### Install with dev dependencies

```bash
uv pip install -e ".[dev]"
```

### Run tests

```bash
python -m pytest tests/ -q
```

### Lint and format

```bash
ruff check murasaki/ tests/
ruff format murasaki/ tests/
```

---

## Data sources

| Source | What it provides |
|--------|-----------------|
| [MITRE ATT&CK](https://attack.mitre.org) | Threat actor groups, technique attribution, data sources |
| [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) | Test GUIDs and executor commands for each technique |
| [Caldera Stockpile](https://github.com/mitre/stockpile) | Ability IDs for automated adversary emulation in Caldera |

---

## License

MIT
