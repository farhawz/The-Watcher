# RAQIB

**RAQIB** is an AI-powered network reconnaissance and security analysis tool that combines Nmap with local LLMs through Ollama. It automatically converts raw scan results into structured security intelligence, including service identification, risk assessment, observations, and hardening recommendations.

> "Observe. Analyze. Reveal."

## Features
# RAQIB

**RAQIB** is an AI-powered network reconnaissance and security analysis tool that combines Nmap with local LLMs through Ollama. It automatically converts raw scan results into structured security intelligence — including per-service risk levels, CVE hints, attack surface mapping, and hardening recommendations — all processed locally with no cloud dependency.

> "Observe. Analyze. Reveal."

---

## Features

- 6 built-in scan profiles (quick, full, stealth, aggressive, udp, vuln)
- AI-powered structured analysis using Ollama (JSON output with risk scores)
- Per-service risk assessment with CVE hints
- Attack surface mapping and prioritized hardening recommendations
- Input validation and shell injection protection
- Timestamped output: raw nmap `.txt`, structured `.json`, combined report `.txt`
- Fully local processing — no cloud, no API keys
- Clean CLI with argparse — scriptable and pipeline-friendly

---

## Requirements

- Python 3.10+
- Nmap
- Ollama
- Internet connection (for initial model download only)

---

## Installation

### 1. Clone Repository

```bash
git clone https://github.com/farhawz/The-Watcheer
cd The-Watcheer
```

### 2. Install Python Dependencies

```bash
pip install requests
```

On Kali Linux:

```bash
pip install requests --break-system-packages
```

### 3. Install Nmap

Ubuntu / Debian / Kali:

```bash
sudo apt update && sudo apt install nmap
nmap --version
```

### 4. Install Ollama

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama --version
```

### 5. Pull an AI Model

```bash
ollama pull qwen2.5-coder:7b
```

Other supported models:

```bash
ollama pull mistral:7b
ollama pull deepseek-coder:6.7b
```

### 6. Start Ollama

```bash
ollama serve
```

Default API endpoint: `http://localhost:11434` — keep this terminal running.

---

## Usage

```bash
python3 raqibscan.py -t <target> [options]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-t`, `--target` | Target IP, hostname, or CIDR range | *(required)* |
| `--scan-type` | Scan profile to use | `quick` |
| `--ports` | Custom port list or range (e.g. `22,80,443` or `1-1024`) | — |
| `--model` | Ollama model for analysis | `qwen2.5-coder:7b` |
| `--output` | Directory to save results | `raqib_results/` |
| `--no-ai` | Skip AI analysis, show raw nmap output only | — |
| `--no-save` | Don't save results to disk | — |

### Scan Profiles

| Profile | Description | Requires Root |
|---------|-------------|---------------|
| `quick` | Fast scan of top 100 ports | No |
| `full` | Full port range with default scripts | No |
| `stealth` | SYN stealth scan | Yes |
| `aggressive` | OS detection, version, scripts, traceroute | No |
| `udp` | Top 50 UDP ports | Yes |
| `vuln` | Vulnerability scan using nmap scripts | No |

---

## Examples

```bash
# Basic scan with AI analysis
python3 raqibscan.py -t scanme.nmap.org

# Full scan with a different model
python3 raqibscan.py -t 192.168.1.1 --scan-type full --model mistral:7b

# Stealth scan (run as root)
sudo python3 raqibscan.py -t 10.0.0.1 --scan-type stealth

# Specific ports only
python3 raqibscan.py -t example.com --ports 22,80,443,8080

# Vuln scan, save to custom directory
python3 raqibscan.py -t 192.168.1.100 --scan-type vuln --output ./reports

# Raw nmap output only, no AI, no saving
python3 raqibscan.py -t 192.168.1.0/24 --no-ai --no-save
```

---

## Workflow

```
Target (IP / Hostname / CIDR)
         │
         ▼
   Input Validation
         │
         ▼
  Nmap Scan (profile-based)
         │
         ▼
    Raw Nmap Output
         │
    ┌────┴────┐
    │         │
    ▼         ▼
 Save      Ollama AI
 .txt      Analysis
    │         │
    └────┬────┘
         ▼
  Structured JSON Report
  (risk score, services,
   CVEs, attack surface,
   hardening recs)
         │
         ▼
  Save .json + .txt Report
```

---

## Output

Each scan saves three files to the output directory:

```
raqib_results/
├── raqib_<target>_<timestamp>_nmap.txt       # Raw nmap output
├── raqib_<target>_<timestamp>_analysis.json  # Structured AI analysis
└── raqib_<target>_<timestamp>_report.txt     # Combined human-readable report
```

### Sample AI Analysis (JSON)

```json
{
  "risk_level": "HIGH",
  "risk_score": 7,
  "summary": "Three services exposed including an outdated OpenSSH version...",
  "open_services": [
    {
      "port": "22/tcp",
      "service": "ssh",
      "version": "OpenSSH 7.4",
      "risk": "HIGH",
      "notes": "EOL version, vulnerable to multiple CVEs"
    }
  ],
  "observations": ["FTP allows anonymous login", "HTTP server exposes version info"],
  "attack_surface": ["SSH brute-force", "Anonymous FTP access"],
  "hardening_recommendations": [
    { "priority": "HIGH", "action": "Upgrade OpenSSH to 9.x" },
    { "priority": "HIGH", "action": "Disable anonymous FTP" }
  ],
  "cve_hints": ["CVE-2018-15473", "CVE-2017-15906"]
}
```

---

## Project Structure

```
RAQIB/
├── raqibscan.py
├── README.md
└── requirements.txt
```

---

## Disclaimer

RAQIB is intended for educational purposes, lab environments, and authorized security assessments only. Unauthorized scanning of systems you do not own or have explicit permission to test is illegal. The author assumes no responsibility for misuse.

---

## License

MIT License
* Automated Nmap scanning
* AI-powered analysis using Ollama
* Service and version detection
* Risk-level assessment
* Security observations
* Hardening recommendations
* Local processing (no cloud required)
* Fast and lightweight

## Requirements

* Python 3.10+
* Nmap
* Ollama
* Internet connection (for initial model download)

---

## Installation

### 1. Clone Repository

```bash
git clone https://github.com/farhawz/The-Watcheer
cd The-Watcheer
```

### 2. Install Python Dependencies

```bash
pip install requests
```

On Kali Linux:

```bash
pip install requests --break-system-packages
```

### 3. Install Nmap

Ubuntu / Debian / Kali:

```bash
sudo apt update
sudo apt install nmap
```

Verify installation:

```bash
nmap --version
```

---

## Install Ollama

### Linux

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Verify installation:

```bash
ollama --version
```

---

## Download AI Model

Example:

```bash
ollama pull qwen2.5-coder:7b
```

Other supported models:

```bash
ollama pull mistral:7b
ollama pull deepseek-coder:6.7b
```

---

## Start Ollama

```bash
ollama serve
```

Default API endpoint:

```text
http://localhost:11434
```

Keep this terminal running.

---

## Usage

Open another terminal:

```bash
python3 RAQIBscanner.py
```

Enter target:

```text
Enter target IP or hostname: scanme.nmap.org
```

RAQIB will:

1. Run Nmap
2. Collect scan results
3. Send data to Ollama
4. Generate AI-powered security analysis

---

## Example Workflow

```text
Target
   │
   ▼
Nmap Scan
   │
   ▼
Raw Results
   │
   ▼
Ollama AI
   │
   ▼
Security Analysis
```

---

## Project Structure

```text
RAQIB/
├── RAQIBscanner.py
├── README.md
└── requirements.txt
```

---

## Disclaimer

RAQIB is intended for educational purposes, lab environments, and authorized security assessments only. Users are responsible for ensuring they have permission to scan any target systems.

## License

MIT License

