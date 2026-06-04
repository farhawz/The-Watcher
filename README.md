# RAQIB

**RAQIB** is an AI-powered network reconnaissance and security analysis tool that combines Nmap with local LLMs through Ollama. It automatically converts raw scan results into structured security intelligence, including service identification, risk assessment, observations, and hardening recommendations.

> "Observe. Analyze. Reveal."

## Features

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

