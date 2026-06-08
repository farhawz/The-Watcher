#!/usr/bin/env python3
"""
RAQIB - AI-Powered Network Reconnaissance & Security Analysis Tool
"Observe. Analyze. Reveal."

Usage:
    python3 raqibscan.py -t scanme.nmap.org
    python3 raqibscan.py -t 192.168.1.1 --scan-type full --model mistral:7b
    python3 raqibscan.py -t 10.0.0.1 --scan-type stealth --output results/
    python3 raqibscan.py -t example.com --ports 22,80,443,8080 --no-ai
"""

import subprocess
import requests
import argparse
import json
import os
import sys
import re
import shutil
from datetime import datetime


# ─── CONFIGURATION ─────────────────────────────────────────────────────────────

OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_MODEL = "qwen2.5-coder:7b"
DEFAULT_OUTPUT_DIR = "raqib_results"

SCAN_PROFILES = {
    "quick": {
        "flags": ["-sV", "-T4", "--top-ports", "100"],
        "description": "Fast scan of top 100 ports"
    },
    "full": {
        "flags": ["-sV", "-sC", "-T4", "-p-"],
        "description": "Full port range with default scripts"
    },
    "stealth": {
        "flags": ["-sS", "-sV", "-T2", "-p-"],
        "description": "SYN stealth scan (requires root)"
    },
    "aggressive": {
        "flags": ["-A", "-T4"],
        "description": "OS detection, version, scripts, traceroute"
    },
    "udp": {
        "flags": ["-sU", "-sV", "-T4", "--top-ports", "50"],
        "description": "Top 50 UDP ports (requires root)"
    },
    "vuln": {
        "flags": ["-sV", "--script=vuln", "-T4"],
        "description": "Vulnerability scan using nmap scripts"
    }
}

SYSTEM_PROMPT = """You are RAQIB, an expert offensive security analyst and penetration tester with deep knowledge of network services, vulnerabilities, and hardening techniques.

Analyze the provided Nmap scan output and return a structured JSON response with exactly this format:
{
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "risk_score": <integer 0-10>,
  "summary": "<2-3 sentence executive summary>",
  "open_services": [
    {
      "port": "<port/proto>",
      "service": "<service name>",
      "version": "<version if detected>",
      "risk": "HIGH|MEDIUM|LOW",
      "notes": "<specific security note>"
    }
  ],
  "observations": ["<observation 1>", "<observation 2>", ...],
  "attack_surface": ["<potential attack vector 1>", ...],
  "hardening_recommendations": [
    {
      "priority": "HIGH|MEDIUM|LOW",
      "action": "<specific recommendation>"
    }
  ],
  "cve_hints": ["<relevant CVE or vulnerability class if version is detectable>"]
}

Be specific. If you see old software versions, flag them. If you see unnecessary services, call them out. Return ONLY valid JSON, no markdown, no extra text."""


# ─── VALIDATION ────────────────────────────────────────────────────────────────

def validate_target(target: str) -> bool:
    """Validate target is a safe IP address or hostname."""
    # Block obviously dangerous inputs
    dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '"', "'", '\\', '\n', '\r']
    if any(c in target for c in dangerous_chars):
        return False

    # Allow valid IPv4
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$'
    if re.match(ipv4_pattern, target):
        parts = target.split('/')[0].split('.')
        return all(0 <= int(p) <= 255 for p in parts)

    # Allow valid IPv6
    ipv6_pattern = r'^[0-9a-fA-F:]+$'
    if re.match(ipv6_pattern, target) and ':' in target:
        return True

    # Allow valid hostnames/domains
    hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,251}[a-zA-Z0-9])?$'
    if re.match(hostname_pattern, target) and len(target) <= 253:
        return True

    return False


def validate_ports(ports_str: str) -> bool:
    """Validate custom port specification."""
    pattern = r'^[\d,\-]+$'
    if not re.match(pattern, ports_str):
        return False
    for part in ports_str.split(','):
        if '-' in part:
            start, end = part.split('-', 1)
            if not (start.isdigit() and end.isdigit()):
                return False
            if not (0 <= int(start) <= 65535 and 0 <= int(end) <= 65535):
                return False
        else:
            if not part.isdigit() or not (0 <= int(part) <= 65535):
                return False
    return True


# ─── DEPENDENCY CHECKS ─────────────────────────────────────────────────────────

def check_dependencies(skip_ai: bool = False) -> bool:
    """Check required tools are installed."""
    ok = True

    if not shutil.which("nmap"):
        print("[ERROR] nmap is not installed or not in PATH.")
        print("        Install: sudo apt install nmap")
        ok = False

    if not skip_ai:
        try:
            r = requests.get("http://localhost:11434/api/tags", timeout=3)
            if r.status_code != 200:
                raise ConnectionError()
        except Exception:
            print("[ERROR] Ollama is not running on localhost:11434.")
            print("        Start it: ollama serve")
            print("        Or use --no-ai to skip AI analysis.")
            ok = False

    return ok


# ─── NMAP SCANNING ─────────────────────────────────────────────────────────────

def run_nmap(target: str, scan_type: str, custom_ports: str = None) -> tuple[str, int]:
    """
    Run nmap scan and return (stdout, return_code).
    Uses list-based subprocess call — safe against shell injection.
    """
    profile = SCAN_PROFILES[scan_type]
    cmd = ["nmap"] + profile["flags"]

    if custom_ports:
        cmd += ["-p", custom_ports]

    cmd.append(target)

    print(f"[*] Scan profile  : {scan_type} — {profile['description']}")
    print(f"[*] Command       : {' '.join(cmd)}\n")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute max
        )
    except subprocess.TimeoutExpired:
        return "", -1
    except FileNotFoundError:
        return "", -2

    if result.returncode != 0 and result.stderr:
        stderr = result.stderr.strip()
        if "requires root" in stderr.lower() or "you requested a scan type" in stderr.lower():
            print(f"[!] Permission error: {stderr}")
            print("[!] Try running with sudo for stealth/UDP scans.")
            return "", -3

    combined = result.stdout
    if result.stderr and result.stderr.strip():
        combined += f"\n[STDERR]: {result.stderr.strip()}"

    return combined, result.returncode


# ─── AI ANALYSIS ───────────────────────────────────────────────────────────────

def analyze_with_ai(nmap_output: str, model: str) -> dict:
    """
    Send nmap results to Ollama and parse structured JSON response.
    """
    prompt = f"Analyze this Nmap scan output:\n\n{nmap_output}"

    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": model,
                "system": SYSTEM_PROMPT,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.1,  # Low temp for consistent structured output
                    "num_predict": 2000
                }
            },
            timeout=120
        )
        response.raise_for_status()
    except requests.exceptions.ConnectionError:
        return {"error": "Cannot connect to Ollama. Is it running? (ollama serve)"}
    except requests.exceptions.Timeout:
        return {"error": "AI analysis timed out (>120s). Try a faster model."}
    except requests.exceptions.HTTPError as e:
        if response.status_code == 404:
            return {"error": f"Model '{model}' not found. Pull it first: ollama pull {model}"}
        return {"error": f"Ollama HTTP error: {e}"}

    raw = response.json().get("response", "")

    # Strip markdown fences if model added them
    clean = re.sub(r"```(?:json)?|```", "", raw).strip()

    try:
        return json.loads(clean)
    except json.JSONDecodeError:
        # Return raw text if JSON parse fails
        return {"error": "AI response was not valid JSON.", "raw_response": raw}


# ─── OUTPUT ────────────────────────────────────────────────────────────────────

def print_analysis(analysis: dict, target: str):
    """Pretty-print the AI analysis to terminal."""
    if "error" in analysis:
        print(f"[!] AI Error: {analysis['error']}")
        if "raw_response" in analysis:
            print("\n--- Raw AI Response ---")
            print(analysis["raw_response"])
        return

    RISK_COLORS = {
        "CRITICAL": "\033[91m",  # red
        "HIGH":     "\033[91m",
        "MEDIUM":   "\033[93m",  # yellow
        "LOW":      "\033[92m",  # green
        "INFO":     "\033[94m",  # blue
    }
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    risk = analysis.get("risk_level", "UNKNOWN")
    score = analysis.get("risk_score", "?")
    color = RISK_COLORS.get(risk, "")

    print(f"\n{'═'*60}")
    print(f"  RAQIB SECURITY ANALYSIS — {target}")
    print(f"{'═'*60}")
    print(f"\n  {BOLD}Risk Level:{RESET} {color}{risk} ({score}/10){RESET}")
    print(f"\n  {BOLD}Summary:{RESET}")
    print(f"  {analysis.get('summary', 'N/A')}")

    if analysis.get("open_services"):
        print(f"\n  {BOLD}Open Services:{RESET}")
        for svc in analysis["open_services"]:
            r = svc.get("risk", "?")
            rc = RISK_COLORS.get(r, "")
            print(f"   ├─ {svc.get('port','?'):15} {svc.get('service','?'):15} [{rc}{r}{RESET}]")
            if svc.get("version"):
                print(f"   │    Version : {svc['version']}")
            if svc.get("notes"):
                print(f"   │    Notes   : {DIM}{svc['notes']}{RESET}")

    if analysis.get("observations"):
        print(f"\n  {BOLD}Observations:{RESET}")
        for obs in analysis["observations"]:
            print(f"   • {obs}")

    if analysis.get("attack_surface"):
        print(f"\n  {BOLD}Attack Surface:{RESET}")
        for vec in analysis["attack_surface"]:
            print(f"   ⚠ {vec}")

    if analysis.get("hardening_recommendations"):
        print(f"\n  {BOLD}Hardening Recommendations:{RESET}")
        for rec in analysis["hardening_recommendations"]:
            p = rec.get("priority", "?")
            pc = RISK_COLORS.get(p, "")
            print(f"   [{pc}{p}{RESET}] {rec.get('action','')}")

    if analysis.get("cve_hints"):
        print(f"\n  {BOLD}CVE / Vuln Hints:{RESET}")
        for cve in analysis["cve_hints"]:
            print(f"   → {cve}")

    print(f"\n{'═'*60}\n")


def save_results(target: str, scan_output: str, analysis: dict, output_dir: str):
    """Save scan results and analysis to timestamped files."""
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = re.sub(r'[^\w\-.]', '_', target)
    base = os.path.join(output_dir, f"raqib_{safe_target}_{timestamp}")

    # Save raw nmap output
    with open(f"{base}_nmap.txt", "w") as f:
        f.write(scan_output)

    # Save AI analysis as JSON
    with open(f"{base}_analysis.json", "w") as f:
        json.dump({
            "target": target,
            "timestamp": timestamp,
            "analysis": analysis
        }, f, indent=2)

    # Save combined human-readable report
    with open(f"{base}_report.txt", "w") as f:
        f.write(f"RAQIB Security Report\n")
        f.write(f"Target    : {target}\n")
        f.write(f"Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"{'='*60}\n\n")
        f.write("NMAP OUTPUT\n")
        f.write(f"{'='*60}\n")
        f.write(scan_output)
        f.write(f"\n{'='*60}\n")
        f.write("AI ANALYSIS\n")
        f.write(f"{'='*60}\n")
        f.write(json.dumps(analysis, indent=2))

    print(f"[+] Results saved to: {output_dir}/")
    print(f"    ├─ {base}_nmap.txt")
    print(f"    ├─ {base}_analysis.json")
    print(f"    └─ {base}_report.txt")


# ─── CLI ───────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="raqibscan",
        description='RAQIB — AI-Powered Network Recon & Security Analysis. "Observe. Analyze. Reveal."',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Scan Profiles:
  quick      Fast scan of top 100 ports (default)
  full       Full port range with default scripts
  stealth    SYN stealth scan (requires root)
  aggressive OS detection, version, scripts, traceroute
  udp        Top 50 UDP ports (requires root)
  vuln       Vulnerability scan using nmap scripts

Examples:
  python3 raqibscan.py -t scanme.nmap.org
  python3 raqibscan.py -t 192.168.1.1 --scan-type full
  python3 raqibscan.py -t 10.0.0.1 --scan-type stealth --model mistral:7b
  python3 raqibscan.py -t example.com --ports 22,80,443,8080
  python3 raqibscan.py -t 192.168.1.0/24 --no-ai --output ./results
        """
    )

    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target IP, hostname, or CIDR range"
    )
    parser.add_argument(
        "--scan-type",
        choices=list(SCAN_PROFILES.keys()),
        default="quick",
        help="Scan profile to use (default: quick)"
    )
    parser.add_argument(
        "--ports",
        help="Custom port list or range (e.g. 22,80,443 or 1-1024)"
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help=f"Ollama model to use for analysis (default: {DEFAULT_MODEL})"
    )
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT_DIR,
        help=f"Directory to save results (default: {DEFAULT_OUTPUT_DIR})"
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Skip AI analysis, show raw nmap output only"
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Don't save results to disk"
    )

    return parser


# ─── MAIN ──────────────────────────────────────────────────────────────────────

def main():
    parser = build_parser()
    args = parser.parse_args()

    print("""
 ██████╗  █████╗  ██████╗ ██╗██████╗
 ██╔══██╗██╔══██╗██╔═══██╗██║██╔══██╗
 ██████╔╝███████║██║   ██║██║██████╔╝
 ██╔══██╗██╔══██║██║▄▄ ██║██║██╔══██╗
 ██║  ██║██║  ██║╚██████╔╝██║██████╔╝
 ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══▀▀═╝ ╚═╝╚═════╝
 AI-Powered Network Recon & Security Analysis
 "Observe. Analyze. Reveal."
""")

    # Validate target
    if not validate_target(args.target):
        print(f"[ERROR] Invalid or potentially unsafe target: '{args.target}'")
        print("        Provide a valid IP address, hostname, or CIDR range.")
        sys.exit(1)

    # Validate custom ports
    if args.ports and not validate_ports(args.ports):
        print(f"[ERROR] Invalid port specification: '{args.ports}'")
        print("        Use format: 22,80,443 or 1-1024")
        sys.exit(1)

    # Check dependencies
    if not check_dependencies(skip_ai=args.no_ai):
        sys.exit(1)

    print(f"[*] Target        : {args.target}")
    print(f"[*] Model         : {'N/A (--no-ai)' if args.no_ai else args.model}")
    print(f"[*] Output        : {'Not saving (--no-save)' if args.no_save else args.output}")
    print()

    # Run scan
    print("[*] Starting scan...\n")
    scan_output, return_code = run_nmap(args.target, args.scan_type, args.ports)

    if return_code == -1:
        print("[ERROR] Scan timed out after 5 minutes.")
        sys.exit(1)
    elif return_code == -2:
        print("[ERROR] nmap not found. Install it first.")
        sys.exit(1)
    elif return_code == -3:
        print("[ERROR] Scan failed due to permissions.")
        sys.exit(1)
    elif not scan_output.strip():
        print("[ERROR] Nmap returned no output. Check your target and network.")
        sys.exit(1)

    print("═" * 60)
    print("NMAP OUTPUT")
    print("═" * 60)
    print(scan_output)

    analysis = {}

    if not args.no_ai:
        print("[*] Running AI analysis...\n")
        analysis = analyze_with_ai(scan_output, args.model)
        print_analysis(analysis, args.target)
    else:
        print("[*] AI analysis skipped (--no-ai)")

    if not args.no_save:
        save_results(args.target, scan_output, analysis, args.output)


if __name__ == "__main__":
    main()
