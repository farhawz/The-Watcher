import subprocess
import requests

TARGET = input("Enter target IP or hostname: ").strip()

def run_nmap(target):
    cmd = [
        "nmap",
        "-sV",
        "-T4",
        target
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True
    )

    return result.stdout

def analyze_scan(nmap_output):
    prompt = f"""
You are a security analyst.

Analyze this Nmap output and provide:
1. Open services detected
2. Security observations
3. Common hardening recommendations
4. Risk level

Nmap Output:
{nmap_output}
"""

    response = requests.post(
        "http://localhost:11434/api/generate",
        json={
            "model": "qwen2.5-coder:7b",
            "prompt": prompt,
            "stream": False
        }
    )

    return response.json()["response"]

print(f"\n[+] Scanning {TARGET}...\n")

scan_results = run_nmap(TARGET)

print("=== NMAP RESULTS ===")
print(scan_results)

print("\n=== AI ANALYSIS ===")
print(analyze_scan(scan_results))
