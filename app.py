from flask import Flask, render_template, request
import whois
import socket
import requests
from urllib.parse import urlparse
from scanner.port_scan import scan_ports
from scanner.subdomain_finder import find_subdomains
from scanner.http_headers import check_http_headers
from scanner.vuln_scan import check_vulnerable_paths
from scanner.fingerprint import fingerprint

app = Flask(__name__)

# 🔹 Function to generate a human-readable summary
def generate_user_friendly_summary(domain, results):
    issues = []
    warnings = []
    positives = []

    # Port scanning / HTTPS check
    open_ports = [p['port'] for p in results.get('ports', []) if p.get('status', '').lower() == 'open']
    if 443 in open_ports:
        positives.append("Website uses HTTPS, which means the connection is encrypted.")
    else:
        issues.append("Website does not support HTTPS. Your connection may not be secure.")

    # Security headers
    headers = results.get('headers', {})
    if headers.get("Content-Security-Policy", "") == "Missing":
        warnings.append("Missing protection against malicious scripts (Content-Security-Policy is absent).")
    else:
        positives.append("Content-Security-Policy is set, which helps protect against attacks.")

    if "Strict-Transport-Security" in headers:
        positives.append("Strict Transport Security is enabled.")
    else:
        warnings.append("HTTPS is not enforced strictly (Strict-Transport-Security missing).")

    # Dangerous ports
    risky_ports = [21, 22, 23, 3306]
    if any(port in open_ports for port in risky_ports):
        issues.append("Risky ports are open (e.g., FTP, SSH, MySQL). This might be dangerous.")

    # Vulnerabilities
    vulns = results.get('vulnerabilities', [])
    found = [v for v in vulns if v.get('found')]
    if found:
        warnings.append(f"{len(found)} sensitive paths found. Admin or config panels may be exposed.")

    # Score-based message
    score = len(issues) * 2 + len(warnings)
    if score <= 2:
        risk = "✅ Safe"
        message = "This website appears secure and well-configured."
    elif score <= 5:
        risk = "⚠️ Moderate Risk"
        message = "Some protections are missing. It's usable, but with caution."
    else:
        risk = "❌ High Risk"
        message = "Website may be unsafe. Avoid entering personal or financial information."

    summary = f"<h5>{risk}</h5><p>{message}</p>"
    for p in positives:
        summary += f"<p>✅ {p}</p>"
    for w in warnings:
        summary += f"<p>⚠️ {w}</p>"
    for i in issues:
        summary += f"<p>❌ {i}</p>"
    return summary

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    domain = request.form['domain'].strip()
    scan_types = request.form.getlist('scan_options')

    results = {}

    # WHOIS Lookup
    if 'whois' in scan_types:
        try:
            w = whois.whois(domain)
            results['whois'] = w
        except Exception as e:
            results['whois'] = f"WHOIS Error: {str(e)}"

    # Port Scanning
    if 'port' in scan_types:
        try:
            ip = socket.gethostbyname(domain)
            port_results = scan_ports(ip)
            results['ports'] = port_results
        except Exception as e:
            results['ports'] = [{"error": str(e)}]

    # Subdomain Finding
    if 'subdomain' in scan_types:
        try:
            subdomains = find_subdomains(domain)
            results['subdomains'] = subdomains
        except Exception as e:
            results['subdomains'] = [f"Error: {str(e)}"]

    # HTTP Headers Check
    if 'headers' in scan_types:
        try:
            headers = check_http_headers(domain)
            results['headers'] = headers
        except Exception as e:
            results['headers'] = {"error": str(e)}

    # Basic Vulnerability Check
    if 'vuln' in scan_types:
        try:
            vulns = check_vulnerable_paths(domain)
            results['vulnerabilities'] = vulns
        except Exception as e:
            results['vulnerabilities'] = [{"error": str(e)}]

    # Tech Stack Fingerprinting
    if 'fingerprint' in scan_types:
        try:
            tech = fingerprint(domain)
            results['fingerprint'] = tech
        except Exception as e:
            results['fingerprint'] = {"error": str(e)}

    # 🔹 Generate readable summary
    summary = generate_user_friendly_summary(domain, results)

    return render_template('result.html', domain=domain, results=results, summary=summary)

if __name__ == '__main__':
    app.run(debug=True)
