#!/usr/bin/env python3
"""
CloudMCP Arsenal: Cloud Reconnaissance MCP Server
Exposes cloud-specific security tools for AI agent consumption.

Tools:
  cloud_s3_enum     - S3 bucket enumeration & permission check
  cloud_azure_enum  - Azure blob storage enumeration
  cloud_metadata    - Cloud metadata service probe (SSRF vector)
  cloud_iam_audit   - IAM policy analysis (AWS)
  cloud_dns_zone    - DNS zone transfer & cloud provider detection
  cloud_cert_trans  - Certificate Transparency log search
  cloud_subdomain   - Cloud-aware subdomain enumeration
  cloud_waf_detect  - WAF/CDN detection & fingerprinting

Author: Ali AlEnezi (@SiteQ8)
"""

import json, socket, ssl, subprocess, urllib.request, urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
import re, sys

VERSION = "1.0"

# ═══ CLOUD TOOLS ═══

def cloud_s3_enum(bucket_name):
    """Enumerate S3 bucket: check existence, permissions, listing"""
    results = {"bucket": bucket_name, "findings": [], "risk": "UNKNOWN"}
    urls = [
        f"https://{bucket_name}.s3.amazonaws.com",
        f"https://s3.amazonaws.com/{bucket_name}",
    ]
    for url in urls:
        try:
            req = urllib.request.Request(url, method="GET")
            req.add_header("User-Agent", "CloudMCP-Arsenal/1.0")
            resp = urllib.request.urlopen(req, timeout=8)
            body = resp.read(2048).decode(errors="ignore")
            if "<ListBucketResult" in body:
                results["findings"].append({"severity": "CRITICAL", "finding": f"Bucket {bucket_name} allows public LIST", "evidence": body[:200]})
                results["risk"] = "CRITICAL"
            elif resp.status == 200:
                results["findings"].append({"severity": "HIGH", "finding": f"Bucket {bucket_name} is publicly accessible"})
                results["risk"] = "HIGH"
            break
        except urllib.error.HTTPError as e:
            if e.code == 403:
                results["findings"].append({"severity": "INFO", "finding": f"Bucket exists but access denied (403)"})
                results["risk"] = "LOW"
            elif e.code == 404:
                results["findings"].append({"severity": "INFO", "finding": "Bucket does not exist"})
        except Exception as e:
            results["findings"].append({"severity": "INFO", "finding": str(e)})

    # Check common sensitive paths
    for path in [".env", "config.json", "credentials", "backup.sql", "database.sql", ".git/HEAD"]:
        try:
            url = f"https://{bucket_name}.s3.amazonaws.com/{path}"
            req = urllib.request.Request(url, method="HEAD")
            resp = urllib.request.urlopen(req, timeout=5)
            if resp.status == 200:
                results["findings"].append({"severity": "CRITICAL", "finding": f"Sensitive file exposed: {path}", "url": url})
                results["risk"] = "CRITICAL"
        except Exception:
            pass

    results["timestamp"] = datetime.now().isoformat()
    return results

def cloud_metadata(target_url):
    """Probe cloud metadata service: SSRF attack vector"""
    results = {"target": target_url, "findings": [], "cloud_provider": "unknown"}

    metadata_endpoints = {
        "AWS": ["http://169.254.169.254/latest/meta-data/", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"],
        "GCP": ["http://metadata.google.internal/computeMetadata/v1/"],
        "Azure": ["http://169.254.169.254/metadata/instance?api-version=2021-02-01"],
        "DigitalOcean": ["http://169.254.169.254/metadata/v1/"]
    }

    for provider, endpoints in metadata_endpoints.items():
        for ep in endpoints:
            try:
                req = urllib.request.Request(ep, method="GET")
                if provider == "GCP":
                    req.add_header("Metadata-Flavor", "Google")
                if provider == "Azure":
                    req.add_header("Metadata", "true")
                resp = urllib.request.urlopen(req, timeout=3)
                body = resp.read(1024).decode(errors="ignore")
                results["cloud_provider"] = provider
                results["findings"].append({
                    "severity": "CRITICAL",
                    "finding": f"Metadata service accessible — {provider}",
                    "endpoint": ep,
                    "data_sample": body[:200]
                })
            except Exception:
                pass

    if not results["findings"]:
        results["findings"].append({"severity": "INFO", "finding": "No metadata service detected (not running in cloud or properly restricted)"})

    results["mitre"] = "T1552.005 — Cloud Instance Metadata API"
    results["timestamp"] = datetime.now().isoformat()
    return results

def cloud_cert_transparency(domain):
    """Search Certificate Transparency logs for subdomains"""
    results = {"domain": domain, "certificates": [], "subdomains": set()}

    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "CloudMCP-Arsenal/1.0")
        resp = urllib.request.urlopen(req, timeout=15)
        data = json.loads(resp.read().decode())

        seen = set()
        for cert in data[:100]:
            name = cert.get("name_value", "")
            for n in name.split("\n"):
                n = n.strip().lower()
                if n and n not in seen and domain in n:
                    seen.add(n)
                    results["subdomains"].add(n)

        results["subdomains"] = sorted(results["subdomains"])
        results["total_certs"] = len(data)
        results["unique_subdomains"] = len(results["subdomains"])

        # Identify cloud services
        cloud_indicators = {
            "s3": "AWS S3", "cloudfront": "AWS CloudFront", "elasticbeanstalk": "AWS EB",
            "azurewebsites": "Azure", "blob.core": "Azure Blob", "cloudapp": "Azure VM",
            "googleapis": "GCP", "appspot": "GCP App Engine", "firebaseapp": "Firebase",
            "herokuapp": "Heroku", "netlify": "Netlify", "vercel": "Vercel"
        }
        results["cloud_services"] = []
        for sub in results["subdomains"]:
            for indicator, service in cloud_indicators.items():
                if indicator in sub:
                    results["cloud_services"].append({"subdomain": sub, "service": service})

    except Exception as e:
        results["error"] = str(e)

    results["timestamp"] = datetime.now().isoformat()
    return results

def cloud_waf_detect(url):
    """Detect WAF/CDN protecting target"""
    results = {"url": url, "waf_detected": False, "findings": []}

    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "CloudMCP-Arsenal/1.0")
        resp = urllib.request.urlopen(req, timeout=10)
        headers = dict(resp.headers)

        waf_signatures = {
            "cloudflare": {"headers": ["cf-ray", "cf-cache-status"], "name": "Cloudflare"},
            "aws_waf": {"headers": ["x-amzn-requestid", "x-amz-cf-id"], "name": "AWS WAF/CloudFront"},
            "akamai": {"headers": ["x-akamai-transformed"], "name": "Akamai"},
            "azure_fd": {"headers": ["x-azure-ref", "x-fd-healthprobe"], "name": "Azure Front Door"},
            "fastly": {"headers": ["x-served-by", "x-cache", "x-fastly-request-id"], "name": "Fastly"},
            "imperva": {"headers": ["x-iinfo"], "name": "Imperva/Incapsula"},
            "sucuri": {"headers": ["x-sucuri-id"], "name": "Sucuri WAF"}
        }

        for waf_id, sig in waf_signatures.items():
            for h in sig["headers"]:
                if h.lower() in [k.lower() for k in headers]:
                    results["waf_detected"] = True
                    results["findings"].append({
                        "waf": sig["name"],
                        "evidence": f"Header {h} present",
                        "value": headers.get(h, headers.get(h.title(), ""))
                    })

        # Check server header
        server = headers.get("Server", headers.get("server", ""))
        if server:
            results["server"] = server
            if "cloudflare" in server.lower():
                results["waf_detected"] = True
            elif "AkamaiGHost" in server:
                results["waf_detected"] = True

    except urllib.error.HTTPError as e:
        results["http_error"] = e.code
        if e.code == 403:
            results["findings"].append({"waf": "Unknown", "evidence": "403 Forbidden — likely WAF blocking"})
            results["waf_detected"] = True
    except Exception as e:
        results["error"] = str(e)

    results["timestamp"] = datetime.now().isoformat()
    return results

def cloud_dns_provider(domain):
    """Detect cloud provider from DNS records"""
    results = {"domain": domain, "providers": [], "records": {}}

    cloud_patterns = {
        "amazonaws.com": "AWS", "awsdns": "AWS Route53",
        "azure": "Microsoft Azure", "microsoft.com": "Microsoft",
        "googledomains": "Google", "google.com": "GCP",
        "cloudflare": "Cloudflare", "ns.cloudflare": "Cloudflare DNS",
        "digitalocean": "DigitalOcean",
        "linode": "Linode/Akamai"
    }

    for rtype in ["A", "NS", "CNAME", "MX"]:
        try:
            out = subprocess.check_output(["dig", "+short", rtype, domain], timeout=8, stderr=subprocess.DEVNULL).decode().strip()
            if out:
                results["records"][rtype] = out.split("\n")
                for line in out.split("\n"):
                    for pattern, provider in cloud_patterns.items():
                        if pattern in line.lower():
                            if provider not in results["providers"]:
                                results["providers"].append(provider)
        except Exception:
            pass

    results["timestamp"] = datetime.now().isoformat()
    return results

def cloud_iam_misconfig():
    """Check common IAM misconfigurations (educational/checklist)"""
    return {
        "title": "Cloud IAM Misconfiguration Checklist",
        "checks": [
            {"id": "IAM-001", "check": "Root account MFA enabled", "severity": "CRITICAL", "cloud": "AWS"},
            {"id": "IAM-002", "check": "No access keys for root account", "severity": "CRITICAL", "cloud": "AWS"},
            {"id": "IAM-003", "check": "Unused credentials disabled (90 days)", "severity": "HIGH", "cloud": "ALL"},
            {"id": "IAM-004", "check": "Password policy enforces complexity", "severity": "MEDIUM", "cloud": "ALL"},
            {"id": "IAM-005", "check": "No wildcard (*) in IAM policies", "severity": "CRITICAL", "cloud": "AWS"},
            {"id": "IAM-006", "check": "Service accounts use least privilege", "severity": "HIGH", "cloud": "ALL"},
            {"id": "IAM-007", "check": "Cross-account access reviewed", "severity": "HIGH", "cloud": "AWS/GCP"},
            {"id": "IAM-008", "check": "Conditional access policies enabled", "severity": "HIGH", "cloud": "Azure"},
            {"id": "IAM-009", "check": "API keys rotated regularly", "severity": "MEDIUM", "cloud": "ALL"},
            {"id": "IAM-010", "check": "CloudTrail/Activity Log enabled", "severity": "CRITICAL", "cloud": "ALL"},
            {"id": "IAM-011", "check": "No public S3/Blob/GCS buckets", "severity": "CRITICAL", "cloud": "ALL"},
            {"id": "IAM-012", "check": "MFA for privileged operations", "severity": "HIGH", "cloud": "ALL"}
        ],
        "mitre_techniques": ["T1078 — Valid Accounts", "T1098 — Account Manipulation", "T1552 — Unsecured Credentials"],
        "timestamp": datetime.now().isoformat()
    }

def cloud_attack_playbook(target, findings):
    """Generate cloud-specific attack playbook from findings"""
    playbook = {"target": target, "phases": [], "risk": "UNKNOWN"}

    playbook["phases"] = [
        {
            "phase": "1. Cloud Provider Identification",
            "objective": "Determine cloud infrastructure",
            "tools": ["cloud_dns_provider", "cloud_waf_detect", "cloud_cert_transparency"],
            "mitre": "T1590 — Gather Victim Network Information"
        },
        {
            "phase": "2. Attack Surface Mapping",
            "objective": "Enumerate cloud resources (buckets, functions, APIs)",
            "tools": ["cloud_s3_enum", "cloud_cert_transparency", "recon_ports"],
            "mitre": "T1595 — Active Scanning"
        },
        {
            "phase": "3. Credential Harvesting",
            "objective": "Find exposed credentials, metadata, keys",
            "tools": ["cloud_metadata", "cloud_s3_enum (sensitive files)"],
            "mitre": "T1552.005 — Cloud Instance Metadata API"
        },
        {
            "phase": "4. Initial Access",
            "objective": "Exploit misconfigured services or stolen credentials",
            "tools": ["Exposed APIs", "Default credentials", "SSRF to metadata"],
            "mitre": "T1190 — Exploit Public-Facing Application"
        },
        {
            "phase": "5. Lateral Movement & Privilege Escalation",
            "objective": "Move across cloud accounts and escalate",
            "tools": ["IAM policy abuse", "Cross-account roles", "Service account impersonation"],
            "mitre": "T1078.004 — Cloud Accounts"
        },
        {
            "phase": "6. Data Exfiltration",
            "objective": "Extract sensitive data from cloud storage",
            "tools": ["S3 sync", "Database snapshots", "Log downloads"],
            "mitre": "T1537 — Transfer Data to Cloud Account"
        }
    ]

    critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    if critical_count > 0:
        playbook["risk"] = "CRITICAL"
    elif any(f.get("severity") == "HIGH" for f in findings):
        playbook["risk"] = "HIGH"
    else:
        playbook["risk"] = "MEDIUM"

    playbook["timestamp"] = datetime.now().isoformat()
    return playbook


# ═══ MCP SERVER ═══

TOOLS = {
    "cloud_s3_enum": {"description": "S3 bucket enumeration — check existence, public access, sensitive files", "parameters": {"bucket_name": {"type": "string"}}},
    "cloud_metadata": {"description": "Cloud metadata service probe — SSRF attack vector (AWS/GCP/Azure)", "parameters": {"target_url": {"type": "string"}}},
    "cloud_cert_transparency": {"description": "Certificate Transparency log search — discover subdomains and cloud services", "parameters": {"domain": {"type": "string"}}},
    "cloud_waf_detect": {"description": "WAF/CDN detection and fingerprinting (Cloudflare, AWS WAF, Akamai, Azure FD)", "parameters": {"url": {"type": "string"}}},
    "cloud_dns_provider": {"description": "Cloud provider detection from DNS records", "parameters": {"domain": {"type": "string"}}},
    "cloud_iam_misconfig": {"description": "IAM misconfiguration checklist — 12 critical checks for AWS/Azure/GCP", "parameters": {}},
    "cloud_attack_playbook": {"description": "Generate cloud attack playbook with MITRE mapping from findings", "parameters": {"target": {"type": "string"}, "findings": {"type": "array"}}},
}

class MCPHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        try:
            req = json.loads(body)
        except:
            self.send_json({"error": "Invalid JSON"}, 400); return

        method = req.get("method", "")
        params = req.get("params", {})

        if method == "tools/list":
            self.send_json({"tools": [{"name": k, **v} for k, v in TOOLS.items()]})
        elif method == "tools/call":
            name = params.get("name", "")
            args = params.get("arguments", {})
            result = self.call_tool(name, args)
            self.send_json({"result": result})
        else:
            self.send_json({"error": f"Unknown: {method}"}, 404)

    def call_tool(self, name, args):
        try:
            fns = {
                "cloud_s3_enum": lambda: cloud_s3_enum(args.get("bucket_name", "")),
                "cloud_metadata": lambda: cloud_metadata(args.get("target_url", "")),
                "cloud_cert_transparency": lambda: cloud_cert_transparency(args.get("domain", "")),
                "cloud_waf_detect": lambda: cloud_waf_detect(args.get("url", "")),
                "cloud_dns_provider": lambda: cloud_dns_provider(args.get("domain", "")),
                "cloud_iam_misconfig": lambda: cloud_iam_misconfig(),
                "cloud_attack_playbook": lambda: cloud_attack_playbook(args.get("target", ""), args.get("findings", []))
            }
            return fns.get(name, lambda: {"error": f"Unknown tool: {name}"})()
        except Exception as e:
            return {"error": str(e)}

    def send_json(self, data, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2, default=str).encode())

    def do_OPTIONS(self):
        self.send_response(200)
        for h in ["Access-Control-Allow-Origin","Access-Control-Allow-Methods","Access-Control-Allow-Headers"]:
            self.send_header(h, "*" if "Origin" in h else "POST, OPTIONS" if "Methods" in h else "Content-Type")
        self.end_headers()

    def log_message(self, f, *a): print(f"[CloudMCP] {datetime.now().strftime('%H:%M:%S')} — {f%a}")

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=9090)
    a = p.parse_args()
    print(f"\n╔═══════════════════════════════════════════════════╗\n║  CloudMCP Arsenal — Cloud Recon Server v{VERSION}        ║\n║  7 cloud security tools via MCP                   ║\n║  Ali AlEnezi (@SiteQ8) — NBK Group                ║\n║  Port: {a.port}                                        ║\n╚═══════════════════════════════════════════════════╝\n")
    HTTPServer(("0.0.0.0", a.port), MCPHandler).serve_forever()
