#!/usr/bin/env python3
"""
CloudMCP Arsenal — Cloud Defense MCP Server
AI-powered defense tools that respond at machine speed.

Tools:
  defense_rate_limit    - Detect and simulate API rate limiting
  defense_anomaly       - Behavioral anomaly detection for cloud APIs
  defense_containment   - Automated containment actions
  defense_deception     - Deploy cloud honeypots/honeytokens
  defense_threat_intel  - Map findings to threat intelligence
  defense_compliance    - Check cloud config against CIS Benchmarks

Author: Ali AlEnezi (@SiteQ8) — NBK Group
"""

import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
import random

VERSION = "1.0"

def defense_rate_limit(api_endpoint, requests_per_minute):
    """Analyze API rate limiting configuration"""
    thresholds = {
        "normal_user": 60,
        "ai_agent_recon": 300,
        "ai_agent_brute": 1000,
        "ddos": 10000
    }
    classification = "normal"
    for level, threshold in thresholds.items():
        if requests_per_minute >= threshold:
            classification = level

    return {
        "endpoint": api_endpoint,
        "rpm_observed": requests_per_minute,
        "classification": classification,
        "recommendation": {
            "normal_user": "No action needed",
            "ai_agent_recon": "ALERT: AI agent reconnaissance detected. Apply progressive rate limiting.",
            "ai_agent_brute": "BLOCK: AI agent brute force. Enable CAPTCHA + exponential backoff.",
            "ddos": "EMERGENCY: DDoS-level traffic. Activate WAF rules + GeoIP blocking."
        }.get(classification, "Monitor"),
        "defense_actions": [
            f"Set rate limit to {min(requests_per_minute // 2, 100)} RPM for this endpoint",
            "Enable request fingerprinting (TLS JA3, User-Agent analysis)",
            "Deploy adaptive rate limiting (normal=60, suspicious=10, blocked=0)",
            "Log all requests for forensic analysis"
        ],
        "mitre_defense": "M1031 — Network Intrusion Prevention",
        "timestamp": datetime.now().isoformat()
    }

def defense_anomaly(events):
    """Behavioral anomaly detection for cloud API access patterns"""
    baseline = {
        "avg_requests_per_hour": 50,
        "unique_endpoints_per_session": 5,
        "avg_session_duration_minutes": 30,
        "geographic_consistency": True
    }

    anomalies = []
    risk_score = 0

    for event in events:
        if event.get("requests_per_hour", 0) > baseline["avg_requests_per_hour"] * 5:
            anomalies.append({"type": "Volume Spike", "severity": "HIGH", "detail": f"RPH {event['requests_per_hour']} vs baseline {baseline['avg_requests_per_hour']}", "indicator": "AI agent rapid enumeration"})
            risk_score += 30

        if event.get("unique_endpoints", 0) > baseline["unique_endpoints_per_session"] * 10:
            anomalies.append({"type": "Endpoint Sweep", "severity": "CRITICAL", "detail": f"Accessing {event['unique_endpoints']} unique endpoints", "indicator": "Automated API discovery"})
            risk_score += 40

        if event.get("sequential_scanning", False):
            anomalies.append({"type": "Sequential Scan", "severity": "HIGH", "detail": "Systematic enumeration pattern detected", "indicator": "Tool-driven reconnaissance"})
            risk_score += 25

        if event.get("multi_region", False):
            anomalies.append({"type": "Geographic Anomaly", "severity": "MEDIUM", "detail": "Requests from multiple regions simultaneously", "indicator": "Distributed attack or proxy chain"})
            risk_score += 15

    return {
        "anomalies": anomalies,
        "risk_score": min(risk_score, 100),
        "risk_level": "CRITICAL" if risk_score >= 70 else "HIGH" if risk_score >= 40 else "MEDIUM" if risk_score >= 20 else "LOW",
        "recommended_actions": [
            "Isolate affected service accounts" if risk_score >= 70 else "Increase monitoring",
            "Enable enhanced logging for all cloud APIs",
            "Review IAM permissions for principle of least privilege",
            "Deploy cloud honeytokens near high-value assets"
        ],
        "timestamp": datetime.now().isoformat()
    }

def defense_containment(threat_type, target_resource):
    """Automated containment playbook"""
    playbooks = {
        "exposed_bucket": {
            "actions": [
                {"step": 1, "action": "Block public access via bucket policy", "command": "aws s3api put-public-access-block --bucket {resource} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true", "auto": True},
                {"step": 2, "action": "Enable access logging", "command": "aws s3api put-bucket-logging --bucket {resource} --bucket-logging-status ...", "auto": True},
                {"step": 3, "action": "Scan for data exposure", "command": "aws macie2 create-classification-job --bucket {resource}", "auto": True},
                {"step": 4, "action": "Notify security team", "command": "aws sns publish --topic-arn arn:aws:sns:...:security-alerts", "auto": True},
                {"step": 5, "action": "Review bucket contents for sensitive data", "auto": False}
            ],
            "sla": "15 minutes"
        },
        "compromised_credentials": {
            "actions": [
                {"step": 1, "action": "Disable access key immediately", "command": "aws iam update-access-key --access-key-id {resource} --status Inactive", "auto": True},
                {"step": 2, "action": "Revoke all active sessions", "command": "aws iam put-role-policy --policy-name RevokeOlderSessions ...", "auto": True},
                {"step": 3, "action": "Analyze CloudTrail for unauthorized activity", "auto": True},
                {"step": 4, "action": "Rotate all credentials for affected account", "auto": False},
                {"step": 5, "action": "Forensic analysis of affected resources", "auto": False}
            ],
            "sla": "5 minutes"
        },
        "ssrf_metadata": {
            "actions": [
                {"step": 1, "action": "Enable IMDSv2 (require token)", "command": "aws ec2 modify-instance-metadata-options --instance-id {resource} --http-tokens required", "auto": True},
                {"step": 2, "action": "Update security group to restrict outbound", "auto": True},
                {"step": 3, "action": "Patch application SSRF vulnerability", "auto": False},
                {"step": 4, "action": "Rotate instance role credentials", "auto": True},
                {"step": 5, "action": "Review all instances for IMDSv1 usage", "auto": True}
            ],
            "sla": "10 minutes"
        }
    }

    pb = playbooks.get(threat_type, {"actions": [{"step": 1, "action": "Escalate to security team", "auto": False}], "sla": "30 minutes"})

    return {
        "threat_type": threat_type,
        "target_resource": target_resource,
        "containment_playbook": pb,
        "auto_actions": sum(1 for a in pb["actions"] if a.get("auto")),
        "manual_actions": sum(1 for a in pb["actions"] if not a.get("auto")),
        "estimated_containment_time": pb["sla"],
        "timestamp": datetime.now().isoformat()
    }

def defense_deception(cloud_provider):
    """Cloud honeypot/honeytoken deployment guide"""
    return {
        "cloud_provider": cloud_provider,
        "honeytokens": [
            {"type": "AWS Access Key", "deployment": "Place fake AWS keys in .env files, Git repos, S3", "detection": "CloudTrail alert on key usage", "mitre": "T1552 — Unsecured Credentials"},
            {"type": "Honey S3 Bucket", "deployment": "Create bucket with attractive name (backup-prod, db-dump)", "detection": "S3 access logging + CloudWatch alarm", "mitre": "T1530 — Data from Cloud Storage"},
            {"type": "Honey Database", "deployment": "Deploy decoy RDS with fake sensitive-looking data", "detection": "VPC Flow Logs + connection alerts", "mitre": "T1213 — Data from Information Repositories"},
            {"type": "Canary Tokens", "deployment": "Embed DNS/HTTP canaries in documents and configs", "detection": "Canarytokens.org callback", "mitre": "T1005 — Data from Local System"},
            {"type": "Honey Lambda", "deployment": "Create function with tempting name (process-payments)", "detection": "CloudWatch invocation alert", "mitre": "T1648 — Serverless Execution"}
        ],
        "deployment_priority": "Deploy honeytokens at every layer where an attacker would look for credentials or data",
        "timestamp": datetime.now().isoformat()
    }

def defense_cis_cloud(cloud_provider):
    """CIS Benchmark checks for cloud environments"""
    checks = {
        "AWS": [
            {"id": "CIS-1.1", "check": "Root account MFA", "status": "CHECK", "severity": "CRITICAL"},
            {"id": "CIS-1.4", "check": "No root access keys", "status": "CHECK", "severity": "CRITICAL"},
            {"id": "CIS-2.1", "check": "CloudTrail enabled all regions", "status": "CHECK", "severity": "CRITICAL"},
            {"id": "CIS-2.6", "check": "S3 bucket access logging", "status": "CHECK", "severity": "HIGH"},
            {"id": "CIS-3.1", "check": "CloudWatch log metric filters", "status": "CHECK", "severity": "MEDIUM"},
            {"id": "CIS-4.1", "check": "No unrestricted SSH (0.0.0.0/0)", "status": "CHECK", "severity": "CRITICAL"},
            {"id": "CIS-4.3", "check": "Default VPC not in use", "status": "CHECK", "severity": "HIGH"},
            {"id": "CIS-5.1", "check": "Network ACLs configured", "status": "CHECK", "severity": "MEDIUM"}
        ],
        "Azure": [
            {"id": "CIS-1.1", "check": "MFA for privileged users", "status": "CHECK", "severity": "CRITICAL"},
            {"id": "CIS-1.3", "check": "No guest users with owner role", "status": "CHECK", "severity": "HIGH"},
            {"id": "CIS-2.1", "check": "Azure Defender enabled", "status": "CHECK", "severity": "HIGH"},
            {"id": "CIS-3.1", "check": "Storage account public access disabled", "status": "CHECK", "severity": "CRITICAL"},
            {"id": "CIS-4.1", "check": "NSG flow logs enabled", "status": "CHECK", "severity": "MEDIUM"},
            {"id": "CIS-5.1", "check": "Activity log alert for policy changes", "status": "CHECK", "severity": "HIGH"}
        ],
        "GCP": [
            {"id": "CIS-1.1", "check": "Corporate login used (no Gmail)", "status": "CHECK", "severity": "HIGH"},
            {"id": "CIS-1.4", "check": "Service account keys rotated", "status": "CHECK", "severity": "HIGH"},
            {"id": "CIS-2.1", "check": "Cloud audit logging enabled", "status": "CHECK", "severity": "CRITICAL"},
            {"id": "CIS-3.1", "check": "Default network not used", "status": "CHECK", "severity": "HIGH"},
            {"id": "CIS-4.1", "check": "GCS buckets not public", "status": "CHECK", "severity": "CRITICAL"},
            {"id": "CIS-5.1", "check": "Cloud Monitoring alerts configured", "status": "CHECK", "severity": "MEDIUM"}
        ]
    }

    return {
        "cloud_provider": cloud_provider,
        "benchmark": f"CIS {cloud_provider} Foundations Benchmark",
        "checks": checks.get(cloud_provider, []),
        "total_checks": len(checks.get(cloud_provider, [])),
        "timestamp": datetime.now().isoformat()
    }

TOOLS = {
    "defense_rate_limit": {"description": "API rate limiting analysis and AI-speed attack detection", "parameters": {"api_endpoint": {"type": "string"}, "requests_per_minute": {"type": "integer"}}},
    "defense_anomaly": {"description": "Behavioral anomaly detection for cloud API access patterns", "parameters": {"events": {"type": "array"}}},
    "defense_containment": {"description": "Automated containment playbook for cloud threats", "parameters": {"threat_type": {"type": "string"}, "target_resource": {"type": "string"}}},
    "defense_deception": {"description": "Cloud honeypot and honeytoken deployment guide", "parameters": {"cloud_provider": {"type": "string"}}},
    "defense_cis_cloud": {"description": "CIS Benchmark checks for AWS/Azure/GCP", "parameters": {"cloud_provider": {"type": "string"}}}
}

class DefenseHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        try: req = json.loads(body)
        except: self.send_json({"error": "Invalid JSON"}, 400); return
        method, params = req.get("method", ""), req.get("params", {})
        if method == "tools/list":
            self.send_json({"tools": [{"name": k, **v} for k, v in TOOLS.items()]})
        elif method == "tools/call":
            name, args = params.get("name", ""), params.get("arguments", {})
            fns = {
                "defense_rate_limit": lambda: defense_rate_limit(args.get("api_endpoint",""), args.get("requests_per_minute",0)),
                "defense_anomaly": lambda: defense_anomaly(args.get("events",[])),
                "defense_containment": lambda: defense_containment(args.get("threat_type",""), args.get("target_resource","")),
                "defense_deception": lambda: defense_deception(args.get("cloud_provider","AWS")),
                "defense_cis_cloud": lambda: defense_cis_cloud(args.get("cloud_provider","AWS"))
            }
            self.send_json({"result": fns.get(name, lambda: {"error": f"Unknown: {name}"})()})
        else:
            self.send_json({"error": f"Unknown: {method}"}, 404)

    def send_json(self, data, code=200):
        self.send_response(code)
        self.send_header("Content-Type","application/json")
        self.send_header("Access-Control-Allow-Origin","*")
        self.end_headers()
        self.wfile.write(json.dumps(data,indent=2,default=str).encode())

    def do_OPTIONS(self):
        self.send_response(200)
        for h in ["Access-Control-Allow-Origin","Access-Control-Allow-Methods","Access-Control-Allow-Headers"]:
            self.send_header(h, "*" if "Origin" in h else "POST, OPTIONS" if "Methods" in h else "Content-Type")
        self.end_headers()

    def log_message(self, f, *a): print(f"[Defense] {datetime.now().strftime('%H:%M:%S')} — {f%a}")

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=9091)
    a = p.parse_args()
    print(f"\n╔═══════════════════════════════════════════════════╗\n║  CloudMCP Arsenal — Defense Server v{VERSION}            ║\n║  5 cloud defense tools via MCP                    ║\n║  Ali AlEnezi (@SiteQ8) — NBK Group                ║\n║  Port: {a.port}                                        ║\n╚═══════════════════════════════════════════════════╝\n")
    HTTPServer(("0.0.0.0", a.port), DefenseHandler).serve_forever()
