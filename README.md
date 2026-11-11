<div align="center">

# CloudMCP Arsenal

### MCP Servers, AI Agent Attacks & Defenses for Cloud Security

[![SANS](https://img.shields.io/badge/SANS-Cloud_Exchange_2026-dc2626?style=flat-square)]()
[![Tools](https://img.shields.io/badge/12-MCP_Tools-00ff88?style=flat-square)]()
[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=flat-square)]()
[![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK_Cloud-ff3366?style=flat-square)]()

**Live Demo:** [siteq8.github.io/CloudMCP-Arsenal](https://siteq8.github.io/CloudMCP-Arsenal)

</div>

---

## Architecture

Two MCP servers, one for offense, one for defense:

```
┌─────────────────────────────────────────────────────┐
│  AI AGENT (Claude / GPT / Local LLM)                │
│  "Assess cloud security of target.com"              │
│                                                     │
│  ┌─────────────────┐   ┌─────────────────────┐      │
│  │ 🗡️ ATTACK SERVER │   │ 🛡️ DEFENSE SERVER    │      │
│  │ Port 9090        │   │ Port 9091             │      │
│  ├─────────────────┤   ├─────────────────────┤      │
│  │ cloud_s3_enum    │   │ defense_rate_limit   │      │
│  │ cloud_metadata   │   │ defense_anomaly      │      │
│  │ cloud_cert_trans │   │ defense_containment  │      │
│  │ cloud_waf_detect │   │ defense_deception    │      │
│  │ cloud_dns_prov   │   │ defense_cis_cloud    │      │
│  │ cloud_iam_miscon │   └─────────────────────┘      │
│  │ cloud_playbook   │                                │
│  └─────────────────┘                                │
└─────────────────────────────────────────────────────┘
```

---

## Quick Start

```bash
git clone https://github.com/SiteQ8/CloudMCP-Arsenal.git
cd CloudMCP-Arsenal

# Attack Server
python3 scripts/mcp-servers/cloud_recon_server.py --port 9090

# Defense Server (in another terminal)
python3 scripts/defenses/cloud_defense_server.py --port 9091
```

### Call Tools

```bash
# S3 Bucket Enumeration
curl -X POST http://localhost:9090 \
  -d '{"method":"tools/call","params":{"name":"cloud_s3_enum","arguments":{"bucket_name":"company-backup"}}}'

# Certificate Transparency Search
curl -X POST http://localhost:9090 \
  -d '{"method":"tools/call","params":{"name":"cloud_cert_transparency","arguments":{"domain":"target.com"}}}'

# Containment Playbook
curl -X POST http://localhost:9091 \
  -d '{"method":"tools/call","params":{"name":"defense_containment","arguments":{"threat_type":"exposed_bucket","target_resource":"company-backup"}}}'
```

---

## Attack Tools (7)

| Tool | Description | MITRE |
|------|-------------|-------|
| `cloud_s3_enum` | S3 bucket enumeration, public listing, sensitive file scan | T1530 |
| `cloud_metadata` | Cloud metadata SSRF probe (AWS/GCP/Azure/DO) | T1552.005 |
| `cloud_cert_transparency` | CT log search for subdomains + cloud service detection | T1596.004 |
| `cloud_waf_detect` | WAF/CDN fingerprinting (7 vendors) | T1595.002 |
| `cloud_dns_provider` | Cloud provider detection from DNS | T1590.002 |
| `cloud_iam_misconfig` | IAM misconfiguration checklist (12 checks) | T1078 |
| `cloud_attack_playbook` | 6-phase cloud attack playbook generator | T1190 |

## Defense Tools (5)

| Tool | Description | Framework |
|------|-------------|-----------|
| `defense_rate_limit` | AI-speed attack detection + adaptive throttling | NIST M1031 |
| `defense_anomaly` | Behavioral anomaly detection (risk scoring 0-100) | NIST DS0029 |
| `defense_containment` | Auto-containment: exposed bucket, cred theft, SSRF | NIST M1030 |
| `defense_deception` | Cloud honeytokens: fake keys, honey buckets, canaries | MITRE M1056 |
| `defense_cis_cloud` | CIS Benchmarks for AWS (8), Azure (6), GCP (6) | CIS |

---

## 6-Point Cloud Defense Playbook

1. **Deploy AI Red Team Agents**: Run CloudMCP monthly against all accounts
2. **Automated Containment < 5 min**: Playbooks for top 3 threat scenarios
3. **Rate Limit All Cloud APIs**: Adaptive: 60→10→0 RPM
4. **Deploy Cloud Honeytokens**: 5 per cloud account
5. **Enforce IMDSv2 Everywhere**: Block SSRF credential theft
6. **CIS Benchmarks Continuous**: Alert on drift, not annual check

---

## Author

**Ali AlEnezi** · [@SiteQ8](https://github.com/SiteQ8) · [3li.info](https://3li.info)

Security Architecture Principal · National Bank of Kuwait (NBK Group) 🇰🇼
