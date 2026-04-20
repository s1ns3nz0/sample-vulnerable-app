# Sample Vulnerable Payment API

**Intentionally vulnerable** FastAPI application for testing the [Compliance-Driven AI Risk Platform](https://github.com/s1ns3nz0/ai-devsecops).

> **WARNING:** This application contains intentional security vulnerabilities. Run only in isolated environments. Never deploy to production.

## Vulnerabilities

| # | Vulnerability | File | Scanner | Control ID |
|---|---|---|---|---|
| 1 | Hardcoded AWS credentials | `src/config.py` | Gitleaks | PCI-DSS-3.5.1 |
| 2 | SQL injection | `src/app.py` (export endpoint) | Semgrep | PCI-DSS-6.3.1 |
| 3 | PII logged in plaintext | `src/app.py` (payment create) | Semgrep | PCI-DSS-6.3.1 |
| 4 | Weak JWT (HS256 + hardcoded secret) | `src/app.py` (login) | Semgrep | ASVS-V3.5.1 |
| 5 | Negative payment amount accepted | `src/app.py` (payment create) | — (logic bug) | — |

## IaC Misconfigurations

| # | Issue | File | Scanner | Control ID |
|---|---|---|---|---|
| 1 | S3 bucket without encryption | `terraform/main.tf` | Checkov | PCI-DSS-3.4 |
| 2 | S3 bucket without versioning | `terraform/main.tf` | Checkov | FISC-DATA-03 |
| 3 | Overly permissive IAM policy | `terraform/main.tf` | Checkov | FISC-ACCESS-07 |
| 4 | Security group open to 0.0.0.0/0 | `terraform/main.tf` | Checkov | PCI-DSS-1.3.4 |

## Dependencies with Known CVEs

| Package | Version | CVE | Severity |
|---|---|---|---|
| cryptography | 3.4.6 | CVE-2023-49083 | High |
| requests | 2.25.0 | CVE-2023-32681 | Medium |
| pyjwt | 1.7.1 | CVE-2022-29217 | High |

## Quick Start

```bash
# Run with Docker
docker build -t sample-vulnerable-app .
docker run -p 127.0.0.1:8080:8080 --name vulnerable-app sample-vulnerable-app

# Generate attack traffic
python scripts/simulate-traffic.py

# Scan with the platform
cd ../ai-devsecops
python -m orchestrator assess ../sample-vulnerable-app --product payment-api
```

## API Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Health check |
| POST | `/api/login` | Login (returns JWT) |
| POST | `/api/payment/create` | Create payment |
| POST | `/api/payment/confirm` | Confirm payment |
| GET | `/api/export` | Export data (SQL injectable) |

## Log Format

JSON structured logs in `logs/access.jsonl`:

```json
{"timestamp": "2026-04-20T10:00:00Z", "event_type": "api_request", "method": "POST", "path": "/api/payment/create", "status": 200, "ip": "10.0.0.1"}
{"timestamp": "2026-04-20T10:00:01Z", "event_type": "login_failed", "username": "admin", "ip": "192.168.1.100", "reason": "invalid_password"}
```
