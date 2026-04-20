"""Application configuration — INTENTIONALLY VULNERABLE."""

# VULNERABILITY 1: Hardcoded AWS credentials (Gitleaks → PCI-DSS-3.5.1)
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # noqa: S105
AWS_REGION = "ap-northeast-1"

# VULNERABILITY 4 (partial): Hardcoded JWT secret
JWT_SECRET = "super-secret-key-do-not-share"  # noqa: S105
JWT_ALGORITHM = "HS256"  # Weak: should use RS256 with key pair

DATABASE_URL = "sqlite:///payments.db"
LOG_PATH = "logs/access.jsonl"
