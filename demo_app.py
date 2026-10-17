"""Demo mode: same dashboard, sample data, no Prowler and no AWS needed.

Run:    uvicorn demo_app:app --host 127.0.0.1 --port 9000
Remove: delete this file. The real backend (app.py) is untouched.
"""
import os
import random

from fastapi import FastAPI
from fastapi.responses import FileResponse

from app import summarize

app = FastAPI(title="CSPM Dashboard (sample data)")

REGIONS = ["ap-south-1", "us-east-1", "eu-west-1", "us-west-2"]
DOCS = "https://docs.aws.amazon.com/"
CHECKS = [  # check_id, title, service, severity, risk, fix
    ("iam_root_mfa_enabled", "MFA is enabled for the root account", "iam", "critical",
     "Without MFA, a stolen root password gives full control of the account.", "Enable a hardware or virtual MFA device on the root user."),
    ("iam_user_mfa_enabled_console_access", "Console users have MFA enabled", "iam", "high",
     "Password-only logins are easy to phish.", "Require MFA for every IAM user with console access."),
    ("iam_password_policy_minimum_length_14", "Password policy requires at least 14 characters", "iam", "medium",
     "Short passwords are easier to guess.", "Raise the minimum password length to 14 or more."),
    ("s3_bucket_public_access", "S3 bucket blocks public access", "s3", "critical",
     "Public buckets can leak data to anyone on the internet.", "Turn on Block Public Access for the bucket and the account."),
    ("s3_bucket_versioning_enabled", "S3 bucket has versioning enabled", "s3", "medium",
     "Deleted or overwritten objects cannot be recovered.", "Enable versioning on the bucket."),
    ("s3_bucket_secure_transport_policy", "S3 bucket denies non-TLS requests", "s3", "medium",
     "Data can be read over unencrypted connections.", "Add a bucket policy that denies aws:SecureTransport=false."),
    ("ec2_securitygroup_allow_ingress_from_internet_to_port_22", "Security groups do not allow SSH from anywhere", "ec2", "high",
     "Open SSH is scanned and brute-forced within minutes.", "Restrict port 22 to known IP ranges or use Session Manager."),
    ("ec2_ebs_default_encryption", "EBS encryption by default is enabled", "ec2", "medium",
     "New volumes and snapshots may be stored unencrypted.", "Enable EBS encryption by default in each region."),
    ("ec2_instance_imdsv2_enabled", "EC2 instances require IMDSv2", "ec2", "high",
     "IMDSv1 can be abused through SSRF to steal instance credentials.", "Set HttpTokens to required on each instance."),
    ("cloudtrail_multi_region_enabled", "CloudTrail is enabled in all regions", "cloudtrail", "high",
     "Activity in unmonitored regions leaves no audit trail.", "Create a multi-region trail."),
    ("cloudtrail_log_file_validation_enabled", "CloudTrail log file validation is on", "cloudtrail", "medium",
     "Tampered logs would go unnoticed.", "Enable log file validation on the trail."),
    ("vpc_flow_logs_enabled", "VPC flow logs are enabled", "vpc", "medium",
     "Network traffic cannot be investigated after an incident.", "Enable flow logs for each VPC."),
    ("rds_instance_storage_encrypted", "RDS storage is encrypted", "rds", "high",
     "Database data at rest is readable if storage is exposed.", "Create an encrypted copy of the instance and switch over."),
    ("awslambda_function_no_secrets_in_variables", "Lambda variables contain no secrets", "awslambda", "critical",
     "Secrets in environment variables leak through logs and console access.", "Move secrets to Secrets Manager or Parameter Store."),
    ("sns_topics_not_publicly_accessible", "SNS topics are not public", "sns", "high",
     "Anyone could publish to or subscribe to the topic.", "Remove the wildcard principal from the topic policy."),
    ("cloudwatch_log_group_retention_policy_specific_days_enabled", "Log groups have a retention period", "cloudwatch", "low",
     "Logs are kept forever, which raises cost and risk.", "Set a retention period such as 365 days."),
    ("guardduty_is_enabled", "GuardDuty is enabled", "guardduty", "medium",
     "Threats such as credential misuse go undetected.", "Enable GuardDuty in each region."),
]


def build(seed, regions, acct):
    rnd, out = random.Random(seed), []
    for cid, title, svc, sev, risk, fix in CHECKS:
        for region in REGIONS[:regions]:
            for k in range(rnd.randint(1, 4)):
                fail = rnd.random() < 0.55
                out.append({"id": f"{acct}-{cid}-{region}-{k}", "status": "FAIL" if fail else "PASS",
                            "severity": sev, "muted": False, "check_id": cid, "title": title,
                            "service": svc, "region": region,
                            "resource": f"arn:aws:{svc}:{region}:{acct}:demo-resource-{k}",
                            "message": f"{title}: {'not met' if fail else 'met'} for demo-resource-{k} in {region}.",
                            "risk": risk, "fix": fix, "fix_url": DOCS})
    return out


ACCOUNTS = {
    "demo-1": {"id": "demo-1", "account_id": "111122223333", "alias": "Production (sample)", "connected": True, "scan_state": "completed"},
    "demo-2": {"id": "demo-2", "account_id": "444455556666", "alias": "Staging (sample)", "connected": True, "scan_state": "completed"},
}
FINDINGS = {"demo-1": build(1, 4, "111122223333"), "demo-2": build(2, 2, "444455556666")}


@app.get("/api/accounts")
def accounts():
    return list(ACCOUNTS.values())


@app.post("/api/accounts")
def add_account(_: dict):
    return {"provider_id": "demo-1", "account_id": "111122223333", "scan_id": "demo-scan"}


@app.delete("/api/accounts/{pid}")
def remove_account(pid: str):
    return {"deleted": pid}


@app.post("/api/scan/{pid}")
def rescan(pid: str):
    return {"scan_id": "demo-scan"}


@app.get("/api/data/{pid}")
def data(pid: str, refresh: bool = False):
    f = FINDINGS.get(pid, [])
    return {"latest_state": "completed", "summary": summarize(f), "findings": f,
            "completed_at": "2026-10-11T08:00:00Z"}


@app.get("/")
def index():
    return FileResponse(os.path.join(os.path.dirname(__file__), "index.html"))
