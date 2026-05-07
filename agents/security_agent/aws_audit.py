"""
AWS Resource Security Scanner — structured boto3 API response analysis.
Same Finding contract as gcp_audit.py — results are provider-agnostic.
"""

from gcp_audit import Finding  # reuse the same dataclass


# ── S3 Checks ─────────────────────────────────────────

def check_s3_public_acl(bucket_name: str, acl: dict) -> Finding | None:
    """
    Detect S3 buckets with public ACL grants (AllUsers or AuthenticatedUsers).
    `acl` is the response from s3.get_bucket_acl.
    """
    public_groups = {
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    }
    for grant in acl.get("Grants", []):
        grantee = grant.get("Grantee", {})
        if grantee.get("URI") in public_groups:
            permission = grant.get("Permission", "UNKNOWN")
            severity = "CRITICAL" if permission in ("FULL_CONTROL", "WRITE") else "HIGH"
            return Finding(
                resource_id=bucket_name,
                resource_type="s3.bucket",
                severity=severity,
                title=f"S3 bucket has public ACL ({permission})",
                description=(
                    f"Bucket '{bucket_name}' grants {permission} to {grantee.get('URI', 'public')}."
                ),
                recommendation=(
                    "Remove public ACL grants. Enable S3 Block Public Access at account level: "
                    "aws s3api put-public-access-block --bucket BUCKET "
                    "--public-access-block-configuration BlockPublicAcls=true,BlockPublicPolicy=true,"
                    "IgnorePublicAcls=true,RestrictPublicBuckets=true"
                ),
                raw=acl,
            )
    return None


def check_s3_block_public_access(bucket_name: str, block_config: dict) -> Finding | None:
    """
    Detect S3 buckets where Block Public Access is not fully enforced.
    `block_config` is the response from s3.get_public_access_block (or {} if not set).
    """
    config = block_config.get("PublicAccessBlockConfiguration", {})
    required = ["BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets"]
    missing = [k for k in required if not config.get(k, False)]

    if not missing:
        return None

    return Finding(
        resource_id=bucket_name,
        resource_type="s3.bucket",
        severity="MEDIUM",
        title="S3 Block Public Access not fully enforced",
        description=(
            f"Bucket '{bucket_name}' is missing Block Public Access settings: {', '.join(missing)}."
        ),
        recommendation=(
            "Enable all 4 Block Public Access settings for this bucket and at the account level."
        ),
        raw=block_config,
    )


def check_s3_encryption(bucket_name: str, encryption: dict) -> Finding | None:
    """
    Detect S3 buckets without server-side encryption configured.
    `encryption` is the response from s3.get_bucket_encryption (or {} if NoSuchConfiguration).
    """
    rules = encryption.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
    if rules:
        return None

    return Finding(
        resource_id=bucket_name,
        resource_type="s3.bucket",
        severity="MEDIUM",
        title="S3 bucket has no default encryption",
        description=f"Bucket '{bucket_name}' does not enforce server-side encryption on new objects.",
        recommendation=(
            "Enable default encryption: "
            "aws s3api put-bucket-encryption --bucket BUCKET "
            "--server-side-encryption-configuration "
            "'{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"aws:kms\"}}]}'"
        ),
        raw=encryption,
    )


def scan_s3_bucket(bucket_name: str, acl: dict, block_config: dict, encryption: dict) -> list[Finding]:
    findings = []
    for checker, args in [
        (check_s3_public_acl, (bucket_name, acl)),
        (check_s3_block_public_access, (bucket_name, block_config)),
        (check_s3_encryption, (bucket_name, encryption)),
    ]:
        f = checker(*args)
        if f:
            findings.append(f)
    return findings


# ── IAM Checks ────────────────────────────────────────

def check_iam_root_access_key(credential_report: dict) -> Finding | None:
    """
    Detect if the AWS root account has active access keys.
    `credential_report` is one row (dict) from the IAM credential report for <root_account>.
    """
    if credential_report.get("user") != "<root_account>":
        return None

    key1_active = credential_report.get("access_key_1_active", "false") == "true"
    key2_active = credential_report.get("access_key_2_active", "false") == "true"

    if not key1_active and not key2_active:
        return None

    active_keys = sum([key1_active, key2_active])
    return Finding(
        resource_id="<root_account>",
        resource_type="iam.credentials",
        severity="CRITICAL",
        title=f"Root account has {active_keys} active access key(s)",
        description=(
            "The AWS root account has programmatic access keys. "
            "Root keys have unrestricted access to all services and cannot be scoped."
        ),
        recommendation=(
            "Delete root access keys immediately: IAM Console → Root account → Security credentials → Delete access keys. "
            "Use IAM users or roles with least-privilege policies instead."
        ),
        raw=credential_report,
    )


def check_iam_root_mfa(credential_report: dict) -> Finding | None:
    """Detect if root account has MFA disabled."""
    if credential_report.get("user") != "<root_account>":
        return None
    if credential_report.get("mfa_active", "false") == "true":
        return None
    return Finding(
        resource_id="<root_account>",
        resource_type="iam.credentials",
        severity="CRITICAL",
        title="Root account MFA is disabled",
        description="The AWS root account does not have MFA enabled.",
        recommendation=(
            "Enable MFA for root: IAM Console → Root account → Security credentials → MFA."
        ),
        raw=credential_report,
    )


def check_iam_stale_access_key(user: str, key: dict, max_age_days: int = 90) -> Finding | None:
    """
    Detect IAM access keys older than max_age_days.
    `key` is one entry from iam.list_access_keys response.
    """
    from datetime import datetime, timezone

    created_str = key.get("CreateDate", "")
    if not created_str:
        return None

    if isinstance(created_str, str):
        created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
    else:
        created = created_str.replace(tzinfo=timezone.utc) if created_str.tzinfo is None else created_str

    age_days = (datetime.now(timezone.utc) - created).days

    if age_days <= max_age_days:
        return None

    return Finding(
        resource_id=f"{user}/{key.get('AccessKeyId', 'unknown')}",
        resource_type="iam.access_key",
        severity="HIGH",
        title=f"IAM access key is {age_days} days old",
        description=(
            f"User '{user}' has access key '{key.get('AccessKeyId')}' created {age_days} days ago. "
            f"Keys older than {max_age_days} days should be rotated."
        ),
        recommendation=(
            f"Rotate the key: aws iam create-access-key --user-name {user} "
            f"&& aws iam delete-access-key --user-name {user} --access-key-id {key.get('AccessKeyId')}"
        ),
        raw=key,
    )


# ── Security Group Checks ─────────────────────────────

def check_sg_open_ssh(sg: dict) -> Finding | None:
    """
    Detect Security Groups with SSH (TCP/22) open to 0.0.0.0/0 or ::/0.
    `sg` is one entry from ec2.describe_security_groups response.
    """
    sg_id = sg.get("GroupId", "unknown")
    sg_name = sg.get("GroupName", sg_id)

    for rule in sg.get("IpPermissions", []):
        if rule.get("IpProtocol") not in ("tcp", "-1"):
            continue

        from_port = rule.get("FromPort", 0)
        to_port = rule.get("ToPort", 65535)

        if rule.get("IpProtocol") == "-1" or (from_port <= 22 <= to_port):
            open_ranges = [
                r["CidrIp"] for r in rule.get("IpRanges", [])
                if r.get("CidrIp") in ("0.0.0.0/0",)
            ] + [
                r["CidrIpv6"] for r in rule.get("Ipv6Ranges", [])
                if r.get("CidrIpv6") in ("::/0",)
            ]
            if open_ranges:
                return Finding(
                    resource_id=sg_id,
                    resource_type="ec2.security_group",
                    severity="CRITICAL",
                    title=f"Security Group '{sg_name}' allows public SSH",
                    description=(
                        f"Security Group '{sg_id}' allows TCP/22 (SSH) from {open_ranges}. "
                        f"VPC: {sg.get('VpcId', 'unknown')}."
                    ),
                    recommendation=(
                        "Restrict port 22 to known IPs or use AWS Systems Manager Session Manager "
                        "(no inbound port needed): aws ec2 revoke-security-group-ingress "
                        f"--group-id {sg_id} --protocol tcp --port 22 --cidr 0.0.0.0/0"
                    ),
                    raw=sg,
                )
    return None


def check_sg_open_rdp(sg: dict) -> Finding | None:
    """Detect Security Groups with RDP (TCP/3389) open to 0.0.0.0/0."""
    sg_id = sg.get("GroupId", "unknown")
    sg_name = sg.get("GroupName", sg_id)

    for rule in sg.get("IpPermissions", []):
        if rule.get("IpProtocol") not in ("tcp", "-1"):
            continue
        from_port = rule.get("FromPort", 0)
        to_port = rule.get("ToPort", 65535)

        if rule.get("IpProtocol") == "-1" or (from_port <= 3389 <= to_port):
            open_ranges = [
                r["CidrIp"] for r in rule.get("IpRanges", [])
                if r.get("CidrIp") == "0.0.0.0/0"
            ]
            if open_ranges:
                return Finding(
                    resource_id=sg_id,
                    resource_type="ec2.security_group",
                    severity="CRITICAL",
                    title=f"Security Group '{sg_name}' allows public RDP",
                    description=f"Security Group '{sg_id}' allows TCP/3389 (RDP) from {open_ranges}.",
                    recommendation=(
                        "Restrict RDP to known IPs or use AWS Systems Manager Fleet Manager."
                    ),
                    raw=sg,
                )
    return None


def scan_security_groups(groups: list[dict]) -> list[Finding]:
    findings = []
    for sg in groups:
        for checker in [check_sg_open_ssh, check_sg_open_rdp]:
            f = checker(sg)
            if f:
                findings.append(f)
    return findings


# ── Top-level scanner ─────────────────────────────────

def run_aws_scan(region: str = "us-east-1") -> dict:
    """
    Fetch live AWS resources and run structured security checks.
    Requires boto3 with credentials (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY or IAM role).

    Permissions needed (read-only):
      s3:ListAllMyBuckets, s3:GetBucketAcl, s3:GetPublicAccessBlock, s3:GetEncryptionConfiguration
      iam:GenerateCredentialReport, iam:GetCredentialReport, iam:ListAccessKeys, iam:ListUsers
      ec2:DescribeSecurityGroups
    """
    import boto3
    from shared.circuit_breaker import get_breaker, CircuitOpenError

    findings = []

    # ── S3 ──
    try:
        with get_breaker("aws-s3"):
            s3 = boto3.client("s3", region_name=region)
            buckets = s3.list_buckets().get("Buckets", [])
            for bucket in buckets:
                name = bucket["Name"]
                acl = s3.get_bucket_acl(Bucket=name)
                try:
                    block = s3.get_public_access_block(Bucket=name)
                except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
                    block = {}
                try:
                    enc = s3.get_bucket_encryption(Bucket=name)
                except Exception:
                    enc = {}
                findings.extend(scan_s3_bucket(name, acl, block, enc))
    except CircuitOpenError as e:
        print(f"[aws_scan] SKIP s3 — circuit open: {e}")
    except Exception as e:
        print(f"[aws_scan] WARN s3: {e}")

    # ── IAM ──
    try:
        with get_breaker("aws-iam"):
            iam = boto3.client("iam", region_name=region)
            iam.generate_credential_report()
            import time; time.sleep(2)
            report_csv = iam.get_credential_report()["Content"].decode("utf-8")
            import csv, io
            reader = csv.DictReader(io.StringIO(report_csv))
            for row in reader:
                f = check_iam_root_access_key(row)
                if f:
                    findings.append(f)
                f = check_iam_root_mfa(row)
                if f:
                    findings.append(f)
            # Stale keys for non-root users
            users = iam.list_users().get("Users", [])
            for user in users:
                keys = iam.list_access_keys(UserName=user["UserName"]).get("AccessKeyMetadata", [])
                for key in keys:
                    f = check_iam_stale_access_key(user["UserName"], key)
                    if f:
                        findings.append(f)
    except CircuitOpenError as e:
        print(f"[aws_scan] SKIP iam — circuit open: {e}")
    except Exception as e:
        print(f"[aws_scan] WARN iam: {e}")

    # ── Security Groups ──
    try:
        with get_breaker("aws-ec2"):
            ec2 = boto3.client("ec2", region_name=region)
            paginator = ec2.get_paginator("describe_security_groups")
            groups = [sg for page in paginator.paginate() for sg in page["SecurityGroups"]]
            findings.extend(scan_security_groups(groups))
    except CircuitOpenError as e:
        print(f"[aws_scan] SKIP ec2 — circuit open: {e}")
    except Exception as e:
        print(f"[aws_scan] WARN ec2: {e}")

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: severity_order.get(f.severity, 9))

    return {
        "provider": "aws",
        "region": region,
        "findings_count": len(findings),
        "findings": [
            {
                "resource_id": f.resource_id,
                "resource_type": f.resource_type,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "recommendation": f.recommendation,
            }
            for f in findings
        ],
    }
