"""Unit tests for aws_audit.py and shared/circuit_breaker.py — no AWS credentials needed."""

import sys
import time
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from aws_audit import (
    check_s3_public_acl,
    check_s3_block_public_access,
    check_s3_encryption,
    scan_s3_bucket,
    check_iam_root_access_key,
    check_iam_root_mfa,
    check_iam_stale_access_key,
    check_sg_open_ssh,
    check_sg_open_rdp,
    scan_security_groups,
)
from shared.circuit_breaker import CircuitBreaker, CircuitOpenError, State, get_breaker


# ── S3 fixtures ───────────────────────────────────────

_ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
_AUTH_USERS = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"

def acl(uri=_ALL_USERS, permission="READ"):
    return {"Grants": [{"Grantee": {"URI": uri, "Type": "Group"}, "Permission": permission}]}

def acl_private():
    return {"Grants": [{"Grantee": {"Type": "CanonicalUser"}, "Permission": "FULL_CONTROL"}]}

def block(all_true=True):
    return {"PublicAccessBlockConfiguration": {
        "BlockPublicAcls": all_true, "BlockPublicPolicy": all_true,
        "IgnorePublicAcls": all_true, "RestrictPublicBuckets": all_true,
    }}

def encryption(enabled=True):
    if enabled:
        return {"ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}}
    return {}


class TestS3PublicAcl:
    def test_allusers_read_is_high(self):
        f = check_s3_public_acl("my-bucket", acl(permission="READ"))
        assert f is not None
        assert f.severity == "HIGH"

    def test_allusers_full_control_is_critical(self):
        f = check_s3_public_acl("my-bucket", acl(permission="FULL_CONTROL"))
        assert f is not None
        assert f.severity == "CRITICAL"

    def test_authenticated_users_detected(self):
        assert check_s3_public_acl("b", acl(uri=_AUTH_USERS)) is not None

    def test_private_acl_not_detected(self):
        assert check_s3_public_acl("b", acl_private()) is None

    def test_empty_grants_not_detected(self):
        assert check_s3_public_acl("b", {"Grants": []}) is None


class TestS3BlockPublicAccess:
    def test_fully_enabled_not_detected(self):
        assert check_s3_block_public_access("b", block(True)) is None

    def test_missing_config_is_medium(self):
        f = check_s3_block_public_access("b", {})
        assert f is not None
        assert f.severity == "MEDIUM"

    def test_partial_config_is_medium(self):
        partial = {"PublicAccessBlockConfiguration": {"BlockPublicAcls": True, "BlockPublicPolicy": False, "IgnorePublicAcls": True, "RestrictPublicBuckets": False}}
        f = check_s3_block_public_access("b", partial)
        assert f is not None
        assert "BlockPublicPolicy" in f.description


class TestS3Encryption:
    def test_encrypted_not_detected(self):
        assert check_s3_encryption("b", encryption(True)) is None

    def test_no_encryption_is_medium(self):
        f = check_s3_encryption("b", encryption(False))
        assert f is not None
        assert f.severity == "MEDIUM"

    def test_empty_dict_is_medium(self):
        assert check_s3_encryption("b", {}) is not None


class TestScanS3Bucket:
    def test_fully_misconfigured_produces_three_findings(self):
        findings = scan_s3_bucket("b", acl(), block(False), encryption(False))
        assert len(findings) == 3

    def test_clean_bucket_produces_no_findings(self):
        findings = scan_s3_bucket("b", acl_private(), block(True), encryption(True))
        assert findings == []


# ── IAM fixtures ──────────────────────────────────────

def root_row(key1=False, key2=False, mfa=True):
    return {
        "user": "<root_account>",
        "access_key_1_active": str(key1).lower(),
        "access_key_2_active": str(key2).lower(),
        "mfa_active": str(mfa).lower(),
    }

def access_key(age_days=100, key_id="AKIA123"):
    from datetime import datetime, timezone, timedelta
    created = datetime.now(timezone.utc) - timedelta(days=age_days)
    return {"AccessKeyId": key_id, "CreateDate": created.isoformat(), "Status": "Active"}


class TestIamRootAccessKey:
    def test_root_with_active_key_is_critical(self):
        f = check_iam_root_access_key(root_row(key1=True))
        assert f is not None
        assert f.severity == "CRITICAL"

    def test_root_no_keys_not_detected(self):
        assert check_iam_root_access_key(root_row()) is None

    def test_non_root_user_ignored(self):
        row = {"user": "alice", "access_key_1_active": "true"}
        assert check_iam_root_access_key(row) is None


class TestIamRootMfa:
    def test_root_no_mfa_is_critical(self):
        f = check_iam_root_mfa(root_row(mfa=False))
        assert f is not None
        assert f.severity == "CRITICAL"

    def test_root_with_mfa_not_detected(self):
        assert check_iam_root_mfa(root_row(mfa=True)) is None


class TestIamStaleAccessKey:
    def test_old_key_is_high(self):
        f = check_iam_stale_access_key("alice", access_key(age_days=100))
        assert f is not None
        assert f.severity == "HIGH"

    def test_fresh_key_not_detected(self):
        assert check_iam_stale_access_key("alice", access_key(age_days=10)) is None

    def test_exactly_at_threshold_not_detected(self):
        assert check_iam_stale_access_key("alice", access_key(age_days=90)) is None


# ── Security Group fixtures ───────────────────────────

def sg(from_port=22, to_port=22, cidr="0.0.0.0/0", protocol="tcp", sg_id="sg-123", name="test-sg"):
    return {
        "GroupId": sg_id,
        "GroupName": name,
        "VpcId": "vpc-abc",
        "IpPermissions": [{
            "IpProtocol": protocol,
            "FromPort": from_port,
            "ToPort": to_port,
            "IpRanges": [{"CidrIp": cidr}] if cidr else [],
            "Ipv6Ranges": [],
        }],
    }

def sg_clean():
    return {"GroupId": "sg-safe", "GroupName": "safe", "IpPermissions": []}


class TestSecurityGroupSsh:
    def test_public_ssh_is_critical(self):
        f = check_sg_open_ssh(sg())
        assert f is not None
        assert f.severity == "CRITICAL"

    def test_restricted_ssh_not_detected(self):
        assert check_sg_open_ssh(sg(cidr="10.0.0.0/8")) is None

    def test_all_ports_open_detected(self):
        f = check_sg_open_ssh(sg(from_port=0, to_port=65535))
        assert f is not None

    def test_protocol_minus1_detected(self):
        f = check_sg_open_ssh(sg(protocol="-1", from_port=None, to_port=None))
        assert f is not None

    def test_rdp_port_not_detected_by_ssh_check(self):
        assert check_sg_open_ssh(sg(from_port=3389, to_port=3389)) is None

    def test_clean_sg_not_detected(self):
        assert check_sg_open_ssh(sg_clean()) is None


class TestSecurityGroupRdp:
    def test_public_rdp_is_critical(self):
        f = check_sg_open_rdp(sg(from_port=3389, to_port=3389))
        assert f is not None
        assert f.severity == "CRITICAL"

    def test_ssh_port_not_detected_by_rdp_check(self):
        assert check_sg_open_rdp(sg(from_port=22, to_port=22)) is None


class TestScanSecurityGroups:
    def test_bad_sg_produces_finding(self):
        findings = scan_security_groups([sg()])
        assert len(findings) == 1

    def test_clean_sg_produces_no_findings(self):
        assert scan_security_groups([sg_clean()]) == []


# ── Circuit Breaker tests ─────────────────────────────

class TestCircuitBreaker:
    def test_starts_closed(self):
        cb = CircuitBreaker("test-start", failure_threshold=3)
        assert cb.state == State.CLOSED

    def test_opens_after_threshold_failures(self):
        cb = CircuitBreaker("test-open", failure_threshold=2)
        for _ in range(2):
            try:
                with cb:
                    raise ValueError("fail")
            except ValueError:
                pass
        assert cb.state == State.OPEN

    def test_open_raises_circuit_open_error(self):
        cb = CircuitBreaker("test-block", failure_threshold=1, recovery_timeout=60)
        try:
            with cb:
                raise ValueError("fail")
        except ValueError:
            pass
        with pytest.raises(CircuitOpenError):
            with cb:
                pass

    def test_success_resets_failure_count(self):
        cb = CircuitBreaker("test-reset", failure_threshold=3)
        try:
            with cb:
                raise ValueError()
        except ValueError:
            pass
        with cb:
            pass  # success
        assert cb._failure_count == 0

    def test_half_open_after_recovery_timeout(self):
        cb = CircuitBreaker("test-halfopen", failure_threshold=1, recovery_timeout=0.05)
        try:
            with cb:
                raise ValueError()
        except ValueError:
            pass
        assert cb.state == State.OPEN
        time.sleep(0.1)
        assert cb.state == State.HALF_OPEN

    def test_closes_after_success_in_half_open(self):
        cb = CircuitBreaker("test-close", failure_threshold=1, recovery_timeout=0.05)
        try:
            with cb:
                raise ValueError()
        except ValueError:
            pass
        time.sleep(0.1)
        with cb:
            pass  # success in HALF_OPEN
        assert cb.state == State.CLOSED

    def test_get_breaker_returns_singleton(self):
        cb1 = get_breaker("singleton-test")
        cb2 = get_breaker("singleton-test")
        assert cb1 is cb2
