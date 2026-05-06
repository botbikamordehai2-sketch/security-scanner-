"""
Unit tests for gcp_audit.py — no GCP credentials required.
All inputs are synthetic dicts that mirror the real API response shape.
"""

import pytest
from gcp_audit import (
    check_firewall_public_ssh,
    scan_firewall_rules,
    check_storage_public_iam,
    check_storage_public_prevention,
    scan_storage_bucket,
    check_iam_overpermissive_sa,
    check_iam_allauth_project,
    scan_project_iam,
    check_sql_public_ip,
    check_sql_no_backup,
    scan_sql_instances,
    check_gke_dashboard_enabled,
    check_gke_legacy_auth,
    check_gke_public_nodes,
    scan_gke_clusters,
)


# ── Firewall fixtures ─────────────────────────────────

def fw(direction="INGRESS", sources=None, allowed=None, disabled=False, name="test-fw"):
    return {
        "name": name,
        "direction": direction,
        "sourceRanges": sources if sources is not None else ["0.0.0.0/0"],
        "allowed": allowed if allowed is not None else [{"IPProtocol": "tcp", "ports": ["22"]}],
        "disabled": disabled,
        "network": "global/networks/default",
    }


class TestFirewallPublicSsh:
    def test_classic_public_ssh_is_critical(self):
        finding = check_firewall_public_ssh(fw())
        assert finding is not None
        assert finding.severity == "CRITICAL"
        assert finding.resource_id == "test-fw"

    def test_disabled_rule_ignored(self):
        assert check_firewall_public_ssh(fw(disabled=True)) is None

    def test_egress_rule_ignored(self):
        assert check_firewall_public_ssh(fw(direction="EGRESS")) is None

    def test_private_source_range_ignored(self):
        assert check_firewall_public_ssh(fw(sources=["10.0.0.0/8"])) is None

    def test_ipv6_wildcard_detected(self):
        finding = check_firewall_public_ssh(fw(sources=["::/0"]))
        assert finding is not None

    def test_port_range_including_22_detected(self):
        allowed = [{"IPProtocol": "tcp", "ports": ["20-25"]}]
        assert check_firewall_public_ssh(fw(allowed=allowed)) is not None

    def test_all_ports_range_detected(self):
        allowed = [{"IPProtocol": "tcp", "ports": ["0-65535"]}]
        assert check_firewall_public_ssh(fw(allowed=allowed)) is not None

    def test_protocol_all_no_ports_detected(self):
        allowed = [{"IPProtocol": "all"}]
        assert check_firewall_public_ssh(fw(allowed=allowed)) is not None

    def test_different_port_not_detected(self):
        allowed = [{"IPProtocol": "tcp", "ports": ["80", "443"]}]
        assert check_firewall_public_ssh(fw(allowed=allowed)) is None

    def test_udp_port_22_not_detected(self):
        allowed = [{"IPProtocol": "udp", "ports": ["22"]}]
        assert check_firewall_public_ssh(fw(allowed=allowed)) is None

    def test_scan_firewall_rules_returns_list(self):
        rules = [fw(name="bad"), fw(sources=["10.0.0.0/8"], name="good")]
        findings = scan_firewall_rules(rules)
        assert len(findings) == 1
        assert findings[0].resource_id == "bad"


# ── Storage IAM fixtures ──────────────────────────────

def storage_policy(role="roles/storage.objectViewer", members=None):
    return {"bindings": [{"role": role, "members": members or ["allUsers"]}]}

def bucket_meta(prevention="enforced"):
    return {"iamConfiguration": {"publicAccessPrevention": prevention}}


class TestStoragePublicIam:
    def test_allusers_objectviewer_is_critical(self):
        finding = check_storage_public_iam("my-bucket", storage_policy())
        assert finding is not None
        assert finding.severity == "CRITICAL"

    def test_allauthenticated_non_sensitive_is_high(self):
        policy = storage_policy(role="roles/storage.legacyBucketWriter", members=["allAuthenticatedUsers"])
        finding = check_storage_public_iam("my-bucket", policy)
        assert finding is not None
        assert finding.severity == "HIGH"

    def test_specific_user_not_detected(self):
        policy = {"bindings": [{"role": "roles/storage.admin", "members": ["user:alice@example.com"]}]}
        assert check_storage_public_iam("my-bucket", policy) is None

    def test_empty_bindings_not_detected(self):
        assert check_storage_public_iam("my-bucket", {"bindings": []}) is None

    def test_resource_id_is_bucket_name(self):
        finding = check_storage_public_iam("secret-data", storage_policy())
        assert finding.resource_id == "secret-data"


class TestStoragePublicPrevention:
    def test_enforced_returns_none(self):
        assert check_storage_public_prevention("b", bucket_meta("enforced")) is None

    def test_unspecified_returns_low_finding(self):
        finding = check_storage_public_prevention("b", bucket_meta("unspecified"))
        assert finding is not None
        assert finding.severity == "LOW"

    def test_inherited_returns_low_finding(self):
        finding = check_storage_public_prevention("b", bucket_meta("inherited"))
        assert finding is not None

    def test_missing_iam_config_returns_low_finding(self):
        finding = check_storage_public_prevention("b", {})
        assert finding is not None

    def test_scan_storage_bucket_combines_both_checks(self):
        # Public IAM + missing prevention → 2 findings
        findings = scan_storage_bucket("b", storage_policy(), bucket_meta("unspecified"))
        assert len(findings) == 2

    def test_scan_storage_bucket_clean_returns_empty(self):
        clean_policy = {"bindings": [{"role": "roles/storage.objectViewer", "members": ["user:alice@example.com"]}]}
        findings = scan_storage_bucket("b", clean_policy, bucket_meta("enforced"))
        assert findings == []


# ── IAM project-level fixtures ────────────────────────

def iam_policy(role, members):
    return {"bindings": [{"role": role, "members": members}]}


class TestIamOverpermissiveSa:
    def test_sa_with_owner_is_critical(self):
        policy = iam_policy("roles/owner", ["serviceAccount:deploy@proj.iam.gserviceaccount.com"])
        findings = check_iam_overpermissive_sa("proj", policy)
        assert len(findings) == 1
        assert findings[0].severity == "CRITICAL"

    def test_sa_with_editor_is_high(self):
        policy = iam_policy("roles/editor", ["serviceAccount:ci@proj.iam.gserviceaccount.com"])
        findings = check_iam_overpermissive_sa("proj", policy)
        assert findings[0].severity == "HIGH"

    def test_default_compute_sa_with_editor_is_critical(self):
        policy = iam_policy("roles/editor", ["serviceAccount:123-compute@developer.gserviceaccount.com"])
        findings = check_iam_overpermissive_sa("proj", policy)
        assert findings[0].severity == "CRITICAL"
        assert "[DEFAULT SA]" in findings[0].title

    def test_human_user_with_owner_not_detected(self):
        policy = iam_policy("roles/owner", ["user:admin@example.com"])
        assert check_iam_overpermissive_sa("proj", policy) == []

    def test_sa_with_viewer_not_detected(self):
        policy = iam_policy("roles/viewer", ["serviceAccount:reader@proj.iam.gserviceaccount.com"])
        assert check_iam_overpermissive_sa("proj", policy) == []

    def test_multiple_sas_in_one_binding(self):
        policy = iam_policy("roles/owner", [
            "serviceAccount:a@proj.iam.gserviceaccount.com",
            "serviceAccount:b@proj.iam.gserviceaccount.com",
            "user:human@example.com",
        ])
        findings = check_iam_overpermissive_sa("proj", policy)
        assert len(findings) == 2


class TestIamAllauthProject:
    def test_allusers_any_role_is_critical(self):
        policy = iam_policy("roles/viewer", ["allUsers"])
        findings = check_iam_allauth_project("proj", policy)
        assert len(findings) == 1
        assert findings[0].severity == "CRITICAL"

    def test_allauthenticated_is_critical(self):
        policy = iam_policy("roles/viewer", ["allAuthenticatedUsers"])
        findings = check_iam_allauth_project("proj", policy)
        assert len(findings) == 1

    def test_specific_member_not_detected(self):
        policy = iam_policy("roles/viewer", ["user:someone@example.com"])
        assert check_iam_allauth_project("proj", policy) == []

    def test_scan_project_iam_combines_both_checkers(self):
        # allUsers + SA with owner → 2 findings
        policy = {
            "bindings": [
                {"role": "roles/viewer", "members": ["allUsers"]},
                {"role": "roles/owner", "members": ["serviceAccount:sa@proj.iam.gserviceaccount.com"]},
            ]
        }
        findings = scan_project_iam("proj", policy)
        assert len(findings) == 2


# ── Cloud SQL fixtures ────────────────────────────────

def sql_instance(ipv4=True, networks=None, backup=True, name="my-db", version="MYSQL_8_0"):
    inst = {
        "name": name,
        "databaseVersion": version,
        "settings": {
            "ipConfiguration": {
                "ipv4Enabled": ipv4,
                "authorizedNetworks": networks if networks is not None else [],
            },
            "backupConfiguration": {"enabled": backup},
        },
    }
    return inst


class TestSqlPublicIp:
    def test_public_ip_no_networks_is_critical(self):
        finding = check_sql_public_ip(sql_instance())
        assert finding is not None
        assert finding.severity == "CRITICAL"

    def test_public_ip_open_network_is_critical(self):
        networks = [{"value": "0.0.0.0/0", "name": "open"}]
        finding = check_sql_public_ip(sql_instance(networks=networks))
        assert finding is not None

    def test_public_ip_restricted_network_not_detected(self):
        networks = [{"value": "203.0.113.0/24", "name": "office"}]
        assert check_sql_public_ip(sql_instance(networks=networks)) is None

    def test_private_ip_only_not_detected(self):
        assert check_sql_public_ip(sql_instance(ipv4=False)) is None

    def test_ipv6_open_network_detected(self):
        networks = [{"value": "::/0"}]
        finding = check_sql_public_ip(sql_instance(networks=networks))
        assert finding is not None

    def test_resource_type_is_sqladmin(self):
        finding = check_sql_public_ip(sql_instance(name="prod-db"))
        assert finding.resource_type == "sqladmin.instances"
        assert finding.resource_id == "prod-db"


class TestSqlNoBackup:
    def test_backup_disabled_is_high(self):
        finding = check_sql_no_backup(sql_instance(backup=False))
        assert finding is not None
        assert finding.severity == "HIGH"

    def test_backup_enabled_not_detected(self):
        assert check_sql_no_backup(sql_instance(backup=True)) is None


class TestScanSqlInstances:
    def test_bad_instance_produces_two_findings(self):
        # public IP + no backup → CRITICAL + HIGH
        bad = sql_instance(ipv4=True, networks=[], backup=False)
        findings = scan_sql_instances([bad])
        assert len(findings) == 2

    def test_clean_instance_produces_no_findings(self):
        clean = sql_instance(ipv4=False, backup=True)
        assert scan_sql_instances([clean]) == []

    def test_multiple_instances_aggregated(self):
        instances = [
            sql_instance(name="bad", ipv4=True, networks=[], backup=False),
            sql_instance(name="ok", ipv4=False, backup=True),
        ]
        findings = scan_sql_instances(instances)
        assert all(f.resource_id == "bad" for f in findings)


# ── GKE fixtures ──────────────────────────────────────

def gke_cluster(name="prod", dashboard_disabled=True, legacy_abac=False, private_nodes=False):
    return {
        "name": name,
        "addonsConfig": {
            "kubernetesDashboard": {"disabled": dashboard_disabled},
        },
        "legacyAbac": {"enabled": legacy_abac},
        "privateClusterConfig": {"enablePrivateNodes": private_nodes},
        "nodePools": [],
    }


class TestGkeDashboard:
    def test_dashboard_enabled_is_high(self):
        cluster = gke_cluster(dashboard_disabled=False)
        finding = check_gke_dashboard_enabled(cluster)
        assert finding is not None
        assert finding.severity == "HIGH"

    def test_dashboard_disabled_not_detected(self):
        assert check_gke_dashboard_enabled(gke_cluster(dashboard_disabled=True)) is None

    def test_missing_addons_config_not_detected(self):
        assert check_gke_dashboard_enabled({"name": "x"}) is None


class TestGkeLegacyAuth:
    def test_legacy_abac_enabled_is_high(self):
        finding = check_gke_legacy_auth(gke_cluster(legacy_abac=True))
        assert finding is not None
        assert finding.severity == "HIGH"

    def test_legacy_abac_disabled_not_detected(self):
        assert check_gke_legacy_auth(gke_cluster(legacy_abac=False)) is None


class TestGkePublicNodes:
    def test_public_nodes_is_medium(self):
        finding = check_gke_public_nodes(gke_cluster(private_nodes=False))
        assert finding is not None
        assert finding.severity == "MEDIUM"

    def test_private_nodes_not_detected(self):
        assert check_gke_public_nodes(gke_cluster(private_nodes=True)) is None


class TestScanGkeClusters:
    def test_fully_misconfigured_cluster_produces_three_findings(self):
        bad = gke_cluster(dashboard_disabled=False, legacy_abac=True, private_nodes=False)
        findings = scan_gke_clusters([bad])
        assert len(findings) == 3

    def test_hardened_cluster_produces_no_findings(self):
        good = gke_cluster(dashboard_disabled=True, legacy_abac=False, private_nodes=True)
        assert scan_gke_clusters([good]) == []
