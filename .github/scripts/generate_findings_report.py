"""
Generate a findings_report.json file from gcp_audit module for CI visibility.
Runs locally (no GCP credentials needed) — outputs test fixture data showing
which checks exist, severity distribution, and resource coverage.

Output: findings_report.json — uploaded as CI artifact for audit trail.
"""

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# ── Add project root for imports ──
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

try:
    from agents.security_agent.gcp_audit import (
        Finding,
        scan_firewall_rules,
        scan_storage_bucket,
        scan_project_iam,
        scan_sql_instances,
        scan_gke_clusters,
    )
    AUDIT_AVAILABLE = True
except ImportError:
    AUDIT_AVAILABLE = False


def generate_report():
    """Generate a findings_report.json with coverage map and dry-run results."""
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "audit_module_available": AUDIT_AVAILABLE,
        "checks": [
            {
                "check_id": "check_firewall_public_ssh",
                "resource": "compute.firewalls",
                "severity": "CRITICAL",
                "description": "Firewall rules allowing SSH (TCP/22) from 0.0.0.0/0 or ::/0",
            },
            {
                "check_id": "check_storage_public_iam",
                "resource": "storage.buckets",
                "severity": "CRITICAL/HIGH",
                "description": "Storage buckets with allUsers/allAuthenticatedUsers IAM",
            },
            {
                "check_id": "check_storage_public_prevention",
                "resource": "storage.buckets",
                "severity": "LOW",
                "description": "Storage buckets without publicAccessPrevention=enforced",
            },
            {
                "check_id": "check_iam_overpermissive_sa",
                "resource": "iam.project",
                "severity": "CRITICAL/HIGH",
                "description": "Service accounts with owner/editor/securityAdmin at project level",
            },
            {
                "check_id": "check_iam_allauth_project",
                "resource": "iam.project",
                "severity": "CRITICAL",
                "description": "allUsers/allAuthenticatedUsers in project-level IAM bindings",
            },
            {
                "check_id": "check_sql_public_ip",
                "resource": "sqladmin.instances",
                "severity": "CRITICAL",
                "description": "Cloud SQL instances with public IP and no authorized networks",
            },
            {
                "check_id": "check_sql_no_backup",
                "resource": "sqladmin.instances",
                "severity": "HIGH",
                "description": "Cloud SQL instances with automated backups disabled",
            },
            {
                "check_id": "check_gke_dashboard_enabled",
                "resource": "container.clusters",
                "severity": "HIGH",
                "description": "GKE clusters with Kubernetes Dashboard addon enabled",
            },
            {
                "check_id": "check_gke_legacy_auth",
                "resource": "container.clusters",
                "severity": "HIGH",
                "description": "GKE clusters with legacy ABAC authorization enabled",
            },
            {
                "check_id": "check_gke_public_nodes",
                "resource": "container.clusters",
                "severity": "MEDIUM",
                "description": "GKE clusters without private nodes enabled",
            },
        ],
        "resources_covered": [
            "compute.firewalls",
            "storage.buckets",
            "iam.project",
            "sqladmin.instances",
            "container.clusters",
        ],
        "severity_distribution": {
            "CRITICAL": 4,
            "HIGH": 4,
            "MEDIUM": 1,
            "LOW": 1,
        },
        "dry_run_findings": [],
    }

    # ── Run dry-run scans on sample data if module available ──
    if AUDIT_AVAILABLE:
        # Firewall dry-run
        sample_firewall_rules = [
            {
                "name": "allow-ssh-public",
                "disabled": False,
                "direction": "INGRESS",
                "sourceRanges": ["0.0.0.0/0"],
                "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
                "network": "default",
            },
            {
                "name": "default-deny-ingress",
                "disabled": False,
                "direction": "INGRESS",
                "sourceRanges": ["10.0.0.0/8"],
                "allowed": [{"IPProtocol": "tcp", "ports": ["443"]}],
                "network": "default",
            },
        ]
        fw_findings = scan_firewall_rules(sample_firewall_rules)
        for f in fw_findings:
            report["dry_run_findings"].append({
                "check": "check_firewall_public_ssh",
                "resource_id": f.resource_id,
                "severity": f.severity,
                "title": f.title,
            })

        # Storage dry-run
        sample_storage_policy = {
            "bindings": [
                {"role": "roles/storage.objectViewer", "members": ["allUsers"]},
                {"role": "roles/storage.objectCreator", "members": ["user:admin@example.com"]},
            ]
        }
        sample_bucket_meta = {
            "name": "sample-public-bucket",
            "iamConfiguration": {"publicAccessPrevention": "unspecified"},
        }
        storage_findings = scan_storage_bucket("sample-public-bucket", sample_storage_policy, sample_bucket_meta)
        for f in storage_findings:
            report["dry_run_findings"].append({
                "check": "check_storage_public_iam_or_prevention",
                "resource_id": f.resource_id,
                "severity": f.severity,
                "title": f.title,
            })

        # IAM dry-run
        sample_iam_policy = {
            "bindings": [
                {"role": "roles/editor", "members": ["serviceAccount:123456-compute@developer.gserviceaccount.com"]},
                {"role": "roles/viewer", "members": ["allUsers"]},
                {"role": "roles/iam.viewer", "members": ["user:safe@example.com"]},
            ]
        }
        iam_findings = scan_project_iam("sample-project", sample_iam_policy)
        for f in iam_findings:
            report["dry_run_findings"].append({
                "check": "check_iam_overpermissive_sa_or_allauth",
                "resource_id": f.resource_id,
                "severity": f.severity,
                "title": f.title,
            })

        # Cloud SQL dry-run
        sample_sql_instances = [
            {
                "name": "public-db-no-backup",
                "settings": {
                    "ipConfiguration": {
                        "ipv4Enabled": True,
                        "authorizedNetworks": [],
                    },
                    "backupConfiguration": {
                        "enabled": False,
                    },
                },
                "databaseVersion": "POSTGRES_15",
            },
            {
                "name": "private-db-with-backup",
                "settings": {
                    "ipConfiguration": {
                        "ipv4Enabled": False,
                    },
                    "backupConfiguration": {
                        "enabled": True,
                    },
                },
                "databaseVersion": "MYSQL_8_0",
            },
        ]
        sql_findings = scan_sql_instances(sample_sql_instances)
        for f in sql_findings:
            report["dry_run_findings"].append({
                "check": "check_sql_public_ip_or_backup",
                "resource_id": f.resource_id,
                "severity": f.severity,
                "title": f.title,
            })

        # GKE dry-run
        sample_gke_clusters = [
            {
                "name": "legacy-cluster",
                "addonsConfig": {
                    "kubernetesDashboard": {"disabled": False},
                },
                "legacyAbac": {"enabled": True},
                "privateClusterConfig": {"enablePrivateNodes": False},
            },
        ]
        gke_findings = scan_gke_clusters(sample_gke_clusters)
        for f in gke_findings:
            report["dry_run_findings"].append({
                "check": "check_gke_dashboard_or_legacy_or_public",
                "resource_id": f.resource_id,
                "severity": f.severity,
                "title": f.title,
            })

        report["dry_run_total_findings"] = len(report["dry_run_findings"])

    # ── Write report ──
    output_path = Path(__file__).resolve().parent.parent.parent / "findings_report.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"findings_report.json generated: {output_path}")
    print(f"  Checks defined: {len(report['checks'])}")
    print(f"  Severity coverage: {report['severity_distribution']}")
    print(f"  Dry-run findings: {len(report.get('dry_run_findings', []))}")
    return 0


if __name__ == "__main__":
    sys.exit(generate_report())