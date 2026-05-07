"""
GCP Resource Security Scanner — structured API response analysis.
Complements audit_skills.py (file/pattern scanner) with cloud resource checks.
"""

from dataclasses import dataclass, field


@dataclass
class Finding:
    resource_id: str
    resource_type: str
    severity: str        # CRITICAL | HIGH | MEDIUM | LOW
    title: str
    description: str
    recommendation: str
    raw: dict = field(default_factory=dict, repr=False)


def _port_in_range(port: int, port_spec: str) -> bool:
    """Return True if port falls within a GCP port spec ('22', '20-25', '0-65535')."""
    if "-" in port_spec:
        lo, hi = port_spec.split("-", 1)
        return int(lo) <= port <= int(hi)
    return port_spec == str(port)


def check_firewall_public_ssh(rule: dict) -> Finding | None:
    """
    Detect Firewall rules that allow SSH (TCP/22) from any source.
    Returns a Finding if the rule is a public SSH exposure, else None.
    """
    if rule.get("disabled"):
        return None

    if rule.get("direction") != "INGRESS":
        return None

    source_ranges = rule.get("sourceRanges", [])
    if not any(r in ("0.0.0.0/0", "::/0") for r in source_ranges):
        return None

    for allow in rule.get("allowed", []):
        if allow.get("IPProtocol") not in ("tcp", "all"):
            continue
        ports = allow.get("ports", [])
        # "all" protocol with no ports list means all ports
        if allow.get("IPProtocol") == "all" or not ports:
            return _make_ssh_finding(rule)
        if any(_port_in_range(22, p) for p in ports):
            return _make_ssh_finding(rule)

    return None


def _make_ssh_finding(rule: dict) -> Finding:
    return Finding(
        resource_id=rule.get("name", "unknown"),
        resource_type="compute.firewalls",
        severity="CRITICAL",
        title="Public SSH exposure (0.0.0.0/0 → TCP/22)",
        description=(
            f"Firewall rule '{rule.get('name')}' allows SSH from any IP. "
            f"Network: {rule.get('network', 'unknown')}"
        ),
        recommendation=(
            "Restrict sourceRanges to known IPs or use IAP tunneling "
            "(https://cloud.google.com/iap/docs/using-tcp-forwarding) instead."
        ),
        raw=rule,
    )


def scan_firewall_rules(rules: list[dict]) -> list[Finding]:
    """Run all firewall checks across a list of rules from compute.firewalls.list."""
    findings = []
    checkers = [check_firewall_public_ssh]
    for rule in rules:
        for checker in checkers:
            finding = checker(rule)
            if finding:
                findings.append(finding)
    return findings


# ── Storage Bucket Checks ─────────────────────────────

_PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}

# Roles that grant read access — these matter most when assigned publicly
_SENSITIVE_ROLES = {
    "roles/storage.objectViewer",
    "roles/storage.objectAdmin",
    "roles/storage.admin",
    "roles/storage.legacyBucketReader",
    "roles/storage.legacyObjectReader",
    "roles/viewer",
    "roles/editor",
    "roles/owner",
}


def check_storage_public_iam(bucket_name: str, policy: dict) -> Finding | None:
    """
    Detect Storage buckets with public IAM bindings (allUsers / allAuthenticatedUsers).
    `policy` is the response from storage.buckets.getIamPolicy.
    Returns a Finding if public access is granted, else None.
    """
    public_bindings = []

    for binding in policy.get("bindings", []):
        members = set(binding.get("members", []))
        public = members & _PUBLIC_MEMBERS
        if not public:
            continue

        role = binding.get("role", "")
        severity = "CRITICAL" if role in _SENSITIVE_ROLES else "HIGH"
        public_bindings.append((role, public, severity))

    if not public_bindings:
        return None

    worst_severity = "CRITICAL" if any(s == "CRITICAL" for _, _, s in public_bindings) else "HIGH"
    roles_summary = ", ".join(f"{role} → {members}" for role, members, _ in public_bindings)

    return Finding(
        resource_id=bucket_name,
        resource_type="storage.buckets",
        severity=worst_severity,
        title="Storage bucket publicly accessible via IAM",
        description=f"Bucket '{bucket_name}' grants public access: {roles_summary}",
        recommendation=(
            "Remove allUsers/allAuthenticatedUsers from IAM bindings. "
            "Enable Public Access Prevention: "
            "gcloud storage buckets update gs://BUCKET --public-access-prevention=enforced"
        ),
        raw=policy,
    )


def check_storage_public_prevention(bucket_name: str, bucket_meta: dict) -> Finding | None:
    """
    Detect buckets where publicAccessPrevention is not enforced.
    `bucket_meta` is the response from storage.buckets.get.
    Returns a Finding (LOW) when the guard is missing — even if not yet public.
    """
    iam_config = bucket_meta.get("iamConfiguration", {})
    prevention = iam_config.get("publicAccessPrevention", "unspecified")

    if prevention == "enforced":
        return None

    return Finding(
        resource_id=bucket_name,
        resource_type="storage.buckets",
        severity="LOW",
        title="Public Access Prevention not enforced",
        description=(
            f"Bucket '{bucket_name}' has publicAccessPrevention='{prevention}'. "
            "A future IAM misconfiguration could expose it publicly."
        ),
        recommendation=(
            "gcloud storage buckets update gs://BUCKET --public-access-prevention=enforced"
        ),
        raw=bucket_meta,
    )


def scan_storage_bucket(bucket_name: str, policy: dict, bucket_meta: dict) -> list[Finding]:
    """Run all storage checks for a single bucket."""
    findings = []
    for checker, args in [
        (check_storage_public_iam, (bucket_name, policy)),
        (check_storage_public_prevention, (bucket_name, bucket_meta)),
    ]:
        finding = checker(*args)
        if finding:
            findings.append(finding)
    return findings


# ── IAM Project-Level Checks ──────────────────────────

# Roles that grant dangerous project-wide access
_OVERPERMISSIVE_ROLES = {
    "roles/owner":              "CRITICAL",
    "roles/editor":             "HIGH",
    "roles/iam.securityAdmin":  "HIGH",
    "roles/iam.admin":          "HIGH",
}

# GCP default service accounts that ship with editor by default — common misconfiguration
_DEFAULT_SA_SUFFIXES = (
    "-compute@developer.gserviceaccount.com",
    "@appspot.gserviceaccount.com",
    "@cloudservices.gserviceaccount.com",
)


def _is_service_account(member: str) -> bool:
    return member.startswith("serviceAccount:")


def _is_default_sa(member: str) -> bool:
    account = member.removeprefix("serviceAccount:")
    return any(account.endswith(suffix) for suffix in _DEFAULT_SA_SUFFIXES)


def check_iam_overpermissive_sa(project_id: str, policy: dict) -> list[Finding]:
    """
    Detect service accounts with project-level owner/editor/securityAdmin roles.
    `policy` is the response from cloudresourcemanager.projects.getIamPolicy.
    """
    findings = []

    for binding in policy.get("bindings", []):
        role = binding.get("role", "")
        severity = _OVERPERMISSIVE_ROLES.get(role)
        if not severity:
            continue

        for member in binding.get("members", []):
            if not _is_service_account(member):
                continue

            is_default = _is_default_sa(member)
            # Default SAs with editor are CRITICAL — GCP docs explicitly warn against this
            effective_severity = "CRITICAL" if is_default and role == "roles/editor" else severity
            label = " [DEFAULT SA]" if is_default else ""

            findings.append(Finding(
                resource_id=f"{project_id}/iamPolicy",
                resource_type="iam.project",
                severity=effective_severity,
                title=f"Service account has {role}{label}",
                description=(
                    f"'{member}' holds '{role}' on project '{project_id}'. "
                    + ("Default service accounts should never have editor/owner. " if is_default else "")
                    + "This grants broad access to all project resources."
                ),
                recommendation=(
                    f"Replace '{role}' with the minimum role required. "
                    "See: https://cloud.google.com/iam/docs/understanding-roles#predefined_roles"
                ),
                raw=binding,
            ))

    return findings


def check_iam_allauth_project(project_id: str, policy: dict) -> list[Finding]:
    """
    Detect any binding that grants allUsers or allAuthenticatedUsers a role at project level.
    Even viewer access project-wide is a significant exposure.
    """
    findings = []

    for binding in policy.get("bindings", []):
        members = set(binding.get("members", []))
        public = members & _PUBLIC_MEMBERS
        if not public:
            continue

        role = binding.get("role", "")
        findings.append(Finding(
            resource_id=f"{project_id}/iamPolicy",
            resource_type="iam.project",
            severity="CRITICAL",
            title=f"Project IAM grants {public} the role {role}",
            description=(
                f"Role '{role}' is granted to {public} at the project level. "
                "This exposes all resources in the project to unauthenticated or public access."
            ),
            recommendation=(
                "Remove public members from project-level IAM immediately. "
                "Use resource-level bindings with specific identities instead."
            ),
            raw=binding,
        ))

    return findings


def scan_project_iam(project_id: str, policy: dict) -> list[Finding]:
    """Run all IAM checks against a project-level IAM policy."""
    findings = []
    for checker in [check_iam_overpermissive_sa, check_iam_allauth_project]:
        findings.extend(checker(project_id, policy))
    return findings


# ── Cloud SQL Checks ──────────────────────────────────

def check_sql_public_ip(instance: dict) -> Finding | None:
    """
    Detect Cloud SQL instances with a public IP and no network restrictions.
    `instance` is one entry from sqladmin.instances.list response.

    Risky when BOTH conditions hold:
      1. ipv4Enabled = True  (public IP assigned)
      2. authorizedNetworks is empty OR contains 0.0.0.0/0
    """
    name = instance.get("name", "unknown")
    ip_config = instance.get("settings", {}).get("ipConfiguration", {})

    if not ip_config.get("ipv4Enabled", False):
        return None

    networks = ip_config.get("authorizedNetworks", [])
    open_to_all = any(n.get("value") in ("0.0.0.0/0", "::/0") for n in networks)
    unrestricted = len(networks) == 0 or open_to_all

    if not unrestricted:
        return None

    reason = "no authorized networks configured" if not networks else "0.0.0.0/0 in authorized networks"

    return Finding(
        resource_id=name,
        resource_type="sqladmin.instances",
        severity="CRITICAL",
        title="Cloud SQL instance has unrestricted public IP",
        description=(
            f"Instance '{name}' has a public IPv4 address and {reason}. "
            f"Database type: {instance.get('databaseVersion', 'unknown')}."
        ),
        recommendation=(
            "Either disable the public IP (use Private IP + Cloud SQL Auth Proxy) "
            "or add specific CIDR ranges to authorizedNetworks. "
            "See: https://cloud.google.com/sql/docs/mysql/configure-ip"
        ),
        raw=instance,
    )


def check_sql_no_backup(instance: dict) -> Finding | None:
    """Detect Cloud SQL instances with automated backups disabled."""
    name = instance.get("name", "unknown")
    backup_config = instance.get("settings", {}).get("backupConfiguration", {})

    if backup_config.get("enabled", False):
        return None

    return Finding(
        resource_id=name,
        resource_type="sqladmin.instances",
        severity="HIGH",
        title="Cloud SQL automated backups disabled",
        description=f"Instance '{name}' has no automated backup schedule configured.",
        recommendation=(
            "Enable automated backups: gcloud sql instances patch INSTANCE --backup-start-time=02:00"
        ),
        raw=instance,
    )


def scan_sql_instances(instances: list[dict]) -> list[Finding]:
    """Run all Cloud SQL checks across a list of instances."""
    findings = []
    for instance in instances:
        for checker in [check_sql_public_ip, check_sql_no_backup]:
            finding = checker(instance)
            if finding:
                findings.append(finding)
    return findings


# ── GKE Cluster Checks ────────────────────────────────

def check_gke_dashboard_enabled(cluster: dict) -> Finding | None:
    """Detect GKE clusters with the Kubernetes Dashboard addon enabled."""
    name = cluster.get("name", "unknown")
    addons = cluster.get("addonsConfig", {})
    dashboard = addons.get("kubernetesDashboard", {})

    if dashboard.get("disabled", True):
        return None

    return Finding(
        resource_id=name,
        resource_type="container.clusters",
        severity="HIGH",
        title="Kubernetes Dashboard addon is enabled",
        description=(
            f"Cluster '{name}' has the Kubernetes Dashboard enabled. "
            "The dashboard has historically been exploited for cluster takeover (e.g. Tesla cryptojacking 2018)."
        ),
        recommendation=(
            "Disable the dashboard: gcloud container clusters update CLUSTER --update-addons=KubernetesDashboard=DISABLED"
        ),
        raw=cluster,
    )


def check_gke_legacy_auth(cluster: dict) -> Finding | None:
    """Detect GKE clusters with legacy ABAC authorization enabled."""
    name = cluster.get("name", "unknown")

    if not cluster.get("legacyAbac", {}).get("enabled", False):
        return None

    return Finding(
        resource_id=name,
        resource_type="container.clusters",
        severity="HIGH",
        title="GKE legacy ABAC authorization enabled",
        description=(
            f"Cluster '{name}' uses legacy Attribute-Based Access Control. "
            "ABAC grants overly broad permissions and bypasses RBAC policies."
        ),
        recommendation=(
            "Disable legacy ABAC: gcloud container clusters update CLUSTER --no-enable-legacy-authorization"
        ),
        raw=cluster,
    )


def check_gke_public_nodes(cluster: dict) -> Finding | None:
    """Detect GKE node pools with public IP addresses assigned to nodes."""
    name = cluster.get("name", "unknown")

    # Simpler signal: cluster-level privateClusterConfig
    private_config = cluster.get("privateClusterConfig", {})
    if private_config.get("enablePrivateNodes", False):
        return None

    return Finding(
        resource_id=name,
        resource_type="container.clusters",
        severity="MEDIUM",
        title="GKE nodes have public IP addresses",
        description=(
            f"Cluster '{name}' does not use private nodes. "
            "Nodes with public IPs increase attack surface for direct node access."
        ),
        recommendation=(
            "Migrate to a private cluster: enable privateClusterConfig.enablePrivateNodes. "
            "See: https://cloud.google.com/kubernetes-engine/docs/how-to/private-clusters"
        ),
        raw=cluster,
    )


def scan_gke_clusters(clusters: list[dict]) -> list[Finding]:
    """Run all GKE checks across a list of clusters."""
    findings = []
    for cluster in clusters:
        for checker in [check_gke_dashboard_enabled, check_gke_legacy_auth, check_gke_public_nodes]:
            finding = checker(cluster)
            if finding:
                findings.append(finding)
    return findings
