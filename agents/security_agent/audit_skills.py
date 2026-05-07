"""
Security Audit Script — ClawHub SKILL.md Scanner + Docker Sandbox Validator.
Scans installed skills for ClawSwarm crypto-mining / exfiltration threats.
Validates Docker sandbox configuration for agent isolation.

Usage:
    python audit_skills.py                # Full audit
    python audit_skills.py --sha256-only  # Only SHA-256 verification
    python audit_skills.py --docker-only  # Only Docker sandbox validation
"""

import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

# ── Configuration ────────────────────────────────────

# Known malicious patterns in SKILL.md files (ClawSwarm threat intel)
MALICIOUS_PATTERNS = [
    # Crypto mining
    "xmrig", "minerd", "cpuminer", "cryptonight", "stratum+tcp://",
    "nicehash", "unmineable", "phoenixminer", "lolminer", "trex",
    "ethminer", "gminer", "nbminer", "cryptocurrency", "wallet_address",
    # Exfiltration
    "curl.*/.env", "curl.*id_rsa", "curl.*credentials",
    "telegram.*sendDocument", "telegram.*sendPhoto",
    "ngrok", "serveo.net", "localhost.run",
    # Reverse shell
    "bash -i >&", "nc -e /bin/sh", "python -c 'import socket",
    "/dev/tcp/", "msfvenom", "metasploit",
    # Destructive
    "rm -rf /", "mkfs.", "dd if=/dev/zero",
    "chmod 777 /", ":(){ :|:& };:",  # Fork bomb
    # Suspicious network
    "wget.*-O-.*|.*sh", "curl.*|.*bash",
    "pip install.*--break-system-packages",
    "npm install -g.*--unsafe-perm",
]

# Skills directory locations (OpenClaw convention)
SKILL_DIRS = [
    Path.home() / ".openclaw" / "skills",
    Path.home() / ".openclaw" / "workspace" / "skills",
    Path.cwd() / "clawhub",
    Path.cwd() / ".clawhub",
]

# SHA-256 known good hashes (would be updated from ClawHub registry)
TRUSTED_SKILL_HASHES = {}  # {filename: sha256_hash}


# ── SHA-256 Verification ─────────────────────────────

def sha256_file(filepath: Path) -> str:
    """Compute SHA-256 hash of a file."""
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha.update(chunk)
    return sha.hexdigest()


def verify_skill_hashes(skill_dir: Path) -> List[Dict]:
    """Verify SHA-256 of all SKILL.md files against trusted registry."""
    results = []
    for skill_file in skill_dir.rglob("SKILL.md"):
        actual_hash = sha256_file(skill_file)
        relative = skill_file.relative_to(skill_dir)
        trusted = TRUSTED_SKILL_HASHES.get(str(relative))

        result = {
            "file": str(relative),
            "sha256": actual_hash,
            "trusted": trusted == actual_hash if trusted else None,
            "status": "✅ Verified" if trusted == actual_hash else "⚠️ Unknown (not in registry)" if trusted is None else "🚨 HASH MISMATCH — possible tampering!",
        }
        results.append(result)

        if trusted and trusted != actual_hash:
            print(f"[SECURITY] 🚨 CRITICAL: {relative} hash mismatch!")
            print(f"   Expected: {trusted[:16]}...")
            print(f"   Actual:   {actual_hash[:16]}...")

    return results


# ── Malicious Pattern Scanner ─────────────────────────

def scan_file_for_threats(filepath: Path) -> List[Dict]:
    """Scan a single file for malicious patterns. Returns list of findings."""
    findings = []
    try:
        content = filepath.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings

    for pattern in MALICIOUS_PATTERNS:
        import re
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            # Extract context (20 chars around match)
            for match in matches[:3]:  # Cap at 3 per pattern
                idx = content.find(match)
                start = max(0, idx - 20)
                end = min(len(content), idx + len(match) + 20)
                context = content[start:end].replace("\n", " ").strip()

                severity = "🔴 CRITICAL"
                if "xmrig" in match.lower() or "stratum" in match.lower():
                    severity = "🔴 CRITICAL — Crypto miner detected"
                elif "rm -rf" in match or "mkfs" in match:
                    severity = "🔴 CRITICAL — Destructive command"
                elif "telegram" in match.lower() and "send" in match.lower():
                    severity = "🟠 HIGH — Data exfiltration"
                elif "curl.*|.*bash" in match.lower() or "wget.*|.*sh" in match.lower():
                    severity = "🟠 HIGH — Remote code execution"
                else:
                    severity = "🟡 MEDIUM — Suspicious pattern"

                findings.append({
                    "file": str(filepath.name),
                    "pattern": pattern,
                    "match": match[:80],
                    "context": context[:120],
                    "severity": severity,
                })

    return findings


def scan_skills_for_threats(skill_dir: Path) -> List[Dict]:
    """Recursively scan all skill files for malicious patterns."""
    all_findings = []
    for skill_file in skill_dir.rglob("*"):
        if skill_file.suffix in [".md", ".py", ".sh", ".js", ".json", ".yaml", ".yml", ".txt"]:
            findings = scan_file_for_threats(skill_file)
            if findings:
                all_findings.extend(findings)
                print(f"[SECURITY] 🚨 {skill_file.name}: {len(findings)} threat(s) detected")
    return all_findings


# ── Docker Sandbox Validator ─────────────────────────

def check_docker_sandbox() -> Dict:
    """Validate Docker sandbox configuration for agent isolation."""
    result = {
        "docker_installed": False,
        "sandbox_configured": False,
        "security_opts": [],
        "read_only_rootfs": False,
        "no_new_privileges": False,
        "cap_drop_all": False,
        "network_mode": "unknown",
        "memory_limit": None,
        "cpu_limit": None,
        "recommendations": [],
    }

    # Check Docker installation
    try:
        subprocess.run(["docker", "--version"], capture_output=True, check=True, timeout=5)
        result["docker_installed"] = True
    except (subprocess.CalledProcessError, FileNotFoundError):
        result["recommendations"].append("❌ Docker not installed — install Docker for agent sandboxing")
        return result

    # Check running containers
    try:
        containers = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=5,
        )
        container_names = containers.stdout.strip().split("\n") if containers.stdout.strip() else []
        result["running_containers"] = container_names
    except Exception:
        container_names = []

    # Inspect each container for sandbox configuration
    for cname in container_names:
        try:
            inspect = subprocess.run(
                ["docker", "inspect", cname],
                capture_output=True, text=True, timeout=5,
            )
            if inspect.returncode == 0:
                data = json.loads(inspect.stdout)[0]
                host_config = data.get("HostConfig", {})
                # Security options
                security_opts = host_config.get("SecurityOpt", [])
                result["security_opts"] = security_opts

                if "no-new-privileges:true" in security_opts:
                    result["no_new_privileges"] = True

                # Read-only root filesystem
                result["read_only_rootfs"] = host_config.get("ReadonlyRootfs", False)

                # Capability drop
                cap_drop = host_config.get("CapDrop", [])
                result["cap_drop_all"] = "ALL" in cap_drop

                # Network
                result["network_mode"] = host_config.get("NetworkMode", "unknown")

                # Resource limits
                result["memory_limit"] = host_config.get("Memory", 0)
                result["cpu_limit"] = host_config.get("NanoCpus", 0) // 1_000_000_000 if host_config.get("NanoCpus") else None

                # Check if this is a properly sandboxed agent
                if (
                    result["no_new_privileges"]
                    and result["read_only_rootfs"]
                    and result["cap_drop_all"]
                ):
                    result["sandbox_configured"] = True

                break  # Check first container only; extend for multi-agent
        except Exception as e:
            result["recommendations"].append(f"⚠️  Could not inspect container {cname}: {e}")

    # Generate recommendations
    if not result["no_new_privileges"]:
        result["recommendations"].append("🔴 Add --security-opt=no-new-privileges:true to Docker run")
    if not result["read_only_rootfs"]:
        result["recommendations"].append("🔴 Add --read-only to Docker run (mount /tmp as tmpfs if needed)")
    if not result["cap_drop_all"]:
        result["recommendations"].append("🟠 Add --cap-drop=ALL to Docker run (add back only needed caps)")
    if result["network_mode"] == "host":
        result["recommendations"].append("🔴 Container uses --network=host — isolate to bridge network")
    if not result["sandbox_configured"]:
        result["recommendations"].append("⚠️  Full sandbox not detected — agent may have host access")

    return result


# ── Main Audit ────────────────────────────────────────

def run_full_audit() -> Dict:
    """Run full security audit: SHA-256 + threat scan + Docker sandbox."""
    report = {
        "audit_time": datetime.now(timezone.utc).isoformat(),
        "audit_version": "1.0.0",
        "sha256_verification": [],
        "threat_scan": {"total_findings": 0, "findings": []},
        "docker_sandbox": {},
        "overall_risk": "LOW",
        "recommendations": [],
    }

    # Find skill directories
    skill_dirs = [d for d in SKILL_DIRS if d.exists()]
    if not skill_dirs:
        report["recommendations"].append("ℹ️  No skill directories found — nothing to audit")
        return report

    print(f"[audit] Found {len(skill_dirs)} skill directories: {skill_dirs}")

    # SHA-256 verification
    for sd in skill_dirs:
        hash_results = verify_skill_hashes(sd)
        report["sha256_verification"].extend(hash_results)

    # Threat scan
    for sd in skill_dirs:
        threat_findings = scan_skills_for_threats(sd)
        report["threat_scan"]["findings"].extend(threat_findings)

    report["threat_scan"]["total_findings"] = len(report["threat_scan"]["findings"])

    # Docker sandbox
    report["docker_sandbox"] = check_docker_sandbox()
    report["recommendations"].extend(report["docker_sandbox"].get("recommendations", []))

    # Calculate overall risk
    hash_mismatches = [h for h in report["sha256_verification"] if "MISMATCH" in h.get("status", "")]
    if hash_mismatches:
        report["overall_risk"] = "🔴 CRITICAL"
        report["recommendations"].append(f"🚨 {len(hash_mismatches)} file(s) have SHA-256 mismatches — possible tampering!")
    elif report["threat_scan"]["total_findings"] > 0:
        criticals = [f for f in report["threat_scan"]["findings"] if "CRITICAL" in f.get("severity", "")]
        if criticals:
            report["overall_risk"] = "🔴 CRITICAL"
        else:
            report["overall_risk"] = "🟠 HIGH"
    elif not report["docker_sandbox"].get("sandbox_configured"):
        report["overall_risk"] = "🟡 MEDIUM"
        report["recommendations"].append("⚠️  Docker sandbox not fully configured — agents may lack isolation")
    else:
        report["overall_risk"] = "🟢 LOW"
        report["recommendations"].append("✅ All checks passed — agents are properly sandboxed")

    return report


# ── CLI ───────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Security Audit — ClawHub Skills + Docker Sandbox")
    parser.add_argument("--sha256-only", action="store_true", help="Only SHA-256 verification")
    parser.add_argument("--docker-only", action="store_true", help="Only Docker sandbox validation")
    parser.add_argument("--output", type=str, default=None, help="Save report to JSON file")
    args = parser.parse_args()

    if args.sha256_only:
        skill_dirs = [d for d in SKILL_DIRS if d.exists()]
        results = []
        for sd in skill_dirs:
            results.extend(verify_skill_hashes(sd))
        report = {"sha256_verification": results}
    elif args.docker_only:
        report = {"docker_sandbox": check_docker_sandbox()}
    else:
        report = run_full_audit()

    # Print summary
    print("\n" + "=" * 60)
    print("🔒 AGENT SECURITY AUDIT REPORT")
    print("=" * 60)
    
    if "overall_risk" in report:
        print(f"Overall Risk: {report['overall_risk']}")
    
    if "threat_scan" in report:
        print(f"Threats Found: {report['threat_scan']['total_findings']}")
        for finding in report['threat_scan']['findings'][:5]:
            print(f"  {finding['severity']} | {finding['file']}: {finding['match'][:60]}")
        if report['threat_scan']['total_findings'] > 5:
            print(f"  ... and {report['threat_scan']['total_findings'] - 5} more")

    if "docker_sandbox" in report:
        ds = report["docker_sandbox"]
        print(f"Docker: {'✅ Installed' if ds.get('docker_installed') else '❌ Not installed'}")
        print(f"Sandbox: {'✅ Active' if ds.get('sandbox_configured') else '❌ Not configured'}")
        print(f"Read-only: {'✅' if ds.get('read_only_rootfs') else '❌'}")
        print(f"No-new-privs: {'✅' if ds.get('no_new_privileges') else '❌'}")
        print(f"Cap-drop=ALL: {'✅' if ds.get('cap_drop_all') else '❌'}")
        print(f"Network: {ds.get('network_mode', 'unknown')}")

    if "recommendations" in report and report["recommendations"]:
        print("\n📋 Recommendations:")
        for rec in report["recommendations"]:
            print(f"  {rec}")

    print("=" * 60)

    # Save to file if requested
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n📁 Report saved to: {args.output}")

    # Exit code: 1 if any threats found, 0 otherwise
    if "threat_scan" in report and report["threat_scan"]["total_findings"] > 0:
        sys.exit(1)
    sys.exit(0)