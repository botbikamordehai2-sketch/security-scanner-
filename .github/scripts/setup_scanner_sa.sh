#!/usr/bin/env bash
# setup_scanner_sa.sh — Create the minimal GCP Service Account for the security scanner.
#
# Principle of least privilege: creates a Custom Role with ONLY the permissions
# needed for read-only scanning. No write, delete, or admin permissions.
#
# Usage:
#   export PROJECT_ID=my-project-123
#   export BILLING_ACCOUNT_ID=012345-ABCDEF-789012
#   bash setup_scanner_sa.sh
#
# Prerequisites: gcloud CLI, authenticated as Owner or IAM Admin.

set -euo pipefail

PROJECT_ID="${PROJECT_ID:?Set PROJECT_ID env var}"
BILLING_ACCOUNT_ID="${BILLING_ACCOUNT_ID:?Set BILLING_ACCOUNT_ID env var}"

SA_NAME="security-scanner"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"
ROLE_ID="securityScannerReader"
ROLE_TITLE="Security Scanner Reader"

echo "==> Project:         $PROJECT_ID"
echo "==> Service Account: $SA_EMAIL"
echo "==> Custom Role:     $ROLE_ID"
echo ""

# ── Step 1: Create Custom Role ────────────────────────
# Each permission mapped to the scan function that needs it:
#
#   compute.firewalls.list          → check_firewall_public_ssh
#   storage.buckets.list            → scan_storage_bucket (list)
#   storage.buckets.getIamPolicy    → check_storage_public_iam
#   resourcemanager.projects.getIamPolicy → check_iam_overpermissive_sa
#   cloudsql.instances.list         → check_sql_public_ip / check_sql_no_backup
#   container.clusters.list         → check_gke_*
#   billing.resourceAssociations.list → check_billing_enabled (project-level)

echo "==> Creating custom role '$ROLE_ID'..."
gcloud iam roles create "$ROLE_ID" \
  --project="$PROJECT_ID" \
  --title="$ROLE_TITLE" \
  --description="Read-only permissions for the security scanner agent. No write or admin access." \
  --permissions="\
compute.firewalls.list,\
storage.buckets.list,\
storage.buckets.getIamPolicy,\
resourcemanager.projects.getIamPolicy,\
cloudsql.instances.list,\
container.clusters.list,\
billing.resourceAssociations.list" \
  --stage=GA 2>/dev/null || \
gcloud iam roles update "$ROLE_ID" \
  --project="$PROJECT_ID" \
  --permissions="\
compute.firewalls.list,\
storage.buckets.list,\
storage.buckets.getIamPolicy,\
resourcemanager.projects.getIamPolicy,\
cloudsql.instances.list,\
container.clusters.list,\
billing.resourceAssociations.list"

echo "    ✅ Custom role ready"

# ── Step 2: Create Service Account ───────────────────
echo "==> Creating service account '$SA_NAME'..."
gcloud iam service-accounts create "$SA_NAME" \
  --project="$PROJECT_ID" \
  --display-name="Security Scanner Agent" \
  --description="Runs read-only GCP security scans. Minimal permissions only." \
  2>/dev/null || echo "    ℹ️  Service account already exists — skipping create"

echo "    ✅ Service account ready"

# ── Step 3: Bind Custom Role to SA (project level) ───
echo "==> Binding custom role to service account..."
gcloud projects add-iam-policy-binding "$PROJECT_ID" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="projects/${PROJECT_ID}/roles/${ROLE_ID}" \
  --condition=None \
  --quiet

echo "    ✅ IAM binding set"

# ── Step 4: Grant billing view at billing account level ──
# billing.resourceAssociations.list alone is insufficient for check_budget_alerts.
# Need billing.budgets.list at billing account level (separate from project).
echo "==> Granting billing account viewer role..."
gcloud billing accounts add-iam-policy-binding "$BILLING_ACCOUNT_ID" \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/billing.viewer" \
  --quiet

echo "    ✅ Billing viewer granted"

# ── Step 5: Export key for GitHub Actions secret ─────
KEY_FILE="scanner-sa-key.json"
echo "==> Exporting SA key to $KEY_FILE..."
gcloud iam service-accounts keys create "$KEY_FILE" \
  --iam-account="$SA_EMAIL" \
  --project="$PROJECT_ID"

echo ""
echo "============================================================"
echo "  Setup complete. Next steps:"
echo "============================================================"
echo ""
echo "  1. Add GitHub Actions secret GCP_SA_KEY:"
echo "     gh secret set GCP_SA_KEY < $KEY_FILE"
echo ""
echo "  2. Add GitHub Actions secret GCP_BILLING_ACCOUNT:"
echo "     gh secret set GCP_BILLING_ACCOUNT --body '$BILLING_ACCOUNT_ID'"
echo ""
echo "  3. Delete the local key file (it's now in GitHub):"
echo "     rm $KEY_FILE"
echo ""
echo "  ⚠️  Never commit $KEY_FILE to git."
echo "============================================================"
