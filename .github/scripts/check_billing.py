"""
Billing Guard — Checks GCP billing account status before deploy.
Prevents autonomous agents from running on a suspended account.
Usage: python check_billing.py
Exit 0 = billing OK, Exit 1 = billing CLOSED/SUSPENDED

Required env vars:
  GCP_PROJECT            — project ID (e.g. my-project-123)
  GCP_BILLING_ACCOUNT    — billing account ID (e.g. 012345-ABCDEF-789012)
"""
import os
import re
import sys

try:
    from google.cloud import billing_v1
    from google.api_core import exceptions as gcp_exceptions
except ImportError:
    print("WARN: google-cloud-billing not installed. Skipping billing check.")
    sys.exit(0)

PROJECT_ID = os.environ.get("GCP_PROJECT", os.environ.get("GOOGLE_CLOUD_PROJECT", ""))
BILLING_ACCOUNT_ID = os.environ.get("GCP_BILLING_ACCOUNT", "")

BILLING_ACCOUNT_PATTERN = re.compile(r"^[0-9A-Z]{6}-[0-9A-Z]{6}-[0-9A-Z]{6}$")

if not PROJECT_ID:
    print("WARN: GCP_PROJECT not set. Skipping billing check.")
    sys.exit(0)


def validate_billing_account_id(account_id: str) -> bool:
    return bool(BILLING_ACCOUNT_PATTERN.match(account_id))


def check_billing_enabled():
    client = billing_v1.CloudBillingClient()
    try:
        billing_info = client.get_project_billing_info(
            request={"name": f"projects/{PROJECT_ID}"}
        )
    except gcp_exceptions.PermissionDenied:
        print("ERROR: Service account lacks billing.resourceAssociations.list permission.")
        sys.exit(1)
    except gcp_exceptions.NotFound:
        print(f"ERROR: Project '{PROJECT_ID}' not found in GCP.")
        sys.exit(1)
    except gcp_exceptions.Unauthenticated:
        print("ERROR: GCP credentials missing or invalid. Check GOOGLE_APPLICATION_CREDENTIALS.")
        sys.exit(1)

    if billing_info.billing_enabled:
        print(f"✅ Billing ENABLED for project: {PROJECT_ID}")
        return True
    else:
        print(f"❌ Billing DISABLED for project: {PROJECT_ID}")
        print("ABORTING deploy — billing must be active for autonomous agents.")
        return False


def check_budget_alerts():
    if not BILLING_ACCOUNT_ID:
        print("WARN: GCP_BILLING_ACCOUNT not set. Skipping budget alert check.")
        return True

    if not validate_billing_account_id(BILLING_ACCOUNT_ID):
        print(f"ERROR: GCP_BILLING_ACCOUNT format invalid: '{BILLING_ACCOUNT_ID}'")
        print("       Expected format: XXXXXX-XXXXXX-XXXXXX (e.g. 012345-ABCDEF-789012)")
        sys.exit(1)

    client = billing_v1.BudgetServiceClient()
    parent = f"billingAccounts/{BILLING_ACCOUNT_ID}"

    try:
        budgets = list(client.list_budgets(request={"parent": parent}))
        if budgets:
            print(f"✅ {len(budgets)} budget alert(s) configured")
        else:
            print("⚠️  WARN: No budget alerts configured.")
            print("   Consider creating one: https://console.cloud.google.com/billing/budgets")
    except gcp_exceptions.PermissionDenied:
        print("WARN: Service account lacks billing.budgets.list permission. Skipping budget check.")
    except gcp_exceptions.NotFound:
        print(f"WARN: Billing account '{BILLING_ACCOUNT_ID}' not found.")
    except gcp_exceptions.GoogleAPICallError as e:
        print(f"WARN: Unexpected API error during budget check: {e}")

    return True


if __name__ == "__main__":
    if check_billing_enabled():
        check_budget_alerts()
        print("Billing OK")
        sys.exit(0)
    else:
        print("Billing CLOSED — aborting deploy")
        sys.exit(1)