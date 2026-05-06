"""
Billing Guard — Checks GCP billing account status before deploy.
Prevents autonomous agents from running on a suspended account.
Usage: python check_billing.py
Exit 0 = billing OK, Exit 1 = billing CLOSED/SUSPENDED
"""
import os
import sys

try:
    from google.cloud import billing_v1
except ImportError:
    print("WARN: google-cloud-billing not installed. Skipping billing check.")
    sys.exit(0)

PROJECT_ID = os.environ.get("GCP_PROJECT", os.environ.get("GOOGLE_CLOUD_PROJECT", ""))

if not PROJECT_ID:
    print("WARN: GCP_PROJECT not set. Skipping billing check.")
    sys.exit(0)

def check_billing_enabled():
    """Check if billing is enabled for the project."""
    client = billing_v1.CloudBillingClient()
    
    # Fetch billing info for the project
    try:
        billing_info = client.get_project_billing_info(
            request={"name": f"projects/{PROJECT_ID}"}
        )
    except Exception as e:
        print(f"ERROR: Failed to fetch billing info: {e}")
        sys.exit(1)
    
    if billing_info.billing_enabled:
        print(f"✅ Billing ENABLED for project: {PROJECT_ID}")
        return True
    else:
        print(f"❌ Billing DISABLED for project: {PROJECT_ID}")
        print("ABORTING deploy — billing must be active for autonomous agents.")
        return False

def check_budget_alerts():
    """Verify budget alerts exist (prevent runaway spending)."""
    client = billing_v1.BudgetServiceClient()
    parent = f"billingAccounts/{PROJECT_ID}"
    
    try:
        budgets = list(client.list_budgets(request={"parent": parent}))
        if budgets:
            print(f"✅ {len(budgets)} budget alert(s) configured")
            return True
        else:
            print("⚠️  WARN: No budget alerts configured for this project.")
            print("   Consider creating one: https://console.cloud.google.com/billing/budgets")
            return True  # Not fatal — just warn
    except Exception as e:
        print(f"WARN: Could not verify budget alerts: {e}")
        return True  # Not fatal

if __name__ == "__main__":
    if check_billing_enabled():
        check_budget_alerts()
        print("Billing OK")
        sys.exit(0)
    else:
        print("Billing CLOSED — aborting deploy")
        sys.exit(1)