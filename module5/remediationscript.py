
import logging
import time
from collections import Counter

# ============================================================
# PROJECT SYNAPSE - MOCK API INTEGRATION
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

KEY_ID = "Global-Service-Account"
WAIT_SECONDS = 30 * 60
POLL_INTERVAL = 30
UNKNOWN_EXTERNAL_LIMIT = 5

EXPECTED_INTERNAL_USER_AGENTS = {
    "App-Server-v2"
}


# ------------------------------------------------------------
# A. IDENTITY API - MOCK FUNCTIONS
# ------------------------------------------------------------

def Get_Active_Sessions(key_id):
    """
    Mock response. In production, retrieve this data
    from the Identity API.
    """
    return [
        {
            "session_id": "S001",
            "ip_address": "10.0.0.15",
            "user_agent": "App-Server-v2",
            "app_name": "Payment-Service"
        },
        {
            "session_id": "S002",
            "ip_address": "203.0.113.25",
            "user_agent": "Python-Requests/2.31",
            "app_name": "Reporting-Service"
        },
        {
            "session_id": "S003",
            "ip_address": "10.0.0.20",
            "user_agent": "Python-Requests/2.31",
            "app_name": "Customer-Portal"
        }
    ]


def Rotate_Key(key_id):
    """
    Mock high-impact operation.
    Assumed to invalidate the old key immediately.
    """
    # Replace with the actual mock API call.
    return {
        "status": "success",
        "new_key_id": "Global-Service-Account-v2"
    }


def Tag_Session_As_Malicious(session_id):
    logging.warning(
        "Session %s routed to honey-token environment",
        session_id
    )
    # Replace with Identity API call.


# ------------------------------------------------------------
# B. ASSET INVENTORY API - MOCK FUNCTIONS
# ------------------------------------------------------------

def Check_IP_Context(ip_address):
    """
    Mock IP classification.
    Replace with Asset Inventory API call.
    """
    internal_ips = {"10.0.0.15", "10.0.0.20"}
    partner_ips = {"198.51.100.10"}

    if ip_address in internal_ips:
        return "Known_Internal"

    if ip_address in partner_ips:
        return "Known_Partner"

    return "Unknown_External"


def Get_App_Criticality(app_name):
    """
    Mock application criticality.
    Replace with Asset Inventory API call.
    """
    criticality = {
        "Payment-Service": "P1",
        "Customer-Portal": "P1",
        "Reporting-Service": "P4"
    }

    return criticality.get(app_name, "P3")


# ------------------------------------------------------------
# C. NOTIFICATION API - MOCK FUNCTIONS
# ------------------------------------------------------------

def Prompt_App_Owner(app_name):
    logging.info(
        "Rotation approval request sent to owner of %s",
        app_name
    )
    # Replace with Notification API call.
    # Expected behaviour: send Slack message with Rotate Now button.


def Alert_CISO(message):
    logging.critical("CISO ALERT: %s", message)
    # Integration placeholder: send the CISO alert.


# ------------------------------------------------------------
# D. ADDITIONAL REQUIRED INTEGRATION PLACEHOLDERS
# ------------------------------------------------------------

def Freeze_Account(key_id):
    """
    The assignment requires account freezing, but no
    Freeze_Account endpoint was supplied.
    """
    logging.critical("FREEZE REQUESTED for %s", key_id)
    # Implement using the organisation's identity-control API.


def Check_App_Migration_Status(app_name):
    """
    Placeholder for the application owner's success signal.
    True means the replacement credential has been tested.
    """
    # Replace with a real callback, webhook, or status API.
    return False


def Request_P2_P3_Approval(app_name):
    """
    P2/P3 approval mechanism is not specified in the task.
    """
    logging.info("Human approval required for %s", app_name)
    return False


def Reconcile_Rotation_State(key_id):
    """
    Required after an HTTP 500 because the rotation may
    have succeeded even though the response was lost.

    Replace with a read-only API call that checks:
    - whether a replacement key exists;
    - whether the old key is still valid;
    - whether applications have migrated.
    """
    return "UNKNOWN"


# ============================================================
# PHASE 1 - SESSION TRIAGE
# ============================================================

def Triage_Sessions(sessions):

    unknown_external_sources = set()
    flagged_for_review = []
    application_sessions = {}

    for session in sessions:

        session_id = session["session_id"]
        ip_address = session["ip_address"]
        user_agent = session["user_agent"]
        app_name = session["app_name"]

        context = Check_IP_Context(ip_address)

        application_sessions.setdefault(app_name, []).append(
            session
        )

        logging.info(
            "Session %s: IP=%s Context=%s App=%s",
            session_id,
            ip_address,
            context,
            app_name
        )

        # Unknown external IP: immediate containment.
        if context == "Unknown_External":

            unknown_external_sources.add(ip_address)

            Tag_Session_As_Malicious(session_id)

        # Internal IP with suspicious User-Agent.
        elif context == "Known_Internal":

            if user_agent not in EXPECTED_INTERNAL_USER_AGENTS:

                flagged_for_review.append(session)

                logging.warning(
                    "Human review required: session %s "
                    "has suspicious User-Agent %s",
                    session_id,
                    user_agent
                )

        # Known partners are not automatically trusted.
        elif context == "Known_Partner":

            logging.info(
                "Partner session %s requires partner "
                "identity and User-Agent validation",
                session_id
            )

    return (
        unknown_external_sources,
        flagged_for_review,
        application_sessions
    )


# ============================================================
# PHASE 2 - SAFETY BACK-OFF
# ============================================================

def Apply_Safety_Backoff(unknown_external_sources):

    count = len(unknown_external_sources)

    logging.info(
        "Unknown external source count: %d",
        count
    )

    if count > UNKNOWN_EXTERNAL_LIMIT:

        Freeze_Account(KEY_ID)

        Alert_CISO(
            f"{count} unknown external IP sources detected "
            f"using {KEY_ID}. Account freeze requested."
        )

        return True

    return False


# ============================================================
# PHASE 3 - P1 OWNER APPROVAL AND MIGRATION CHECK
# ============================================================

def Wait_For_P1_Success(app_name):

    Prompt_App_Owner(app_name)

    deadline = time.monotonic() + WAIT_SECONDS

    while time.monotonic() < deadline:

        if Check_App_Migration_Status(app_name):

            logging.info(
                "Successful migration confirmed for %s",
                app_name
            )

            return True

        time.sleep(POLL_INTERVAL)

    logging.error(
        "30-minute migration window expired for %s",
        app_name
    )

    return False


# ============================================================
# PHASE 4 - CLASSIFY APPLICATIONS FOR MIGRATION
# ============================================================

def Assess_Applications(application_sessions):

    p1_ready = []
    p4_eligible = []
    approval_required = []
    migration_failures = []

    for app_name in application_sessions:

        criticality = Get_App_Criticality(app_name)

        logging.info(
            "Application %s has criticality %s",
            app_name,
            criticality
        )

        if criticality == "P1":

            if Wait_For_P1_Success(app_name):
                p1_ready.append(app_name)
            else:
                migration_failures.append(app_name)

        elif criticality == "P4":

            p4_eligible.append(app_name)

        else:
            if Request_P2_P3_Approval(app_name):
                approval_required.append(app_name)
            else:
                migration_failures.append(app_name)

    return (
        p1_ready,
        p4_eligible,
        approval_required,
        migration_failures
    )


# ============================================================
# PHASE 5 - GLOBAL ROTATION SAFETY GATE
# ============================================================

def Perform_Global_Rotation(
    all_apps,
    p1_ready,
    p4_eligible,
    approval_required,
    migration_failures
):

    # The key is shared by all applications.
    # Therefore, every consumer must be ready before
    # the old global key is invalidated.

    ready_apps = set(p1_ready + p4_eligible + approval_required)
    all_app_names = set(all_apps)

    if migration_failures:
        logging.error(
            "Rotation blocked: one or more applications "
            "have not confirmed migration."
        )
        return False

    if ready_apps != all_app_names:
        logging.error(
            "Rotation blocked: not all 40 consumers "
            "are verified as ready."
        )
        return False

    try:

        result = Rotate_Key(KEY_ID)

        if result.get("status") == "success":

            logging.info(
                "Global key rotation successful. New key ID: %s",
                result.get("new_key_id")
            )

            return True

        logging.error("Rotation returned an unsuccessful response.")

    except Exception as error:

        logging.error(
            "Rotation API error: %s",
            error
        )

    # HTTP 500 or an uncertain result:
    # Do not blindly retry or reactivate the compromised key.
    state = Reconcile_Rotation_State(KEY_ID)

    if state == "NEW_KEY_ACTIVE":

        logging.warning(
            "Rotation appears to have succeeded despite API error. "
            "Verify application connectivity."
        )

    elif state == "OLD_KEY_ACTIVE":

        logging.critical(
            "Old compromised key remains active. "
            "Maintain containment and escalate."
        )

    else:

        logging.critical(
            "Rotation state is unknown. "
            "Do not issue another destructive rotation blindly."
        )

    Alert_CISO(
        "Global key rotation returned an error or uncertain state. "
        "Reconciliation and incident-response action required."
    )

    return False


# ============================================================
# MAIN ORCHESTRATION
# ============================================================

def main():

    logging.info("PROJECT SYNAPSE STARTED")

    sessions = Get_Active_Sessions(KEY_ID)

    (
        unknown_external_sources,
        flagged_for_review,
        application_sessions
    ) = Triage_Sessions(sessions)

    # Stop the playbook if the external-source threshold is exceeded.
    if Apply_Safety_Backoff(unknown_external_sources):
        logging.critical(
            "Automation stopped because the safety threshold "
            "was exceeded."
        )
        return

    if flagged_for_review:

        logging.warning(
            "%d sessions require human review.",
            len(flagged_for_review)
        )

    # In production, obtain the complete 40-app consumer list
    # from the asset inventory, not only apps with active sessions.
    all_apps = list(application_sessions.keys())

    (
        p1_ready,
        p4_eligible,
        approval_required,
        migration_failures
    ) = Assess_Applications(application_sessions)

    Perform_Global_Rotation(
        all_apps,
        p1_ready,
        p4_eligible,
        approval_required,
        migration_failures
    )

    logging.info("PROJECT SYNAPSE FINISHED")


if __name__ == "__main__":
    main()

