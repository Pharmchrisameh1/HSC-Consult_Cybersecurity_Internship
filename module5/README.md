**Module 5 Task: Project Synapse**

Role: Senior Security Automation Engineer

Objective: Architect and Code a Context-Aware Remediation Playbook using Mock APIs.

1. The Challenge
An API Key for our Global-Service-Account was found in a public GitHub repo.

The Problem: This key is used by 40 production apps. If you revoke it immediately, the company stops functioning.

The Goal: Build an automation that identifies Malicious vs. Legitimate usage in real-time and performs a Phased Rotation.

2. The API Specification (Your Toolkit)
You need to write a script that interacts with these three (mock) API endpoints:
A. Endpoint: Identity_API
- Get_Active_Sessions(key_id) : Returns list of IPs and UserAgents using the key.
- Rotate_Key(key_id) : Generates a new key and invalidates the old one (WARNING: High Impact).
- Tag_Session_As_Malicious(session_id) : Routes specific traffic to a Honey-Token environment.
B. Endpoint: Asset_Inventory_API
- Check_IP_Context(ip_address) : Returns Known_Internal, Known_Partner, or Unknown_External.
- Get_App_Criticality(app_name) : Returns P1 (Critical) to P4 (Low).
C. Endpoint: Notification_API
- Prompt_App_Owner(app_name) : Sends a Slack message with a Rotate Now button.

3. The Engineering Deliverables
You must submit a Python-based Orchestration Script (or detailed Pseudo-code) that implements the following sophisticated logic:

The Triage Logic: Your script must loop through all active sessions.

If an IP is Unknown_External, it must be tagged as Malicious immediately.

If an IP is Known_Internal but the UserAgent is suspicious (e.g., Python-Requests instead of App-Server-v2), it must flag for human review.

The Graceful Rotation:

For P1 (Critical) apps, the script must not rotate the key. It must trigger Prompt_App_Owner and wait 30 minutes for a Success signal.

For P4 (Low) apps, the script should Rotate_Key automatically.

The Safety Back-off:

Write a Throttling mechanism: If the script detects more than 5 Unknown_External sources at once, it must Freeze the entire account and alert the CISO.

Error Handling:

What happens if the Identity_API returns a 500 Internal Server Error during the rotation? Your code must handle the Rollback logic.

4. Submission Requirement
Your report must include:
- A Logic Flowchart (using Mermaid or similar).
- The Remediation Script (Python/PowerShell) using the mock functions provided above.
- A Risk Assessment: Explain the Residual Risk of leaving the key active for P1 apps during the rotation period.

**Steps**


## Logic Flowchart

The following flow illustrates the automated session investigation, threat containment, application assessment, and global API key rotation process.

```text
START
  ↓
Retrieve Active Sessions using the exposed API Key
  ↓
Loop Through Each Active Session
  ↓
Check IP Context using Asset_Inventory_API
  ↓
Is the IP Address Known?
  │
  ├── UNKNOWN_EXTERNAL
  │      ↓
  │   Tag Session as Malicious
  │      ↓
  │   Count Unknown External IP Addresses
  │
  ├── KNOWN_INTERNAL
  │      ↓
  │   Inspect User-Agent
  │      ↓
  │   Is the User-Agent Suspicious?
  │      │
  │      ├── YES → Flag Session for Human Review
  │      │
  │      └── NO  → Mark Session as Legitimate
  │
  └── KNOWN_PARTNER
         ↓
      Validate Partner Session
         ↓
         Continue Session Assessment

  ↓
Count Unique Unknown External IP Addresses
  ↓
Are There More Than 5 Unknown External IPs?
  │
  ├── YES
  │      ↓
  │   Freeze Global Service Account
  │      ↓
  │   Alert CISO
  │      ↓
  │     STOP
  │
  └── NO
         ↓
      Retrieve Application Criticality
         ↓
      Assess Application Priority
         │
         ├── P1 (CRITICAL)
         │      ↓
         │   Prompt Application Owner
         │      ↓
         │   Wait Up to 30 Minutes for Success Signal
         │      ↓
         │   Was Migration Successful?
         │      │
         │      ├── NO → Escalate for Human Intervention
         │      │
         │      └── YES → Mark Application as Ready
         │
         ├── P4 (LOW)
         │      ↓
         │   Mark Application for Automatic Migration
         │
         └── P2 / P3
                ↓
             Request Human Approval

  ↓
Check Migration Status of All 40 Applications
  ↓
Have All Applications Migrated and Been Verified?
  │
  ├── NO
  │      ↓
  │   Keep Existing Key Temporarily
  │      ↓
  │   Continue Monitoring and Escalate
  │
  └── YES
         ↓
      Initiate Global API Key Rotation
         ↓
      Was Rotation Successful?
         │
         ├── YES
         │      ↓
         │   Verify New API Key
         │      ↓
         │   Confirm Application Connectivity
         │      ↓
         │   Revoke Old Compromised Key
         │      ↓
         │     END
         │
         └── NO (HTTP 500 ERROR)
                ↓
             Reconcile Rotation State
                ↓
             Is Rotation State Known?
                │
                ├── YES → Verify Key Validity and Application Status
                │
                └── NO  → Stop Further Rotation Attempts
                ↓
             Alert CISO and Investigate
                ↓
               END
```

**Risk assessment**

Residual risk of keeping the key active for P1 applications
The decision not to immediately revoke the compromised key for P1 applications reduces the risk of disrupting essential production services. However, it creates a period during which an attacker who possesses the exposed key may continue to use it.

   **Risk	                                                     Potential impact	                                               Mitigation**

Risk of continued unauthorized access  
The potential impact is that an attacker could continue accessing services through the exposed key	
Monitor active sessions and contain external sources to mitigate it


Data exposure risk	     
Unauthorized users may access sensitive application information which could have a potential impact        
Review API access logs, permissions, and unusual data requests to mitigate risk.


Risk of service impersonation	
Potential impact is that an attacker may impersonate legitimate applications	         
It can be mitigated by validating IP context, User-Agent, and application identity.


Risk of delayed credential rotation	  
Compromised key remains usable as owners migrate their apps and this could have an impact	 
Set a strict 30-minute migration window and escalate missed deadlines to mitigate the risk.


Production disruption risk	 
Immediate global rotation could break all 40 apps as a result of this	     
It can be mitigated by the use of a staged migration process and verify app readiness before revocation.


**Recommended risk-reduction measures**

1. Apply least-privilege permissions to the service account.
2. Monitor API requests continuously during the migration period.
3. Restrict the compromised key's access where the identity platform supports safe permission reduction.
4. Require application owners to confirm successful migration within 30 minutes.
5. Escalate P1 applications that fail to migrate within the allocated period.
6. Maintain a complete audit trail of session tagging, approvals, and rotation events.
7. After migration, revoke the exposed key and verify that no application continues using it.
