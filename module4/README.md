**TASK**

Malware Analysis & Threat Intelligence Investigation

SCENARIO

You are part of a Cyber Threat Intelligence (CTI) team investigating a potential malware
resurgence Your mission is to identify the malicious hash, analyze its threat landscape, and
develop a detection mechanism to help your organization and others prevent future attacks.
HASH –
SHA256: 1adc29f30b30e301acefe1b46bbbd7a4f3a76c3708ab842199e95f8f5f053244

● Section 1 - Extract key details from VirusTotal, such as:
○ Number of detection engines that flagged it
○ File type
○ Detection names
○ First seen and last seen dates
• Identify:
o File name & original submission source (if available)
o File type and architecture
o Cryptographic hashes (MD5/SHA1/SHA256)
• Examine:
o Metadata & version info
o Possible spoofed company/product info
o Signs of masquerading as legitimate software
• Extract static network indicators:
o Domains
o IPs
o URLs
• Look for:
o Potential registry or persistence references visible statically

Section 2 — Cloud Sandbox Behavioral Intelligence (ANY.RUN)
Register here: https://any.run
Submit Hash here: https://app.any.run/submissions/
Tasks
• Identify:
o Malware family (if sandbox or engines associate one)
o Confidence level in classification
• Summarize sandbox behavioral findings:
o Key process behavior
o Persistence attempts (if reported)
o Privilege escalation / evasion attempts
• Network behavior:
o Connections attempted
o Protocols used
o Suspicious domains or IPs contacted
• Payloads / Observed Actions:
o Files created or modified
o Commands executed

• Inference Question
o Based on static characteristics, what type of malware might this be? (infostealer,
trojan, ransomware, dropper, etc.)
o What lure/social engineering strategy is likely being used?
o As a Tier 1 analyst, how would you first identify the attack before escalating.


**Steps**


# Module 4: Malware Analysis

## Overview

This module focused on malware analysis using **VirusTotal** and **ANY.RUN** to investigate the suspicious executable `izup.exe`. The task involved reviewing file reputation, examining sandbox behaviour, identifying network indicators, documenting suspicious activities, and organizing Indicators of Compromise (IOCs).

## Tools Used

- **VirusTotal:** For file reputation checks, antivirus detection results, file hashes, and malware classification.
- **ANY.RUN:** For sandbox-based behavioural analysis, process monitoring, network activity inspection, and threat identification.
- **Linux/WSL terminal:** For creating directories and organizing IOC files.

## Procedures Carried Out

### 1. File Reputation Analysis Using VirusTotal

The SHA-256 hash of `izup.exe` was used to locate and review the sample on VirusTotal.

The following activities were carried out:

- Reviewed the antivirus detection ratio.
- Examined the malware names and classifications assigned by security vendors.
- Recorded the available file details and hash values.
- Reviewed the file tags for possible behavioural characteristics.
- Documented the findings for inclusion in the malware-analysis report.

VirusTotal reported that **59 out of 70 security engines** flagged the file as malicious. The sample was associated with Trojan and Agent Tesla-related classifications.

VirusTotal results were treated as threat-intelligence evidence rather than independent proof of every behaviour attributed to the sample.

### 2. Sandbox Analysis Using ANY.RUN

The executable was examined using ANY.RUN's interactive malware-analysis sandbox.

The analysis was conducted in a Windows 10 64-bit environment, with a reported analysis duration of approximately 78 seconds.

The following procedures were carried out:

- Reviewed the sandbox's malware classification and YARA detection results.
- Inspected the process tree to identify processes associated with the sample.
- Examined observed network connections and DNS requests.
- Reviewed HTTP requests and responses.
- Inspected network threat alerts generated during execution.
- Recorded suspicious activities and relevant indicators for further investigation.

The sandbox associated the sample with Agent Tesla and information-stealing malware classifications.

### 3. Process and Persistence Investigation

The process tree was examined to identify suspicious child processes and possible persistence-related activities.

Particular attention was given to the appearance of `schtasks.exe` and the command associated with a scheduled task:

`/Create /TN "Updates\fAjLxt" /XML "C:\Users\admin\AppData\Local\Temp\tmp23CF.tmp"`

This command was documented because it indicates an attempt to create a scheduled task. However, the observed command alone does not confirm that the task was successfully created or that persistence was established.

### 4. Network Activity Investigation

The network activity recorded by ANY.RUN was reviewed to identify external communication associated with the sample.

The investigation included:

- Reviewing the HTTP GET request to `http://ip-api.com/line/?fields=hosting`.
- Recording the observed response status of HTTP 200 OK.
- Identifying the associated domain and IP address.
- Examining the connection to `us2.smtp.mailhostbox.com` over port 587.
- Reviewing DNS requests and network threat alerts.
- Distinguishing sample-attributed connections from events associated with Windows system processes.

The SMTP-related connection was documented as suspicious and requiring further investigation. The available evidence does not independently establish that emails were sent or that data was successfully exfiltrated.

### 5. IOC Extraction and Documentation

Relevant indicators were collected from the available VirusTotal and ANY.RUN results.

The indicators included:

- SHA-256 and MD5 file hashes.
- Network domains.
- IP addresses.
- Observed URLs.
- Network activity associated with the sample.

The `iocs` directory was used to organize the collected indicators into separate files for easier review and future threat-hunting activities.

The intended file organization was:

```text
iocs/
├── hashes.txt
├── domains.txt
├── ips.txt
├── urls.txt
├── network_iocs.csv
└── iocs.md
```

The indicators were documented with their available context to distinguish directly observed evidence from conclusions requiring further validation.

### 6. Malware Analysis Report Preparation

The findings from VirusTotal and ANY.RUN were consolidated into the Module 4 malware-analysis report.

The report documented:

- Sample identification and file hashes.
- Antivirus detection results.
- Malware classifications.
- Suspicious process activity.
- Scheduled-task creation attempt.
- Network connections and observed HTTP requests.
- Relevant indicators of compromise.
- Limitations of the available evidence.
- Recommended investigation and defensive actions.

### 7. Repository Documentation

The Module 4 documentation was organized within the cybersecurity internship repository.

The README provides an overview of the procedures performed, the tools used, and the evidence collected. Supporting reports and IOC files are maintained separately to keep the documentation organized.

## Key Findings

1. VirusTotal reported **59/70 detections** for `izup.exe`.
2. VirusTotal and ANY.RUN results associated the sample with Agent Tesla-related malware classifications.
3. The sandbox recorded suspicious process activity involving `schtasks.exe`.
4. Network activity included a request to `ip-api.com` and a connection to an SMTP-related host.
5. Relevant hashes and network indicators were documented for further investigation.

## Conclusion

Module 4 provided practical experience in malware investigation using file-reputation intelligence and sandbox-based behavioural analysis. The procedures helped identify suspicious process activity, examine network communications, extract indicators of compromise, and document findings in a structured report.

The results support treating `izup.exe` as malicious. Any conclusions about successful persistence, credential theft, or data exfiltration should be confirmed with additional evidence.

**Safety note:** Suspicious executables should only be investigated in an authorized, isolated analysis environment and should not be executed on a personal or production computer.

