Module 2 Task: Endpoint Defense &amp;
Memory Analysis

Role: Senior SOC Tier 2 Analyst

Objective: Analyze forensic artifacts to identify an active compromise.

1. Incident Overview

A workstation in the Finance department triggered a generic Suspicious Network Connection
alert. The local antivirus did not detect any malicious files on the disk. A memory dump was
captured, and the following Volatility reports have been provided for your analysis:

1. pstree_output.txt (Process Tree Analysis)

2. malfind_results.txt (Memory Injection/In-memory artifacts)

3. netscan_results.txt (Network Connection artifacts)

2. Your Mission

You must analyze the provided raw data to reconstruct the attack. You are expected to find the
Signal in the Noise. Several legitimate system processes are running. Your job is to identify
which one is not what it seems.
Recommended Analysis Tools
To perform this analysis efficiently, you should use tools that allow for deep searching and side-
by-side comparison of data:

● Advanced Text Editors: VS Code (use Split View to compare pstree and netscan side-by-
side) or Notepad++.

● Command Line Utilities: Use grep (Linux/Mac) or findstr (Windows) to quickly filter PIDs
across all three files.

● Hex/Text Viewers: Use CyberChef if you need to decode any strings found in the malfind
output.

● Knowledge Bases: Refer to the MITRE ATT&amp;CK Framework and LOLBAS (Living Off
The Land Binaries and Scripts) to verify if a process&#39;s behavior matches known attack
patterns.

Required Deliverables

In your final investigation report, you must answer the following:

1. Identify the Compromised Process: Provide the Name and PID of the process acting as
the vessel for the malware.


2. Parent-Child Analysis: Identify the Parent Process (Name and PID) of the malicious
entry. Explain why this relationship is architecturally significant or suspicious in a Windows
environment.

3. Memory Evidence: Cite the specific memory protection flags and Magic Bytes found in the
malfind report that prove code injection has occurred.

4. C2 Identification: Provide the Destination IP address and Port the compromised process
is communicating with.

5. Attack Classification: Based on the evidence (Process Tree + Memory Injection +
Network Call), what specific type of memory-resident attack is this? (e.g., Process
Hollowing, DLL Injection, or Reflective Loading).

3. Evidence Guidelines

● Do not assume a process is safe just because it has a standard Windows name.

● Compare the netscan results with the pstree results to see which processes are actually
talking to the internet.

● Look for inconsistencies between how Windows should work and what the data shows.

Submission Instructions: Your report should be professional and suitable for a SOC Manager.
Use technical terminology (e.g., Parent-Child relationship, Memory Protection, Hexadecimal
Headers).

**Steps**

grep was used to find suspicious processes(svchost.exe) and enteries from Process Tree, Malfind, and Network scan were viewed.

```bash
grep -n "svchost.exe" *.txt
```

A cross-artifact correlation was carried out by conducting a PID Search on 3880
```bash
grep -n "3880" *.txt
```

The parent process was investigated
```bash
grep "3880" pstree_output.txt
```

A search was carried out on PID 2550 from the above output
```bash
grep "2550" pstree_output.txt
```

The suspicious process hierarchy was examined and the chain manually reconstructed


explorer.exe PID 1840

        |
        ↓
notepad.exe PID 2550

        |
        ↓
svchost.exe PID 3880


The chain was compared with the other svchost.exe processes


services.exe PID 512

        |
        ├── svchost.exe PID 720
        |
        └── svchost.exe PID 884


The windows architectural inconsistency was identified and recorded

Suspicious parent-child relationship:

notepad.exe PID 2550

        ↓

svchost.exe PID 3880


The Memory Artifact was analyzed by carrying out the following:

```bash
grep -A5 -B1 "Pid: 3880" malfind_results.txt
```

The Memory Protection and Magic Bytes were recorded

Memory Protection

PAGE_EXECUTE_READWRITE

Magic Bytes

4d 5a

The Magic Bytes were converted to ASCII

4D 5A = MZ


Magic Bytes: 4D 5A ("MZ")


The Network Connection was investigated to know the Destination IP and the Destination Port
```bash
grep "3880" netscan_results.txt
```

A critical correlation was carried out between the Process, Memory, and the Network.

Process Tree

notepad.exe PID 2550

       ↓

svchost.exe PID 3880


Malfind

svchost.exe PID 3880

       ↓

PAGE_EXECUTE_READWRITE

       ↓

4D 5A ("MZ")


Network Scan

svchost.exe PID 3880

       ↓

185.112.55.20:443

       ↓

ESTABLISHED

The Attack was classified by Correlating the process hierarchy, memory flags, and network connections.
Based on the available evidence, the attack can be classified as Process Injection / In-Memory PE Execution.

