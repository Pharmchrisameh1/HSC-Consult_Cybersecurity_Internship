
# Module 3 — Operation Overcast

## 1. Objective

The objective of this investigation was to analyze AWS CloudTrail logs using command-line tools, particularly `jq`, to identify:

* The compromised AWS access key
* The initial attacker IP address
* The persistence/backdoor IP address
* Privilege escalation activity
* Base64-encoded data
* The stolen S3 object
* The backdoor IAM user
* The attacker's final actions and attempted evasion

---

## 2. Environment

The investigation was performed in WSL/Linux using:

* Bash
* `jq`
* `base64`

The CloudTrail dataset used was:

```text
cloudtrail_log_dump.json
```

---

# Task 1: Prepared the Investigation Environment

## Step 1: Copied the CloudTrail dataset

```bash
cp cloudtrail_log_dump.json ~/HSC-Consult_Cybersecurity_Internship/module3
```

---

## Step 2: Navigated to the Module3 directory

```bash
cd ~/HSC-Consult_Cybersecurity_Internship/module3
```

---

## Step 3: Verified the file exists

```bash
ls
```

---

# Task 2: Establish a Timeline of CloudTrail Events

## Step 4: Extracted the main fields from the CloudTrail logs

```bash
jq -r '.[] | [.eventTime, .sourceIPAddress, .eventSource, .eventName] | @tsv' cloudtrail_log_dump.json
```

### Explanation

* `jq` processes JSON data.
* `-r` outputs raw text instead of JSON strings.
* `.[]` processes each event in the JSON array.
* `.eventTime` extracts the timestamp.
* `.sourceIPAddress` extracts the source IP address.
* `.eventSource` identifies the AWS service.
* `.eventName` identifies the API operation.
* `@tsv` formats the results as tab-separated values.

### Reason

The command creates a simplified timeline that makes it easier to identify unusual activity, suspicious IP addresses, and important AWS API calls.

### Important observations

The timeline showed activity from:

```text
190.45.112.3
45.33.10.11
```

The first suspicious activity from `190.45.112.3` was:

```text
2026-04-20T01:15:33Z    GetCallerIdentity
```

Later, activity from `45.33.10.11` appeared:

```text
2026-04-20T03:35:45Z    CreateAccessKey
```

The dataset therefore provided the initial timeline for tracing the attack.

---

# Task 3: Identify the Compromised Access Key

## Step 5: Searched for events containing an Access Key ID

```bash
jq -r '.[] | select(.userIdentity.accessKeyId != null) | [.eventTime, .sourceIPAddress, .userIdentity.accessKeyId, .eventName] | @tsv' cloudtrail_log_dump.json
```

### Explanation

* `select(.userIdentity.accessKeyId != null)` filters the events so that only events containing an Access Key ID are displayed.
* The command then extracts:

  * timestamp
  * source IP
  * Access Key ID
  * API operation

### Reason

The purpose is to identify which AWS credential was being used during the suspicious activity.

### Finding

The key repeatedly associated with the initial attacker IP was:

```text
AKIA_DEV_PROD_9982
```

It was used by:

```text
190.45.112.3
```

for activities including:

```text
GetCallerIdentity
GetAccountSummary
ListBuckets
ListUserPolicies
ListAttachedUserPolicies
GetSessionToken
PutUserPolicy
GetSecretValue
GetObject
CreateUser
AttachUserPolicy
```

This establishes a strong relationship between the access key and the main sequence of suspicious activity.

---

# Task 4: Investigate the Suspicious IP Addresses

## Step 6: Displayed events associated with the suspicious IP addresses

```bash
jq -r '.[] | select(.sourceIPAddress == "190.45.112.3" or .sourceIPAddress == "45.33.10.11") | [.eventTime, .sourceIPAddress, .eventName] | @tsv' cloudtrail_log_dump.json
```

### Reasons

This filters the CloudTrail dataset to only the two suspicious external IP addresses.

This makes it easier to reconstruct the attack sequence without unrelated AWS activity.

### Findings

The first observed activity from:

```text
190.45.112.3
```

was:

```text
2026-04-20T01:15:33Z    GetCallerIdentity
```

The first observed activity from:

```text
45.33.10.11
```

was:

```text
2026-04-20T03:35:45Z    CreateAccessKey
```

The second IP subsequently performed additional activity, including:

```text
StopLogging
GetCallerIdentity
DeleteBucket
UpdateAccessKey
```

---

# Task 5: Search for Base64-Encoded Data

## Step 7: Located suspicious content and secret values

```bash
jq -r '.[] | select(.requestParameters.content != null or .responseElements.secretString != null) | [.eventTime, .eventName, .requestParameters.content, .responseElements.secretString] | @tsv' cloudtrail_log_dump.json
```

### Reasons

The purpose of this command is to find CloudTrail events containing:

* `requestParameters.content`
* `responseElements.secretString`

These fields may contain encoded or sensitive data.

### Findings

The command identified two Base64 strings:

```text
c2V0dGluZzogYmFja3VwX2VuYWJsZWQ9dHJ1ZQ==
```

and:

```text
ZGJfcGFzczogUEBzc3cwcmRfQ2xvdWRfMjAyNiE=
```

They occurred during:

```text
PutObject
GetSecretValue
```

respectively.

---

# Task 6: Decode the First Base64 String

## Step 8: Decoded the first Base64 value

```bash
echo 'c2V0dGluZzogYmFja3VwX2VuYWJsZWQ9dHJ1ZQ==' | base64 -d
```

### Result

```text
setting: backup_enabled=true
```

### Reason

The `base64 -d` option decodes Base64-encoded data into its original text representation.

### Interpretation

The decoded value represents a configuration setting indicating that backups are enabled.

---

# Task 7: Decode the Second Base64 String

## Step 9: Decoded the second Base64 value

```bash
echo 'ZGJfcGFzczogUEBzc3cwcmRfQ2xvdWRfMjAyNiE=' | base64 -d
```

### Result

```text
db_pass: [REDACTED]
```

### Reason

The command decodes the second Base64 string so that its contents can be identified.

### Interpretation

The decoded value contains a database password credential. Because it is sensitive information, the actual password should not be exposed unnecessarily in the README.

The event was associated with:

```text
GetSecretValue
```

at:

```text
2026-04-20T03:02:11Z
```

This indicates that sensitive credential information was accessed during the attack.

---

# Task 8 — Investigate Privilege Escalation

## Step 10: Searched for IAM policy changes

```bash
jq -r '.[] | select(.eventName == "PutUserPolicy" or .eventName == "AttachUserPolicy") | [.eventTime, .sourceIPAddress, .eventName, .requestParameters.userName, .requestParameters.policyName, .requestParameters.policyArn] | @tsv' cloudtrail_log_dump.json
```

### Reason

`PutUserPolicy` and `AttachUserPolicy` can modify the permissions associated with IAM users.

The command searches specifically for these events to identify privilege escalation.

### Findings

The first relevant event was:

```text
2026-04-20T02:50:33Z
190.45.112.3
PutUserPolicy
dev_user_musa
FullAdmin
```

A later event was:

```text
2026-04-20T03:25:33Z
190.45.112.3
AttachUserPolicy
support_service_backup
AdministratorAccess
```

---

# Task 9: Investigate the Stolen S3 Object

## Step 11: Searched for S3 GetObject operations

```bash
jq -r '.[] | select(.eventName == "GetObject") | [.eventTime, .sourceIPAddress, .requestParameters.bucketName, .requestParameters.key] | @tsv' cloudtrail_log_dump.json
```

### Reason

`GetObject` is an S3 operation used to retrieve an object from an S3 bucket.

Searching for this event allows us to identify files accessed during the investigation.

### Finding

The suspicious access was:

```text
Time:
2026-04-20T03:10:44Z

Source IP:
190.45.112.3

Bucket:
top-secret-financials-2026

Object:
ceo_personal_taxes_2025.pdf
```

This indicates that the attacker accessed the specified file.

---

# Task 10: Identify the Backdoor IAM User

## Step 12: Searched for newly created IAM users

```bash
jq -r '.[] | select(.eventName == "CreateUser") | [.eventTime, .sourceIPAddress, .requestParameters.userName] | @tsv' cloudtrail_log_dump.json
```

### Reason

`CreateUser` records the creation of a new IAM user.

Searching for this event helps identify accounts that may have been created during the attack.

### Finding

The investigation identified:

```text
2026-04-20T03:15:22Z
190.45.112.3
support_service_backup
```

---

# Task 11: Investigate the Backdoor User

## Step 13: Searched for all events associated with the backdoor username

```bash
jq -r '.[] | select(.requestParameters.userName == "support_service_backup") | [.eventTime, .sourceIPAddress, .eventName, (.requestParameters.policyArn // ""), (.requestParameters.accessKeyId // ""), (.requestParameters.policyName // "")] | @tsv' cloudtrail_log_dump.json
```

### Reason

The original attempt to output the entire `requestParameters` object using `@tsv` produced an error because `requestParameters` is a JSON object rather than a simple text value.

Instead, this command extracts individual fields.

### Finding

The account was:

```text
Created:
2026-04-20T03:15:22Z
```

Then:

```text
2026-04-20T03:25:33Z
AttachUserPolicy
AdministratorAccess
```

Then:

```text
2026-04-20T03:35:45Z
CreateAccessKey
```

This sequence shows that the newly created account was subsequently given administrative privileges and an access key was created for it.

---

# Task 12 — Investigate Attempts to Disable Logging

## Step 14: Searched for StopLogging events

```bash
jq -r '.[] | select(.eventName == "StopLogging") | [.eventTime, .sourceIPAddress, .userIdentity.accessKeyId, (.errorCode // "SUCCESS")] | @tsv' cloudtrail_log_dump.json
```

### Reason

`StopLogging` is an important CloudTrail event because it indicates an attempt to stop the recording of AWS API activity.

The command also checks `errorCode` to determine whether the operation succeeded or failed.

### Finding

The dataset shows:

```text
2026-04-20T03:40:00Z
45.33.10.11
AKIA_DEV_PROD_9982
```

with an unsuccessful result if the event contains an access-denied error.

This is relevant to the investigation because disabling logging could reduce the visibility of subsequent attacker activity.

---

# Task 13: Investigate the Final S3 Destruction Attempt

## Step 15: Searched for DeleteBucket events

```bash
jq -r '.[] | select(.eventName == "DeleteBucket") | [.eventTime, .sourceIPAddress, .userIdentity.accessKeyId, .requestParameters.bucketName, (.errorCode // "SUCCESS")] | @tsv' cloudtrail_log_dump.json
```

### Reason

`DeleteBucket` records an attempt to delete an S3 bucket.

The command extracts:

* timestamp
* source IP
* access key
* bucket name
* error code

The error code is important because it tells us whether the deletion succeeded.

### Finding

The event was:

```text
2026-04-20T04:10:00Z
45.33.10.11
AKIA_FAKE_BACKDOOR_KEY_7721
DeleteBucket
AccessDenied
```

Therefore, the attacker **attempted to delete the bucket, but the operation was denied**.

The evidence does not support claiming that the bucket was successfully deleted.

---

# Investigation Timeline

The important events can be summarized as follows:

| Time     | Source IP    | Event             | Significance                         |
| -------- | ------------ | ----------------- | ------------------------------------ |
| 01:15:33 | 190.45.112.3 | GetCallerIdentity | Initial suspicious activity          |
| 01:23:45 | 10.0.1.55    | PutObject         | Base64 configuration value           |
| 02:30:10 | 190.45.112.3 | GetSessionToken   | Session credential activity          |
| 02:50:33 | 190.45.112.3 | PutUserPolicy     | `FullAdmin` policy applied           |
| 03:02:11 | 190.45.112.3 | GetSecretValue    | Database credential accessed         |
| 03:10:44 | 190.45.112.3 | GetObject         | Sensitive S3 object accessed         |
| 03:15:22 | 190.45.112.3 | CreateUser        | Backdoor user created                |
| 03:25:33 | 190.45.112.3 | AttachUserPolicy  | `AdministratorAccess` granted        |
| 03:35:45 | 45.33.10.11  | CreateAccessKey   | New access key created               |
| 03:40:00 | 45.33.10.11  | StopLogging       | Attempt to disable logging           |
| 04:05:44 | 45.33.10.11  | GetCallerIdentity | Backdoor credential activity         |
| 04:10:00 | 45.33.10.11  | DeleteBucket      | Bucket deletion attempted but denied |

---

# Conclusion

The CloudTrail investigation identified a suspicious attack sequence beginning with activity from `190.45.112.3` using the access key `AKIA_DEV_PROD_9982`.

The investigation showed privilege escalation through IAM policy modification, access to a database credential through Secrets Manager, retrieval of a sensitive S3 object, creation of the `support_service_backup` IAM account, assignment of `AdministratorAccess`, and creation of an additional access key.

Activity subsequently shifted to `45.33.10.11`, which used the newly created credential to perform further account activity. The attacker attempted to disable CloudTrail logging and later attempted to delete the S3 bucket containing the accessed data. The `DeleteBucket` operation was denied.

The investigation demonstrates how command-line JSON parsing with `jq` can be used to correlate timestamps, IP addresses, credentials, AWS API calls, IAM changes, and S3 activity to reconstruct an incident timeline.

