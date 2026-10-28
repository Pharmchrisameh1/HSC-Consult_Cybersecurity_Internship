# IOC Summary — izup.exe

## Sample hashes
See `hashes.txt`. Primary sample SHA-256:
`1adc29f30b30e301acefe1b46bbbd7a4f3a76c3708ab842199e95f8f5f053244`

## Priority items for investigation
- Scheduled task name: `Updates\\fAjLxt`
- Executable copy: `fAjLxt.exe`
- SMTP-related domain: `us2.smtp.mailhostbox.com`
- External-IP lookup: `ip-api.com`
- Reported Defender exclusion attempt: `Add-MpPreference -ExclusionPath`
- Reported task-cache registry changes: see `registry.txt`

## Confidence and handling notes
- Primary sample hashes are high-confidence identifiers for the submitted file.
- File/task paths and the `schtasks.exe` command were reported in sandbox behaviour.
- SMTP connection evidence warrants investigation but does not prove successful email delivery or data exfiltration.
- Browser, mail-client, and VPN paths were probed; some returned not-found statuses. Do not describe this as confirmed credential theft.
- Microsoft/Sectigo certificate URLs and related IPs may be legitimate infrastructure. Keep them as contextual observations, not automatically malicious block indicators.
- IPs, domains, and strings in aggregated reports may originate from separate runs, memory strings, or shared infrastructure. Confirm source and timestamp before operational blocking.
