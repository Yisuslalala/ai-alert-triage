"""The subset of MITRE ATT&CK (Enterprise) techniques the agent may cite.

The model can only choose IDs from this catalog, so a report never contains
an invented technique. Extend it as new detections need it.
"""

from ai_alert_triage.domain.investigation import AttackTechnique

_TECHNIQUES = [
    AttackTechnique("T1003.001", "OS Credential Dumping: LSASS Memory", "Credential Access"),
    AttackTechnique("T1021.001", "Remote Services: Remote Desktop Protocol", "Lateral Movement"),
    AttackTechnique("T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
    AttackTechnique("T1027", "Obfuscated Files or Information", "Defense Evasion"),
    AttackTechnique("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration"),
    AttackTechnique("T1053.005", "Scheduled Task/Job: Scheduled Task", "Persistence"),
    AttackTechnique("T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution"),
    AttackTechnique(
        "T1059.003", "Command and Scripting Interpreter: Windows Command Shell", "Execution"
    ),
    AttackTechnique(
        "T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control"
    ),
    AttackTechnique("T1078", "Valid Accounts", "Initial Access"),
    AttackTechnique("T1098", "Account Manipulation", "Persistence"),
    AttackTechnique("T1105", "Ingress Tool Transfer", "Command and Control"),
    AttackTechnique("T1110", "Brute Force", "Credential Access"),
    AttackTechnique("T1110.003", "Brute Force: Password Spraying", "Credential Access"),
    AttackTechnique("T1204.002", "User Execution: Malicious File", "Execution"),
    AttackTechnique("T1486", "Data Encrypted for Impact", "Impact"),
    AttackTechnique("T1490", "Inhibit System Recovery", "Impact"),
    AttackTechnique("T1539", "Steal Web Session Cookie", "Credential Access"),
    AttackTechnique("T1547.001", "Boot or Logon Autostart: Registry Run Keys", "Persistence"),
    AttackTechnique("T1562.001", "Impair Defenses: Disable or Modify Tools", "Defense Evasion"),
    AttackTechnique("T1566.001", "Phishing: Spearphishing Attachment", "Initial Access"),
    AttackTechnique("T1566.002", "Phishing: Spearphishing Link", "Initial Access"),
    AttackTechnique(
        "T1567.002", "Exfiltration Over Web Service: Exfiltration to Cloud Storage", "Exfiltration"
    ),
    AttackTechnique("T1621", "Multi-Factor Authentication Request Generation", "Credential Access"),
]

CATALOG: dict[str, AttackTechnique] = {technique.id: technique for technique in _TECHNIQUES}
