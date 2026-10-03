"""
MITRE ATT&CK mapping for the incident report.

GuardDuty names a finding `ThreatPurpose:ResourceType/ThreatFamily.Variant!Artifact`.
The threat purpose maps onto the kill-chain stage the correlator records, and
each stage onto an ATT&CK tactic. The family, for the handful whose meaning is
unambiguous, maps onto a technique.

The mapping is indicative. It says which part of the matrix a finding belongs
to, so a reader can place the incident; it does not claim the technique was
confirmed. Families whose finding type does not pin a technique — GuardDuty's
"AnomalousBehavior" detectors above all — get a tactic and nothing more.
"""

# Mirrors the correlator's table; a test holds the two equal.
STAGE_BY_PURPOSE = {
    "Recon": "reconnaissance",
    "UnauthorizedAccess": "initial-access",
    "CredentialAccess": "credential-access",
    "Discovery": "discovery",
    "Execution": "execution",
    "Persistence": "persistence",
    "PrivilegeEscalation": "privilege-escalation",
    "DefenseEvasion": "defense-evasion",
    "Backdoor": "command-and-control",
    "Trojan": "command-and-control",
    "CryptoCurrency": "impact",
    "Impact": "impact",
    "Exfiltration": "exfiltration",
    "Policy": "policy-violation",
    "PenTest": "reconnaissance",
    "Stealth": "defense-evasion",
    "InitialAccess": "initial-access",
    "DefenseImpairment": "defense-evasion",
    "LateralMovement": "lateral-movement",
    "ResourceDevelopment": "resource-development",
}

STAGE_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "credential-access",
    "discovery", "execution", "persistence", "privilege-escalation", "defense-evasion",
    "lateral-movement", "command-and-control", "exfiltration", "impact",
    "policy-violation", "unknown",
]

# ATT&CK Enterprise tactics, by the correlator's stage name. Policy violations
# and unknown stages have no tactic.
TACTICS = {
    "reconnaissance": ("TA0043", "Reconnaissance"),
    "resource-development": ("TA0042", "Resource Development"),
    "initial-access": ("TA0001", "Initial Access"),
    "credential-access": ("TA0006", "Credential Access"),
    "discovery": ("TA0007", "Discovery"),
    "execution": ("TA0002", "Execution"),
    "persistence": ("TA0003", "Persistence"),
    "privilege-escalation": ("TA0004", "Privilege Escalation"),
    "defense-evasion": ("TA0005", "Defense Evasion"),
    "lateral-movement": ("TA0008", "Lateral Movement"),
    "command-and-control": ("TA0011", "Command and Control"),
    "exfiltration": ("TA0010", "Exfiltration"),
    "impact": ("TA0040", "Impact"),
}

# Techniques by GuardDuty threat family, for families that name one activity.
TECHNIQUES_BY_FAMILY = {
    "SSHBruteForce": ("T1110", "Brute Force"),
    "RDPBruteForce": ("T1110", "Brute Force"),
    "PortProbeUnprotectedPort": ("T1046", "Network Service Discovery"),
    "Portscan": ("T1046", "Network Service Discovery"),
    "PortSweep": ("T1046", "Network Service Discovery"),
    "C&CActivity": ("T1071", "Application Layer Protocol"),
    "BitcoinTool": ("T1496", "Resource Hijacking"),
    "TorClient": ("T1090.003", "Proxy: Multi-hop Proxy"),
    "TorRelay": ("T1090.003", "Proxy: Multi-hop Proxy"),
    "DNSDataExfiltration": ("T1048", "Exfiltration Over Alternative Protocol"),
    "InstanceCredentialExfiltration": ("T1078.004", "Valid Accounts: Cloud Accounts"),
    "MaliciousIPCaller": ("T1078", "Valid Accounts"),
    "RootCredentialUsage": ("T1078.004", "Valid Accounts: Cloud Accounts"),
    "DenialOfService": ("T1498", "Network Denial of Service"),
}

# A few purposes name a technique once the affected resource type is known.
TECHNIQUES_BY_PURPOSE_RESOURCE = {
    ("Exfiltration", "S3"): ("T1530", "Data from Cloud Storage"),
}


def parse_finding_type(finding_type):
    """(purpose, resource type, family) from a GuardDuty finding type, each ""
    where the type does not have that part."""
    text = str(finding_type or "")
    purpose, _, rest = text.partition(":")
    resource, _, family = rest.partition("/")
    family = family.split(".", 1)[0].split("!", 1)[0]
    return purpose, resource, family


def stage(finding_type):
    purpose, _, _ = parse_finding_type(finding_type)
    return STAGE_BY_PURPOSE.get(purpose, "unknown")


def technique(finding_type):
    """(ID, name) for a finding type that pins a technique, else None."""
    purpose, resource, family = parse_finding_type(finding_type)
    return (TECHNIQUES_BY_FAMILY.get(family)
            or TECHNIQUES_BY_PURPOSE_RESOURCE.get((purpose, resource)))


def mapping(finding_types):
    """Tactics and techniques for a set of finding types.

    Tactics come back in kill-chain order, each once; techniques once per
    distinct finding type that pins one, in the order the types were given,
    with the finding type kept beside the technique so the reader can see
    what each claim rests on.
    """
    stages = {stage(t) for t in finding_types}
    tactics = [(s, *TACTICS[s]) for s in STAGE_ORDER if s in stages and s in TACTICS]
    techniques, seen = [], set()
    for finding_type in finding_types:
        found = technique(finding_type)
        if found and finding_type not in seen:
            seen.add(finding_type)
            techniques.append((finding_type, *found))
    return {"tactics": tactics, "techniques": techniques}
