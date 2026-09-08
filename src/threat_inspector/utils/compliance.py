"""
Compliance framework mapping for vulnerabilities.
Maps vulnerabilities to PCI-DSS, HIPAA, SOC2, NIST, and other frameworks.

These mappings become compliance claims in a client-facing report, so two
things matter more than coverage of the keyword lists:

  * asking for a framework by its own name must actually select it, and
  * a keyword must not match a word that merely contains it.

Both were wrong. `frameworks=["NIST 800-53"]` — the exact name these mappings
use — selected nothing, because normalisation stripped hyphens and underscores
but not spaces, and the result was compared for exact membership. And keyword
matching was a plain substring test, so "Dispatcher misconfiguration" mapped to
patch-management requirements on the strength of "dis-PATCH-er".

The second fix is narrower than it first looks: substring matching is KEPT,
because it is what makes "patch" match "unpatched" and "ssl" match "OpenSSL".
Anchoring to a word boundary would have removed both of those real mappings to
be rid of one false one, and on a compliance report a missing true mapping is
worse than an extra one.
"""

import logging
import re
from dataclasses import dataclass

log = logging.getLogger("threat_inspector.utils.compliance")


@dataclass
class ComplianceMapping:
    """Compliance framework mapping for a vulnerability."""

    framework: str
    requirement: str
    description: str


# PCI-DSS v4.0 Mappings
PCI_DSS_MAPPINGS = {
    "sql injection": [
        ComplianceMapping(
            "PCI-DSS",
            "6.2.4",
            "Software development personnel working on bespoke and custom software are trained at least once every 12 months on secure coding techniques",
        ),
        ComplianceMapping("PCI-DSS", "6.5.1", "Injection flaws, particularly SQL injection"),
    ],
    "xss": [
        ComplianceMapping("PCI-DSS", "6.5.7", "Cross-site scripting (XSS)"),
    ],
    "cross-site scripting": [
        ComplianceMapping("PCI-DSS", "6.5.7", "Cross-site scripting (XSS)"),
    ],
    "ssl": [
        ComplianceMapping(
            "PCI-DSS", "4.2.1", "Strong cryptography is used during transmission of cardholder data"
        ),
        ComplianceMapping(
            "PCI-DSS",
            "2.2.7",
            "All non-console administrative access is encrypted using strong cryptography",
        ),
    ],
    "weak encryption": [
        ComplianceMapping(
            "PCI-DSS", "3.5.1", "Encryption key management procedures are documented"
        ),
        ComplianceMapping("PCI-DSS", "4.2.1", "Strong cryptography is used during transmission"),
    ],
    "outdated": [
        ComplianceMapping(
            "PCI-DSS", "6.3.3", "Software components are updated to address known vulnerabilities"
        ),
    ],
    "patch": [
        ComplianceMapping(
            "PCI-DSS", "6.3.3", "Software components are updated to address known vulnerabilities"
        ),
        ComplianceMapping(
            "PCI-DSS", "11.3.1", "Internal vulnerability scans are performed at least quarterly"
        ),
    ],
    "authentication": [
        ComplianceMapping(
            "PCI-DSS", "8.3.1", "All user access to system components is authenticated"
        ),
        ComplianceMapping("PCI-DSS", "8.3.6", "MFA is used for all access into the CDE"),
    ],
    "password": [
        ComplianceMapping("PCI-DSS", "8.3.7", "Password complexity requirements are enforced"),
        ComplianceMapping(
            "PCI-DSS", "8.3.9", "Passwords/passphrases are changed at least once every 90 days"
        ),
    ],
    "access control": [
        ComplianceMapping("PCI-DSS", "7.2.1", "Access control system is established"),
        ComplianceMapping(
            "PCI-DSS",
            "7.2.2",
            "Access privileges are assigned based on job classification and function",
        ),
    ],
    "logging": [
        ComplianceMapping("PCI-DSS", "10.2.1", "Audit logs are enabled and active"),
        ComplianceMapping("PCI-DSS", "10.3.1", "Audit log entries contain all required elements"),
    ],
    "firewall": [
        ComplianceMapping("PCI-DSS", "1.2.1", "Inbound and outbound traffic is restricted"),
        ComplianceMapping("PCI-DSS", "1.3.1", "Inbound traffic to the CDE is restricted"),
    ],
    "vulnerability": [
        ComplianceMapping(
            "PCI-DSS", "11.3.1", "Internal vulnerability scans are performed at least quarterly"
        ),
        ComplianceMapping(
            "PCI-DSS", "11.3.2", "External vulnerability scans are performed at least quarterly"
        ),
    ],
}

# HIPAA Security Rule Mappings
HIPAA_MAPPINGS = {
    "encryption": [
        ComplianceMapping("HIPAA", "164.312(a)(2)(iv)", "Encryption and Decryption"),
        ComplianceMapping("HIPAA", "164.312(e)(2)(ii)", "Encryption"),
    ],
    "ssl": [
        ComplianceMapping("HIPAA", "164.312(e)(1)", "Transmission Security"),
        ComplianceMapping("HIPAA", "164.312(e)(2)(ii)", "Encryption"),
    ],
    "access control": [
        ComplianceMapping("HIPAA", "164.312(a)(1)", "Access Control"),
        ComplianceMapping("HIPAA", "164.312(a)(2)(i)", "Unique User Identification"),
    ],
    "authentication": [
        ComplianceMapping("HIPAA", "164.312(d)", "Person or Entity Authentication"),
    ],
    "audit": [
        ComplianceMapping("HIPAA", "164.312(b)", "Audit Controls"),
    ],
    "logging": [
        ComplianceMapping("HIPAA", "164.312(b)", "Audit Controls"),
    ],
    "integrity": [
        ComplianceMapping("HIPAA", "164.312(c)(1)", "Integrity"),
        ComplianceMapping("HIPAA", "164.312(e)(2)(i)", "Integrity Controls"),
    ],
}

# SOC 2 Trust Services Criteria Mappings
SOC2_MAPPINGS = {
    "access control": [
        ComplianceMapping("SOC2", "CC6.1", "Logical and physical access controls"),
        ComplianceMapping(
            "SOC2", "CC6.2", "Prior to issuing system credentials, identity verification"
        ),
    ],
    "authentication": [
        ComplianceMapping("SOC2", "CC6.1", "Logical access security software"),
    ],
    "encryption": [
        ComplianceMapping("SOC2", "CC6.7", "Data transmissions are encrypted"),
    ],
    "ssl": [
        ComplianceMapping("SOC2", "CC6.7", "Transmission encryption controls"),
    ],
    "vulnerability": [
        ComplianceMapping("SOC2", "CC7.1", "Vulnerability management procedures"),
    ],
    "monitoring": [
        ComplianceMapping("SOC2", "CC7.2", "System monitoring activities"),
    ],
    "logging": [
        ComplianceMapping("SOC2", "CC7.2", "Logging and monitoring"),
    ],
    "incident": [
        ComplianceMapping("SOC2", "CC7.3", "Incident response procedures"),
        ComplianceMapping("SOC2", "CC7.4", "Incident containment"),
    ],
    "change management": [
        ComplianceMapping("SOC2", "CC8.1", "Change management process"),
    ],
}

# NIST 800-53 Mappings
NIST_MAPPINGS = {
    "access control": [
        ComplianceMapping("NIST 800-53", "AC-2", "Account Management"),
        ComplianceMapping("NIST 800-53", "AC-3", "Access Enforcement"),
    ],
    "authentication": [
        ComplianceMapping("NIST 800-53", "IA-2", "Identification and Authentication"),
        ComplianceMapping("NIST 800-53", "IA-5", "Authenticator Management"),
    ],
    "audit": [
        ComplianceMapping("NIST 800-53", "AU-2", "Audit Events"),
        ComplianceMapping("NIST 800-53", "AU-3", "Content of Audit Records"),
    ],
    "logging": [
        ComplianceMapping("NIST 800-53", "AU-2", "Audit Events"),
        ComplianceMapping("NIST 800-53", "AU-6", "Audit Review, Analysis, and Reporting"),
    ],
    "configuration": [
        ComplianceMapping("NIST 800-53", "CM-6", "Configuration Settings"),
        ComplianceMapping("NIST 800-53", "CM-7", "Least Functionality"),
    ],
    "encryption": [
        ComplianceMapping("NIST 800-53", "SC-8", "Transmission Confidentiality and Integrity"),
        ComplianceMapping("NIST 800-53", "SC-13", "Cryptographic Protection"),
    ],
    "ssl": [
        ComplianceMapping("NIST 800-53", "SC-8", "Transmission Confidentiality and Integrity"),
    ],
    "vulnerability": [
        ComplianceMapping("NIST 800-53", "RA-5", "Vulnerability Scanning"),
        ComplianceMapping("NIST 800-53", "SI-2", "Flaw Remediation"),
    ],
    "patch": [
        ComplianceMapping("NIST 800-53", "SI-2", "Flaw Remediation"),
    ],
    "incident": [
        ComplianceMapping("NIST 800-53", "IR-4", "Incident Handling"),
        ComplianceMapping("NIST 800-53", "IR-6", "Incident Reporting"),
    ],
}


def _normalize_framework(name: str) -> str:
    """Reduce a framework name to a comparable key.

    Strips EVERY non-alphanumeric character, not just hyphens and underscores.
    "NIST 800-53" — the name these mappings themselves use, and the one a human
    writes in a config file — used to survive normalisation as "nist 80053",
    match neither accepted key, and silently contribute no mappings at all.
    """
    return re.sub(r"[^a-z0-9]", "", name.lower())


# Normalised key -> the mapping table it selects. Aliases are deliberate: a
# framework should answer to the names people actually write for it.
_FRAMEWORK_TABLES: dict[str, dict[str, list[ComplianceMapping]]] = {
    "pcidss": PCI_DSS_MAPPINGS,
    "pci": PCI_DSS_MAPPINGS,
    "hipaa": HIPAA_MAPPINGS,
    "soc2": SOC2_MAPPINGS,
    "nist": NIST_MAPPINGS,
    "nist80053": NIST_MAPPINGS,
}

# What a caller may ask for, in the spelling most likely to be written.
KNOWN_FRAMEWORKS = ("pci-dss", "hipaa", "soc2", "nist-800-53")

DEFAULT_FRAMEWORKS = ["pci-dss", "hipaa", "soc2", "nist"]


# Words that CONTAIN a keyword without meaning it.
#
# The first attempt at this fix anchored keywords to a word boundary, which does
# kill "dis-PATCH-er" — and also killed "un-PATCH-ed" and "Open-SSL", both of
# which are real mappings a client's report should carry. For a compliance
# report a missing true mapping is worse than an extra one, so substring
# matching stays and the known false matches are named here instead.
_FALSE_MATCHES: dict[str, tuple[str, ...]] = {
    "patch": ("dispatch",),
}


def _matches(keyword: str, title: str) -> bool:
    """Does `keyword` appear in `title`, ignoring words that merely contain it?

    Plain `keyword in title` mapped "Dispatcher misconfiguration" to
    patch-management requirements — a compliance claim on a client's report
    about a finding with nothing to do with patching.

    Substring matching is kept deliberately: it is what makes "patch" match
    "unpatched" and "ssl" match "OpenSSL". Only the specific words that carry a
    keyword without its meaning are removed before the test.
    """
    haystack = title
    for false_match in _FALSE_MATCHES.get(keyword, ()):
        haystack = haystack.replace(false_match, " ")
    return keyword in haystack


def get_compliance_mappings(
    vulnerability_title: str,
    frameworks: list[str] | None = None,
) -> list[ComplianceMapping]:
    """
    Get compliance framework mappings for a vulnerability.

    Args:
        vulnerability_title: The vulnerability title/name
        frameworks: Framework names to check (default: all known)

    Returns:
        List of ComplianceMapping objects, de-duplicated by (framework,
        requirement) and in the order the frameworks were requested.
    """
    if frameworks is None:
        frameworks = list(DEFAULT_FRAMEWORKS)

    title_lower = (vulnerability_title or "").lower()

    mappings: list[ComplianceMapping] = []
    for requested in frameworks:
        table = _FRAMEWORK_TABLES.get(_normalize_framework(requested))
        if table is None:
            # Silently contributing nothing is how a report ends up claiming a
            # framework was considered when it never was. Say so.
            log.warning(
                "unknown compliance framework %r — no mappings will be produced for it; "
                "known frameworks: %s",
                requested,
                ", ".join(KNOWN_FRAMEWORKS),
            )
            continue
        for keyword, maps in table.items():
            if _matches(keyword, title_lower):
                mappings.extend(maps)

    seen = set()
    unique_mappings = []
    for m in mappings:
        key = (m.framework, m.requirement)
        if key not in seen:
            seen.add(key)
            unique_mappings.append(m)

    return unique_mappings


def format_compliance_tags(mappings: list[ComplianceMapping]) -> list[str]:
    """
    Format compliance mappings as tags.

    Args:
        mappings: List of ComplianceMapping objects

    Returns:
        List of formatted tags like "PCI-DSS-6.5.1"
    """
    return [f"{m.framework}-{m.requirement}" for m in mappings]
