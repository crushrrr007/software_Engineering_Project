"""
MITRE ATT&CK Technique Mapper
Maps detected activities to MITRE ATT&CK framework techniques
"""

from enum import Enum
from typing import Dict, List


class MITRETactic(Enum):
    """MITRE ATT&CK Tactics"""
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


class MITRETechnique:
    """MITRE ATT&CK Technique representation"""

    def __init__(self, technique_id: str, name: str, tactic: MITRETactic,
                 description: str, severity: str = "medium"):
        """
        Initialize a MITRE technique

        Args:
            technique_id: MITRE technique ID (e.g., T1113)
            name: Technique name
            tactic: Associated tactic
            description: Technique description
            severity: Severity level (low, medium, high, critical)
        """
        self.technique_id = technique_id
        self.name = name
        self.tactic = tactic
        self.description = description
        self.severity = severity
        self.url = f"https://attack.mitre.org/techniques/{technique_id}/"

    def to_dict(self) -> Dict:
        """Convert to dictionary representation"""
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "tactic": self.tactic.value,
            "description": self.description,
            "severity": self.severity,
            "url": self.url
        }

    def __str__(self):
        return f"{self.technique_id} - {self.name} ({self.tactic.value})"


class MITREMapper:
    """Maps security events to MITRE ATT&CK techniques"""

    # Define relevant techniques
    TECHNIQUES = {
        "T1113": MITRETechnique(
            technique_id="T1113",
            name="Screen Capture",
            tactic=MITRETactic.COLLECTION,
            description="Adversaries may attempt to take screen captures of the desktop to gather "
                       "information over the course of an operation. Screen capturing functionality "
                       "may be included as a feature of a remote access tool used in post-compromise "
                       "operations. Taking a screenshot is also typically possible through native "
                       "utilities or API calls, such as CopyFromScreen, xwd, or screencapture.",
            severity="high"
        ),
        "T1056.001": MITRETechnique(
            technique_id="T1056.001",
            name="Input Capture: Keylogging",
            tactic=MITRETactic.COLLECTION,
            description="Adversaries may log user keystrokes to intercept credentials as the user "
                       "types them. Keylogging is likely to be used to acquire credentials for new "
                       "access opportunities when OS Credential Dumping efforts are not effective.",
            severity="high"
        ),
        "T1041": MITRETechnique(
            technique_id="T1041",
            name="Exfiltration Over C2 Channel",
            tactic=MITRETactic.EXFILTRATION,
            description="Adversaries may steal data by exfiltrating it over an existing command and "
                       "control channel. Data exfiltration over the command and control channel is a "
                       "common technique.",
            severity="high"
        ),
        "T1057": MITRETechnique(
            technique_id="T1057",
            name="Process Discovery",
            tactic=MITRETactic.DISCOVERY,
            description="Adversaries may attempt to get information about running processes on a system.",
            severity="low"
        ),
        "T1082": MITRETechnique(
            technique_id="T1082",
            name="System Information Discovery",
            tactic=MITRETactic.DISCOVERY,
            description="An adversary may attempt to get detailed information about the operating system "
                       "and hardware, including version, patches, hotfixes, service packs, and architecture.",
            severity="low"
        ),
        "T1055": MITRETechnique(
            technique_id="T1055",
            name="Process Injection",
            tactic=MITRETactic.PRIVILEGE_ESCALATION,
            description="Adversaries may inject code into processes in order to evade process-based "
                       "defenses as well as possibly elevate privileges.",
            severity="critical"
        ),
        "T1027": MITRETechnique(
            technique_id="T1027",
            name="Obfuscated Files or Information",
            tactic=MITRETactic.DEFENSE_EVASION,
            description="Adversaries may attempt to make an executable or file difficult to discover "
                       "or analyze by encrypting, encoding, or otherwise obfuscating its contents.",
            severity="medium"
        )
    }

    @staticmethod
    def get_technique(technique_id: str) -> MITRETechnique:
        """
        Get a MITRE technique by ID

        Args:
            technique_id: MITRE technique ID

        Returns:
            MITRETechnique: The technique object
        """
        return MITREMapper.TECHNIQUES.get(technique_id)

    @staticmethod
    def map_detection(detection_type: str) -> List[MITRETechnique]:
        """
        Map a detection type to relevant MITRE techniques

        Args:
            detection_type: Type of detection (e.g., "screenshot", "keylog", "network")

        Returns:
            List of relevant MITRE techniques
        """
        mappings = {
            "screenshot": ["T1113"],
            "screen_capture": ["T1113"],
            "api_capture": ["T1113"],
            "keylog": ["T1056.001"],
            "network_exfiltration": ["T1041"],
            "process_discovery": ["T1057"],
            "system_info": ["T1082"],
            "process_injection": ["T1055"],
            "obfuscation": ["T1027"]
        }

        technique_ids = mappings.get(detection_type.lower(), [])
        return [MITREMapper.get_technique(tid) for tid in technique_ids if tid in MITREMapper.TECHNIQUES]

    @staticmethod
    def get_all_techniques() -> List[MITRETechnique]:
        """Get all defined MITRE techniques"""
        return list(MITREMapper.TECHNIQUES.values())

    @staticmethod
    def get_techniques_by_tactic(tactic: MITRETactic) -> List[MITRETechnique]:
        """
        Get all techniques for a specific tactic

        Args:
            tactic: MITRE tactic

        Returns:
            List of techniques under the tactic
        """
        return [t for t in MITREMapper.TECHNIQUES.values() if t.tactic == tactic]

    @staticmethod
    def format_alert_with_mitre(alert_message: str, detection_type: str) -> str:
        """
        Format an alert message with MITRE ATT&CK information

        Args:
            alert_message: Original alert message
            detection_type: Type of detection

        Returns:
            Formatted alert message with MITRE info
        """
        techniques = MITREMapper.map_detection(detection_type)

        if not techniques:
            return alert_message

        mitre_info = "\n\n[MITRE ATT&CK]\n"
        for technique in techniques:
            mitre_info += f"- {technique.technique_id}: {technique.name}\n"
            mitre_info += f"  Tactic: {technique.tactic.value}\n"
            mitre_info += f"  Severity: {technique.severity.upper()}\n"
            mitre_info += f"  Reference: {technique.url}\n"

        return alert_message + mitre_info


# Example usage
if __name__ == "__main__":
    # Test the mapper
    mapper = MITREMapper()

    # Get screen capture technique
    t1113 = mapper.get_technique("T1113")
    print(t1113)
    print(t1113.to_dict())

    # Map detection to techniques
    techniques = mapper.map_detection("screenshot")
    print(f"\nTechniques for screenshot detection: {[str(t) for t in techniques]}")

    # Format alert
    alert = "Suspicious screenshot activity detected from process: malware.exe"
    formatted = mapper.format_alert_with_mitre(alert, "screenshot")
    print(f"\n{formatted}")
