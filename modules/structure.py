from dataclasses import dataclass, field
from dataclass_wizard import JSONWizard


@dataclass
class PoC(JSONWizard):
    source: str = "exploitdb"
    title: str = "Exploit for something"
    link: str = "https://example.com"
    parent_name: str = "CVE-2000-0000"


@dataclass(order=True)
class Vulnerability(JSONWizard):
    name: str = "Default vulnerability"
    description: str = "Default vulnerability description"
    severity: str = "0.0"
    pocs: list[PoC] = field(default_factory=list)

    def __post_init__(self):
        self.sort_index = float(self.severity)


@dataclass(order=True)
class Technology(JSONWizard):
    name: str = "Default technology"
    version: str = "0.0.0"
    confidence: int = 0
    cpe_name: str = "cpe:2.3:*:*:*:*:*:*:*:*:*:*:*"
    cpe_ID: str = ""
    vulns: list[Vulnerability] = field(default_factory=list)

    def __post_init__(self):
        self.sort_index = self.confidence


class Status:
    def __init__(self, status=True, message="Succeeded"):
        self.status = status
        self.message = message

    def __repr__(self):
        return self.message

    def __bool__(self):
        return self.status

    def __getitem__(self, item):
        return self.message[item]
