from marshmallow import Schema, fields


class PoCSchema(Schema):
    source = fields.String()
    title = fields.String()
    link = fields.String()
    parent_name = fields.String()


class PoC:
    def __init__(self, source="exploitdb", title="Exploit for something",
                 link="https://example.com", parent_name="CVE-2000-0000"):
        self.source = source
        self.title = title
        self.link = link
        self.parent_name = parent_name

    def __repr__(self):
        return f"PoC(source={self.source}, title={self.title}, link={self.link}, parent_name={self.parent_name})"


class VulnerabilitySchema(Schema):
    name = fields.String()
    description = fields.String()
    severity = fields.String()
    pocs = fields.Nested(PoCSchema, many=True)


class Vulnerability:
    def __init__(self, name="Default vulnerability",
                 description="Default vulnerability description",
                 severity="0.0", pocs=None):
        self.name = name
        self.description = description
        self.severity = severity
        self.pocs = pocs or []

    def __repr__(self):
        return f"Vulnerability(name={self.name}, description={self.description}, severity={self.severity}, pocs={self.pocs})"


class TechnologySchema(Schema):
    name = fields.String()
    version = fields.String()
    confidence = fields.Integer()
    cpe_name = fields.String()
    cpe_ID = fields.String()
    vulns = fields.Nested(VulnerabilitySchema, many=True)


class Technology:
    def __init__(self, name="Default technology", version="0.0.0",
                 confidence=0, cpe_name="cpe:2.3:*:*:*:*:*:*:*:*:*:*:*", cpe_ID="",
                 vulns=None):
        self.name = name
        self.version = version
        self.confidence = confidence
        self.cpe_name = cpe_name
        self.cpe_ID = cpe_ID
        self.vulns = vulns or []

    def __repr__(self):
        return f"Technology(name={self.name}, version={self.version}, confidence={self.confidence}, cpe_name={self.cpe_name}, cpe_ID={self.cpe_ID}, vulns={self.vulns})"


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
