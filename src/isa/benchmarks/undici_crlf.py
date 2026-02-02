from __future__ import annotations

from isa.witness import Witness, Target, Vuln, Endpoint, Location


def demo_witness(rev: str) -> Witness:
    # NOTE: This is a placeholder witness used to lock down output shape.
    # Later milestones will replace this with a real interprocedural slice + SMT+Z3 proof.
    return Witness(
        target=Target(repo="https://github.com/nodejs/undici", rev=rev),
        vuln=Vuln(kind="crlf-injection/request-splitting", advisory="CVE-2022-35948"),
        source=Endpoint(
            kind="external_input",
            location=Location(file="poc", function="headers['content-type']"),
            notes="Untrusted header value containing CRLF",
        ),
        sink=Endpoint(
            kind="http-request-serialization",
            location=Location(file="undici/index.js", function="request"),
            notes="Header value reaches outbound request bytes without validation (vulnerable rev)",
        ),
        call_chain=[
            Location(file="undici/index.js", function="request"),
        ],
        path_constraints=[],
        z3_model={
            "content_type": "application/json\\r\\n\\r\\nGET /pwned HTTP/1.1\\r\\nHost: 127.0.0.1:3000\\r\\n\\r\\n",
        },
    )
