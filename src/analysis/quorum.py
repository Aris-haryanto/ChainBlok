import re
from cmd.env import Finding

def analyze(parser, findings) -> tuple[bool, bool]:
    quorum_pattern = re.compile(r'(quorum|multisig|multiSig|signaturesRequired|numConfirmations|timelock|Governor|executeTransaction|confirmTransaction)', re.IGNORECASE)
    admin_pattern = re.compile(r'(onlyOwner|onlyAdmin|onlyRole|requiresAuth)')
    
    has_quorum = bool(quorum_pattern.search(parser.clean_code))
    has_admin = bool(admin_pattern.search(parser.clean_code))

    if has_admin and not has_quorum:
        match = admin_pattern.search(parser.clean_code)
        if match:
            findings.append(Finding(
                category="OWASP SC01: Access Control", title="Single Point of Failure (No Internal Quorum)", severity="Medium",
                line_number=parser.get_line_number(match.start()), explanation="Admin roles detected without internal quorum or timelock logic. If the privileged wallet is compromised, it results in full protocol loss.",
                recommendation="Ensure ownership is assigned to a Multisig wallet or implement an on-chain DAO/Timelock mechanism.",
                code_snippet=match.group(0).strip()
            ))
    return has_admin, has_quorum