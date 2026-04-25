import re
from cmd.env import Finding

def analyze(parser, findings):
    ecrecover_pattern = re.compile(r'ecrecover\(')
    for match in ecrecover_pattern.finditer(parser.clean_code):
        if 'nonce' not in parser.clean_code and 'DOMAIN_SEPARATOR' not in parser.clean_code:
            findings.append(Finding(
                category="OWASP SC05: Lack of Input Validation", title="Raw ecrecover / Signature Replay Risk", severity="High",
                line_number=parser.get_line_number(match.start()), explanation="Raw ecrecover is used without a visible nonce or EIP-712 Domain Separator.",
                recommendation="Implement EIP-712 structured data hashing and track used nonces.", code_snippet=match.group(0).strip()
            ))