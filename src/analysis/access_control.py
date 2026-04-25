import re
from cmd.env import Finding

def analyze(parser, findings):
    # tx.origin check
    pattern_tx = re.compile(r'tx\.origin\s*==')
    for match in pattern_tx.finditer(parser.clean_code):
        findings.append(Finding(
            category="OWASP SC01: Access Control", title="tx.origin used for Authorization", severity="High",
            line_number=parser.get_line_number(match.start()), explanation="Using tx.origin makes the contract vulnerable to phishing attacks via malicious proxies.",
            recommendation="Use msg.sender instead.", code_snippet=match.group(0).strip()
        ))

    # Missing modifier check
    func_pattern = re.compile(r'function\s+([a-zA-Z0-9_]+)\s*\([^)]*\)\s*[^\{]*(public|external)[^\{]*\{', re.MULTILINE)
    risk_keywords = ['set', 'update', 'change', 'withdraw', 'mint', 'burn', 'transferOwnership', 'upgrade']
    for match in func_pattern.finditer(parser.clean_code):
        func_name = match.group(1)
        func_signature = match.group(0)
        if any(func_name.lower().startswith(kw) or kw in func_name.lower() for kw in risk_keywords):
            auth_keywords = ['onlyOwner', 'onlyRole', 'onlyAdmin', 'require(msg.sender ==', 'requiresAuth']
            if not any(auth in func_signature for auth in auth_keywords):
                start_idx = match.end()
                end_idx = parser.clean_code.find('}', start_idx)
                if 'msg.sender' not in parser.clean_code[start_idx:end_idx]:
                    findings.append(Finding(
                        category="OWASP SC01: Access Control", title=f"Missing Role Check in `{func_name}`", severity="Critical",
                        line_number=parser.get_line_number(match.start()), explanation="State-changing administrative function lacks access control.",
                        recommendation="Add an `onlyOwner` or role-based modifier.", code_snippet=func_signature.strip()[:100]
                    ))