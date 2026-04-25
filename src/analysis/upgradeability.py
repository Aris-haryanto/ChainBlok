import re
from cmd.env import Finding

def analyze(parser, findings):
    pattern_delegate = re.compile(r'\.delegatecall\(')
    for match in pattern_delegate.finditer(parser.clean_code):
        findings.append(Finding(
            category="OWASP SC10: Proxy & Upgradeability", title="Use of delegatecall", severity="High",
            line_number=parser.get_line_number(match.start()), explanation="delegatecall executes external code in the context of this contract.",
            recommendation="Ensure the target address is strictly immutable.", code_snippet=match.group(0).strip()[:100]
        ))