import re
from cmd.env import Finding

def analyze(parser, findings):
    pattern = re.compile(r'(\.call\{.*?value:.*?\}|\.transfer\(|\.send\()', re.DOTALL)
    for match in pattern.finditer(parser.clean_code):
        snippet = match.group(0).strip()[:100] + "..." if len(match.group(0)) > 100 else match.group(0).strip()
        findings.append(Finding(
            category="OWASP SC08: Reentrancy Attacks",
            title="Potential Reentrancy via External Call",
            severity="Critical",
            line_number=parser.get_line_number(match.start()),
            explanation="External call detected before state updates.",
            recommendation="Use the Checks-Effects-Interactions pattern or a ReentrancyGuard.",
            code_snippet=snippet
        ))