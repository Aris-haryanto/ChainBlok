import re
from cmd.env import Finding

def analyze(parser, findings):
    pattern_loop = re.compile(r'for\s*\([^;]*;\s*[^;]*\.length\s*;')
    for match in pattern_loop.finditer(parser.clean_code):
        findings.append(Finding(
            category="OWASP SC10 (2025): Denial of Service", title="Unbounded Array Loop", severity="Medium",
            line_number=parser.get_line_number(match.start()), explanation="Looping over a dynamic array can exceed block gas limits, bricking the function.",
            recommendation="Implement pagination or hard bounds on the array size.", code_snippet=match.group(0).strip()[:100]
        ))