import re
from cmd.env import Finding

def analyze(parser, findings):
    pattern_unchecked = re.compile(r'(?<!require\()(?<!if \()[\w\.]+\.call\{.*?\}.*?(?=;)')
    for match in pattern_unchecked.finditer(parser.clean_code):
        findings.append(Finding(
            category="OWASP SC06: Unchecked External Calls", title="Ignored Return Value", severity="Medium",
            line_number=parser.get_line_number(match.start()), explanation="The boolean return value of a low-level call is ignored.",
            recommendation="Wrap the call in a require() statement.", code_snippet=match.group(0).strip()[:100]
        ))