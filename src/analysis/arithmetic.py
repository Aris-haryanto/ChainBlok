import re
from cmd.env import Finding

def analyze(parser, findings):
    pragma_pattern = re.compile(r'pragma solidity \^?0\.[0-7]\.')
    has_old_pragma = pragma_pattern.search(parser.clean_code)
    has_safemath = "SafeMath" in parser.clean_code

    if has_old_pragma and not has_safemath:
        findings.append(Finding(
            category="OWASP SC09: Integer Overflow/Underflow", title="Outdated Pragma & Missing SafeMath", severity="High",
            line_number=parser.get_line_number(has_old_pragma.start()), explanation="Contract uses Solidity < 0.8.0 without SafeMath.",
            recommendation="Upgrade to Solidity ^0.8.0 or implement OpenZeppelin SafeMath.", code_snippet=has_old_pragma.group(0).strip()
        ))

    unchecked_pattern = re.compile(r'unchecked\s*\{[^\}]*[-+*\/]+[^\}]*\}', re.DOTALL)
    for match in unchecked_pattern.finditer(parser.clean_code):
        snippet = match.group(0).strip()[:100]
        findings.append(Finding(
            category="OWASP SC09: Integer Overflow/Underflow", title="Dangerous 'unchecked' Math Block", severity="Medium",
            line_number=parser.get_line_number(match.start()), explanation="Unchecked block contains arithmetic operations that will not revert on overflow.",
            recommendation="Ensure variables within unchecked blocks are absolutely bounded.", code_snippet=snippet
        ))