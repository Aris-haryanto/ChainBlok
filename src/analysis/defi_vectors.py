import re
from cmd.env import Finding

def analyze(parser, findings):
    pattern_spot = re.compile(r'(balanceOf\(address\(this\)\)|getReserves\(\))')
    for match in pattern_spot.finditer(parser.clean_code):
        findings.append(Finding(
            category="OWASP SC03: Price Oracle Manipulation", title="Flash Loan Spot Price Risk", severity="High",
            line_number=parser.get_line_number(match.start()), explanation="Relies on instantaneous token balances or reserves, highly vulnerable to Flash Loans.",
            recommendation="Use a Time-Weighted Average Price (TWAP) or Chainlink.", code_snippet=match.group(0).strip()
        ))