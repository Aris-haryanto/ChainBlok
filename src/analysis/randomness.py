import re
from cmd.env import Finding

def analyze(parser, findings):
    random_pattern = re.compile(r'((block\.timestamp|block\.difficulty|blockhash)\s*%|keccak256.*(block\.timestamp|block\.difficulty))')
    for match in random_pattern.finditer(parser.clean_code):
        findings.append(Finding(
            category="OWASP SC09 (2025): Insecure Randomness", title="Predictable On-Chain Randomness", severity="High",
            line_number=parser.get_line_number(match.start()), explanation="Using block variables for randomness is insecure. Miners can manipulate these values.",
            recommendation="Use a Verifiable Random Function (VRF) like Chainlink VRF.", code_snippet=match.group(0).strip()[:100]
        ))