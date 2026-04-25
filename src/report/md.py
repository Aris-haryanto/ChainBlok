from typing import List
from cmd.env import Finding, ForensicsData, SEVERITY_WEIGHTS, SEVERITY_ICONS

class Reporter:
    def __init__(self, findings: List[Finding], has_admin: bool, has_quorum: bool, forensics: ForensicsData):
        self.findings = findings
        self.has_admin = has_admin
        self.has_quorum = has_quorum
        self.forensics = forensics

    def calculate_score(self):
        score = 100
        for f in self.findings:
            score -= SEVERITY_WEIGHTS.get(f.severity, 0)
        return max(0, score)

    def generate_static_analysis_md(self) -> str:
        md = ["## 1. OWASP Static Analysis Findings\n"]
        md.append(f"**Overall Security Score:** {self.calculate_score()}/100")
        md.append(f"**Total Findings:** {len(self.findings)}\n")

        md.append("### Governance & Access Control Summary")
        md.append(f"- **Privileged Admin Roles Detected:** {'✅ Yes' if self.has_admin else '❌ No'}")
        md.append(f"- **Internal Quorum / Multisig Logic:** {'✅ Yes' if self.has_quorum else '❌ No'}")
        if self.has_admin and not self.has_quorum:
            md.append("\n> **⚠️ Centralization Warning:** Privileged roles found but no internal quorum mechanisms exist. Ensure the owner address is a smart contract Multisig (like Gnosis Safe), not a single user.\n")
        md.append("---\n")

        grouped = {"Critical": [], "High": [], "Medium": [], "Low": [], "Informational": []}
        for f in self.findings:
            if f.severity in grouped: grouped[f.severity].append(f)

        for sev in ["Critical", "High", "Medium", "Low", "Informational"]:
            if not grouped[sev]: continue
            
            md.append(f"### {SEVERITY_ICONS[sev]} ({len(grouped[sev])})")
            for idx, f in enumerate(grouped[sev], 1):
                md.append(f"#### {idx}. {f.title} (Line ~{f.line_number})")
                md.append(f"- **OWASP Category:** {f.category}")
                md.append(f"- **Snippet:**\n  ```solidity\n  {f.code_snippet}\n  ```")
                md.append(f"- **Risk:** {f.explanation}")
                md.append(f"- **Fix:** {f.recommendation}\n")

        return "\n".join(md)

    def generate_forensics_md(self) -> str:
        md = ["## 2. On-Chain Forensics & Contract History\n"]
        
        if not self.forensics.has_address:
            md.append("*No on-chain address provided. Skipping forensics.*")
            return "\n".join(md)

        ui = self.forensics.explorer_ui

        # 1. Deployment Info
        md.append("### Deployment Info")
        if self.forensics.creator:
            md.append(f"- **Original Deployer:** `{self.forensics.creator}`")
            md.append(f"- **Creation Transaction:** [{self.forensics.creation_tx}]({ui}/tx/{self.forensics.creation_tx})\n")
        else:
            md.append("- *Could not fetch contract creation history.*\n")

        # 2. Upgrades
        md.append("### Proxy Logic Upgrades")
        if self.forensics.upgrades:
            md.append(f"**⚠️ WARNING:** This contract is a Proxy and has been **UPGRADED {len(self.forensics.upgrades)} time(s)!**\n")
            for i, tx in enumerate(self.forensics.upgrades):
                md.append(f"- Upgrade #{i+1} Transaction: [{tx}]({ui}/tx/{tx})")
            md.append("\n")
        else:
            md.append("*No Proxy upgrade events found. (Logic appears unchanged since deployment).*\n")

        # 3. Admin Actions
        md.append("### Administrative Action History\n")
        if not self.forensics.admin_actions:
            md.append("*No critical admin actions found in the transaction history.*")
        else:
            md.append("This table tracks distinct combinations of critical state-changing functions and the addresses that successfully executed them.\n")
            md.append("| Action (Function) | Caller Address | Value (ETH) | Transaction Hash |")
            md.append("|---|---|---|---|")
            for action in self.forensics.admin_actions:
                md.append(f"| `{action.function_name}` | `{action.caller}` | {action.value_eth} ETH | [View Tx]({ui}/tx/{action.tx_hash}) |")

        return "\n".join(md)