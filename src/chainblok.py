import re
import json
import requests
import sys
import urllib.parse
from datetime import datetime

from cmd.env import ETHERSCAN_V2_API, CHAIN_UI
from src.analysis import (
    reentrancy, access_control, quorum, defi_vectors, 
    logic_gas, upgradeability, external_deps, arithmetic, 
    randomness, input_validation, owner_action
)
from src.report.md import Reporter

class Chainblok:
    """Unified engine handling fetching, parsing, and analysis state."""
    
    def __init__(self, url: str, api_key: str = ""):
        self.url = url
        self.api_key = api_key
        
        # Code & Parser State
        self.raw_code = ""
        self.clean_code = ""
        
        # Analysis & Forensics State
        self.findings = []
        self.has_admin = False
        self.has_quorum = False
        self.forensics_data = None

    def _fetch_source(self):
        """Fetches smart contract code from block explorers or GitHub."""
        print(f"[*] Fetching contract source from: {self.url}")
        
        if "github.com" in self.url or "raw.githubusercontent.com" in self.url:
            url = self.url
            if "/blob/" in url:
                url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
            response = requests.get(url)
            if response.status_code != 200:
                sys.exit(f"[-] Error: Failed to fetch from GitHub.")
            self.raw_code = response.text
            return
        
        address_match = re.search(r'0x[a-fA-F0-9]{40}', self.url)
        if not address_match:
            sys.exit("[-] Error: Invalid contract address.")
        
        address = address_match.group(0)
        chain_id = "1" 
        for cid, ui_url in CHAIN_UI.items():
            if urllib.parse.urlparse(ui_url).netloc in self.url:
                chain_id = cid
                break
        
        params = {"chainid": chain_id, "module": "contract", "action": "getsourcecode", "address": address, "apikey": self.api_key}
        try:
            response = requests.get(ETHERSCAN_V2_API, params=params).json()
            if response.get('status') != '1':
                sys.exit(f"[-] Explorer API Error: {response.get('result')}")
            
            source_data = response['result'][0]['SourceCode']
            
            # Handle multi-file verified contracts
            if source_data.startswith('{{'):
                data = json.loads(source_data[1:-1])
                self.raw_code = "".join([f"\n// File: {fn}\n{content['content']}" for fn, content in data['sources'].items()])
            else:
                self.raw_code = source_data
        except Exception as e:
            sys.exit(f"[-] Failed to fetch contract source: {str(e)}")

    def _parse_code(self):
        """Normalizes code by removing comments for the AST heuristic."""
        print("[*] Parsing AST and normalizing code...")
        self.clean_code = re.sub(r'/\*.*?\*/', '', re.sub(r'//.*', '', self.raw_code), flags=re.DOTALL)
        # print(self.clean_code)

    def get_line_number(self, index: int) -> int:
        """Utility for analysis rules to map regex matches to line numbers."""
        return self.clean_code[:index].count('\n') + 1

    def _run_analysis(self):
        """Executes the modular security rules and on-chain forensics."""
        print("[*] Running comprehensive security and forensics engine...")
        
        # 1. Run Static Code Analysis
        # Notice we just pass 'self' as the parser context
        self.has_admin, self.has_quorum = quorum.analyze(self, self.findings)
        reentrancy.analyze(self, self.findings)
        access_control.analyze(self, self.findings)
        defi_vectors.analyze(self, self.findings)
        logic_gas.analyze(self, self.findings)
        upgradeability.analyze(self, self.findings)
        external_deps.analyze(self, self.findings)
        arithmetic.analyze(self, self.findings)
        randomness.analyze(self, self.findings)
        input_validation.analyze(self, self.findings)
        
        # 2. Run Dynamic On-Chain Forensics
        self.forensics_data = owner_action.gather_forensics(self.url, self.api_key)

    def run(self):
        """Main lifecycle orchestrator."""
        self._fetch_source()
        self._parse_code()
        self._run_analysis()
        
        # Build Report
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_md = f"# 🛡️ Chainblok Security Audit Report\n\n**Target:** `{self.url}`\n**Date:** {current_time}\n\n---\n\n"

        reporter = Reporter(self.findings, self.has_admin, self.has_quorum, self.forensics_data)
        
        report_md += reporter.generate_static_analysis_md() + "\n\n---\n\n"
        report_md += reporter.generate_forensics_md()

        # Save to File
        address_match = re.search(r'0x[a-fA-F0-9]{40}', self.url)
        filename = f"Chainblok_Report_{address_match.group(0) if address_match else 'local_file'}.md"

        print("\n[*] Writing report...")
        with open(filename, "w", encoding="utf-8") as f:
            f.write(report_md)

        print(f"\n[SUCCESS] Analysis complete. Saved to: {filename}")


# --- ENTRY POINT WRAPPER ---
def run_audit(url: str, api_key: str):
    service = Chainblok(url, api_key)
    service.run()