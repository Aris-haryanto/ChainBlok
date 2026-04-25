from dataclasses import dataclass, field
from typing import List

ETHERSCAN_V2_API = "https://api.etherscan.io/v2/api"

CHAIN_UI = {
    "1": "https://etherscan.io/address",
    "137": "https://polygonscan.com/address",
    "56": "https://bscscan.com/address",
    "42161": "https://arbiscan.io/address",
    "10": "https://optimistic.etherscan.io/address",
    "8453": "https://basescan.org/address"
}

SEVERITY_WEIGHTS = {"Critical": 25, "High": 15, "Medium": 10, "Low": 5, "Informational": 0}
SEVERITY_ICONS = {"Critical": "🔴 CRITICAL", "High": "🟠 HIGH", "Medium": "🟡 MEDIUM", "Low": "🔵 LOW", "Informational": "⚪ INFO"}

@dataclass
class Finding:
    category: str
    title: str
    severity: str
    line_number: int
    explanation: str
    recommendation: str
    code_snippet: str

@dataclass
class AdminAction:
    function_name: str
    caller: str
    value_eth: float
    tx_hash: str

@dataclass
class ForensicsData:
    has_address: bool = False
    address: str = ""
    explorer_ui: str = ""
    creator: str = ""
    creation_tx: str = ""
    upgrades: List[str] = field(default_factory=list)
    admin_actions: List[AdminAction] = field(default_factory=list)