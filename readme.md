# 🛡️ ChainBlok

**ChainBlok** is a lightweight, highly modular Python-based smart contract security analyzer and on-chain forensics tool. It is designed to perform static code analysis mapped to the **OWASP Smart Contract Top 10** and execute dynamic blockchain forensics to track centralization risks, proxy upgrades, and historical administrative actions.

## 💡 Why I build this
Manual smart contract audits and forensic investigations are notoriously tedious. Combine through nested proxy patterns, tracing deployment origins, and hunting down unverified owner actions across block explorers takes hours of manual digging.

I build ChainBlok to be a zero-friction, modular engine that mimics a professional auditor's workflow. I needed a tool where I could drop in a contract URL and instantly generate a clean, publication-ready report detailing both the code-level vulnerabilities and the actual on-chain governance history. It is built to accelerate initial triage, streamline fundamental security analysis, and map out centralized power structures instantly.

## 🌐 Supported Targets & Blockchains

**What can it analyze?**
ChainBlok can analyze any valid Solidity smart contract. This includes:
* Standard Tokens (ERC20, ERC721, ERC1155)
* DeFi Protocols (AMMs, Lending Pools, Yield Farms)
* Governance Structures (DAOs, Timelocks, Multisigs)
* Upgradeable Contracts (EIP-1967, UUPS Proxy implementations)
* Unverified raw Solidity code hosted directly on GitHub

**Supported Blockchains:**
ChainBlok utilizes the unified Etherscan V2 API to automatically detect and route your queries. It currently supports analyzing verified smart contracts natively on:
* **Ethereum Mainnet**
* **Polygon POS**
* **Binance Smart Chain (BNB)**
* **Arbitrum One**
* **Optimism**
* **Base**

## ⚙️ Installation

ChainBlok is designed to be highly portable and lightweight. The only external Python dependency is the standard `requests` library.

**1. Clone the repository:**
```bash
git clone https://github.com/Aris-haryanto/ChainBlok.git
cd ChainBlok
```

## 🚀 How to Use

ChainBlok is executed entirely via the command line interface. 

**Syntax:**
```bash
python cmd.main <URL> --api-key <OPTIONAL_API_KEY>
```

**Example 1: Auditing a deployed contract (Highly recommended to use an API key to avoid rate limits)**
```bash
python cmd.main https://etherscan.io/address/0x1f9840a85d5af5bf1d1762f925bdaddc4201f984 --api-key YOUR_ETHERSCAN_V2_API_KEY
```

**Example 2: Auditing a raw Solidity file from GitHub (No API key required)**
```bash
python cmd.main https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/master/contracts/token/ERC20/ERC20.sol"
```

### 📄 Output Details
ChainBlok will output its real-time progress in the terminal and generate a comprehensive `Chainblok_Report_0x....md` file in your root directory containing:
1.  **OWASP Static Analysis Findings:** Categorized by severity (Critical, High, Medium, Low) with code snippets and remediation steps.
2.  **Governance & Access Control Summary:** Clear centralization risk warnings and missing quorum flags.
3.  **On-Chain Forensics:** Deployment history, original creator addresses, and Proxy logic upgrade logs.
4.  **Administrative Action History:** A mapped table of every critical state-changing function called, the caller's address, and the exact transaction hash.

## 🏗️ Architecture
ChainBlok uses a highly modular, enterprise-grade architecture separating data fetching, static analysis rules, and reporting. Adding a new vulnerability check is as simple as dropping a new Python file into the `src/analysis/` directory and registering it in the orchestrator.

## ⚠️ Disclaimer
ChainBlok is an automated reconnaissance and initial triage tool, the rules engine relies on heuristic pattern matching and regular expressions, which means it will produce false positives.

You must manually revalidate every finding in the generated report by reviewing the actual contract logic and execution context before making any security, auditing, or investment decisions.

## 🤝 Contributing
Contributions, issues, and feature requests are welcome! Feel free to check the issues page to help expand the analysis rules engine.