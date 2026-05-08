import argparse
from src.chainblok import run_audit

def main():
    parser = argparse.ArgumentParser(description="Chainblok: Modular Smart Contract Security Analyzer")
    parser.add_argument("url", help="URL of the smart contract (Etherscan, Polygonscan, GitHub raw, etc.)")
    parser.add_argument("--api-key", default="", help="Optional API key for block explorers")
    
    args = parser.parse_args()
    run_audit(args.url, args.api_key)

if __name__ == "__main__":
    main()