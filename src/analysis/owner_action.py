import requests
import re
import urllib.parse
from cmd.env import ETHERSCAN_V2_API, CHAIN_UI, ForensicsData, AdminAction

def gather_forensics(url: str, api_key: str) -> ForensicsData:
    print("[*] Gathering On-Chain Forensics & History...")
    data = ForensicsData()

    address_match = re.search(r'0x[a-fA-F0-9]{40}', url)
    if not address_match:
        print("[-] No contract address found in URL. Skipping on-chain history.")
        return data

    address = address_match.group(0)
    data.has_address = True
    data.address = address
    
    # Determine Chain Context
    explorer_ui = "https://etherscan.io"
    chain_id = "1"
    for cid, ui_url in CHAIN_UI.items():
        domain = urllib.parse.urlparse(ui_url).netloc
        if domain in url:
            explorer_ui = f"https://{domain}"
            chain_id = cid
            break
    data.explorer_ui = explorer_ui

    # 1. Fetch Deployment Info
    params_creation = {"chainid": chain_id, "module": "contract", "action": "getcontractcreation", "contractaddresses": address, "apikey": api_key}
    try:
        res = requests.get(ETHERSCAN_V2_API, params=params_creation).json()
        if res.get('status') == '1' and res.get('result'):
            data.creator = res['result'][0]['contractCreator']
            data.creation_tx = res['result'][0]['txHash']
    except Exception:
        pass

    # 2. Check Proxy Upgrades
    print("[*] Checking for Proxy Logic Upgrades...")
    upgraded_topic = "0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b"
    params_logs = {"chainid": chain_id, "module": "logs", "action": "getLogs", "address": address, "topic0": upgraded_topic, "apikey": api_key}
    try:
        res_logs = requests.get(ETHERSCAN_V2_API, params=params_logs).json()
        if res_logs.get('status') == '1' and res_logs.get('result'):
            data.upgrades = [log['transactionHash'] for log in res_logs['result']]
    except Exception:
        pass

    # 3. Track Admin Actions
    data.admin_actions = _track_admin_actions(address, chain_id, api_key)
    
    return data

def _track_admin_actions(address: str, chain_id: str, api_key: str) -> list[AdminAction]:
    print("[*] Paginating through transaction history for Owner Actions...")
    all_txs = []
    page = 1
    
    while True:
        params = {"chainid": chain_id, "module": "account", "action": "txlist", "address": address, "startblock": 0, "endblock": 99999999, "page": page, "offset": 10000, "sort": "desc", "apikey": api_key}
        try:
            res = requests.get(ETHERSCAN_V2_API, params=params).json()
            if res.get('status') == '1' and isinstance(res.get('result'), list):
                txs = res['result']
                all_txs.extend(txs)
                if len(txs) < 10000: break
                page += 1
            else:
                break 
        except Exception:
            break

    keywords = ['set', 'update', 'change', 'withdraw', 'mint', 'burn', 'transferownership', 'upgrade']
    seen_combinations = set()
    actions = []

    for tx in all_txs:
        raw_func = tx.get('functionName', '')
        caller = tx.get('from', '').lower()
        if not raw_func: continue
        
        if any(kw in raw_func.lower() for kw in keywords) and tx.get('txreceipt_status') == '1':
            key = (raw_func, caller)
            if key not in seen_combinations:
                seen_combinations.add(key)
                actions.append(AdminAction(
                    function_name=raw_func,
                    caller=caller,
                    value_eth=int(tx.get('value', 0)) / 10**18,
                    tx_hash=tx.get('hash')
                ))

    return actions