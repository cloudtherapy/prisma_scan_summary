import requests
import configparser
import logging
import sys
from datetime import datetime

# Setup logging
logging.basicConfig(filename='prisma_cloud_health_check.log',
                    level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(message)s')

def load_config(path='config.ini'):
    config = configparser.ConfigParser()
    config.read(path)
    return config['prisma_cloud']

def get_auth_token(api_url, api_key, api_secret):
    url = f"{api_url}/login"
    payload = {"username": api_key, "password": api_secret}
    try:
        resp = requests.post(url, json=payload)
        resp.raise_for_status()
        token = resp.json().get('token')
        if not token:
            logging.error('No token received during authentication.')
            sys.exit('Authentication failed. No token received.')
        return token
    except Exception as e:
        logging.error(f"Authentication error: {e}")
        sys.exit(f"Authentication failed: {e}")

def get_cloud_accounts(api_url, token):
    url = f"{api_url}/cloud/name"
    headers = {"x-redlock-auth": token}
    try:
        resp = requests.get(url, headers=headers)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logging.error(f"Error fetching cloud accounts: {e}")
        sys.exit(f"Failed to fetch cloud accounts: {e}")

def select_accounts(accounts):
    print("Available Cloud Accounts:")
    for idx, acc in enumerate(accounts):
        name = acc.get('name', acc.get('accountName', 'UNKNOWN'))
        acc_id = acc.get('id', acc.get('accountId', 'UNKNOWN'))
        print(f"{idx+1}. {name} (ID: {acc_id})")
    sel = input("Enter comma-separated numbers of accounts to check (e.g. 1,3): ")
    chosen = []
    try:
        indices = [int(i.strip())-1 for i in sel.split(',') if i.strip().isdigit()]
        for i in indices:
            if 0 <= i < len(accounts):
                chosen.append(accounts[i])
    except Exception as e:
        logging.error(f"Account selection error: {e}")
        sys.exit("Invalid account selection.")
    if not chosen:
        sys.exit("No valid accounts selected.")
    return chosen

def get_scan_rules(scan_results_url, token, cloud_account_id):
    headers = {"x-redlock-auth": token}
    params = {"cloudAccountId": cloud_account_id}
    try:
        resp = requests.get(scan_results_url, headers=headers, params=params)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logging.error(f"Error fetching scan rules for account {cloud_account_id}: {e}")
        return None

def get_agentless_progress(agentless_progress_url, token, cloud_account_id):
    headers = {"x-redlock-auth": token}
    params = {"cloudAccountId": cloud_account_id}
    try:
        resp = requests.get(agentless_progress_url, headers=headers, params=params)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logging.error(f"Error fetching agentless progress for account {cloud_account_id}: {e}")
        return None

def summarize_scan(account, scan_rules, agentless_progress):
    from datetime import datetime, timezone, timedelta
    import re
    name = account['name']
    # Find the scan_rules entry for this account (by id/accountID)
    account_id = account.get('id', account.get('accountId', ''))
    scan_entry = None
    if isinstance(scan_rules, list):
        for entry in scan_rules:
            cred = entry.get('credential', {})
            if entry.get('credentialId') == account_id or cred.get('accountID') == account_id:
                scan_entry = entry
                break
    # If not found, just use the first
    if not scan_entry and isinstance(scan_rules, list) and scan_rules:
        scan_entry = scan_rules[0]
    # Sum over all regions in agentlessAccountState
    success = issues = excluded = unsupported = pending = 0
    total = 0
    last_scan_utc = None
    last_scan_str = 'N/A'
    last_scan_est_str = 'N/A'
    # Find the latest scan time across all regions
    latest_scan_dt = None
    if scan_entry and 'agentlessAccountState' in scan_entry and 'regions' in scan_entry['agentlessAccountState']:
        for region in scan_entry['agentlessAccountState']['regions']:
            coverage = region.get('scanCoverage', {})
            success += coverage.get('successful', 0)
            issues += coverage.get('issued', 0)
            excluded += coverage.get('excluded', 0)
            unsupported += coverage.get('unsupported', 0)
            pending += coverage.get('pending', 0)
            total += sum([coverage.get(k, 0) for k in ['successful', 'issued', 'excluded', 'unsupported', 'pending']])
            region_last_scan = region.get('lastScan')
            if region_last_scan:
                # Try to parse ISO 8601 string
                try:
                    # Remove fractional seconds for compatibility
                    iso_match = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", region_last_scan)
                    if iso_match:
                        dt = datetime.strptime(iso_match.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
                        if not latest_scan_dt or dt > latest_scan_dt:
                            latest_scan_dt = dt
                except Exception:
                    pass
    if latest_scan_dt:
        last_scan_utc = latest_scan_dt
        last_scan_str = last_scan_utc.strftime("%Y-%m-%d %H:%M:%S UTC")
        # Convert to EST (America/New_York)
        # Handle daylight saving time: EST is UTC-5, EDT is UTC-4
        # For simplicity, use UTC-4 as is typical in May
        est_offset = timedelta(hours=-4)
        last_scan_est = last_scan_utc + est_offset
        last_scan_est_str = last_scan_est.strftime("%Y-%m-%d %H:%M:%S EST")
    # Calculate scan coverage
    coverage_pct = f"{(success/total*100):.2f}%" if total else 'N/A'
    print(f"\nCloud Account Name: {name}")
    print(f"Agentless Last Scan: {last_scan_str} / {last_scan_est_str}")
    print(f"Total Host Resources: {total}")
    print(f"Total Host Resources Scanned Successfully    : {success}")
    print(f"Total Host Resources Scanned with Issues: {issues}")
    print(f"Total Host Resources Scanned Excluded: {excluded}")
    print(f"Total Host Resources Scanned Unsupported: {unsupported}")
    print(f"Scan Coverage: {coverage_pct}")

def main():
    config = load_config()
    api_key = config['api_key']
    api_secret = config['api_secret']
    api_url = config['api_url'].rstrip('/')
    scan_results_url = config['console_scan_results_url']
    agentless_progress_url = config['console_agentless_progress_url']

    token = get_auth_token(api_url, api_key, api_secret)
    accounts = get_cloud_accounts(api_url, token)
    if not accounts:
        sys.exit("No cloud accounts found.")
    chosen_accounts = select_accounts(accounts)
    for acc in chosen_accounts:
        acc_id = acc.get('id', acc.get('accountId', 'UNKNOWN'))
        scan_rules = get_scan_rules(scan_results_url, token, acc_id)
        agentless_progress = get_agentless_progress(agentless_progress_url, token, acc_id)
        summarize_scan(acc, scan_rules, agentless_progress)

if __name__ == '__main__':
    main()
