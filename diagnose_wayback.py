import sys
import re
import requests

def diagnose(domain):
    print(f"=== DIAGNOSING OSINT ENGINES FOR TARGET: {domain} ===")
    
    # 1. Archive.org CDX Wildcard Query
    archive_url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&limit=100&collapse=urlkey"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
    }
    
    print("\n[1] Testing Archive.org CDX API...")
    try:
        resp = requests.get(archive_url, headers=headers, timeout=10)
        print(f"    → HTTP Status: {resp.status_code}")
        if resp.status_code == 200:
            data = resp.json()
            print(f"    → Success! Retrieved {len(data) - 1 if len(data) > 0 else 0} results from Archive.org.")
            if len(data) > 1:
                print("    → Sample URLs:")
                for row in data[1:4]:
                    print(f"      - {row[2]}")
        else:
            print(f"    → Blocked/Failed: {resp.text[:200]}")
    except Exception as e:
        print(f"    → Error connecting to Archive.org: {str(e)}")

    # 2. AlienVault OTX Query
    otx_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=100"
    print("\n[2] Testing AlienVault OTX API...")
    try:
        resp = requests.get(otx_url, headers=headers, timeout=10)
        print(f"    → HTTP Status: {resp.status_code}")
        if resp.status_code == 200:
            data = resp.json()
            urls = data.get('url_list', [])
            print(f"    → Success! Retrieved {len(urls)} results from AlienVault.")
            if urls:
                print("    → Sample URLs:")
                for item in urls[:3]:
                    print(f"      - {item.get('url')}")
        else:
            print(f"    → Blocked/Failed: {resp.text[:200]}")
    except Exception as e:
        print(f"    → Error connecting to AlienVault: {str(e)}")

    # 3. Common Crawl Index Query
    print("\n[3] Testing Common Crawl CDX Index...")
    try:
        # Get latest index collection
        col_resp = requests.get("https://index.commoncrawl.org/collinfo.json", headers=headers, timeout=5)
        if col_resp.status_code == 200:
            latest_idx = col_resp.json()[0].get('id')
            print(f"    → Using latest Common Crawl Index: {latest_idx}")
            cc_url = f"https://index.commoncrawl.org/{latest_idx}?url=*.{domain}/*&output=json&limit=10"
            cc_resp = requests.get(cc_url, headers=headers, timeout=10)
            print(f"    → HTTP Status: {cc_resp.status_code}")
            if cc_resp.status_code == 200:
                lines = cc_resp.text.strip().splitlines()
                print(f"    → Success! Retrieved {len(lines)} results from Common Crawl.")
                if lines:
                    print("    → Sample URLs:")
                    for line in lines[:3]:
                        import json
                        print(f"      - {json.loads(line).get('url')}")
            else:
                print(f"    → Index query failed: {cc_resp.status_code}")
        else:
            print(f"    → Failed to fetch Common Crawl index metadata")
    except Exception as e:
        print(f"    → Error connecting to Common Crawl: {str(e)}")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "oto.co.id"
    diagnose(target)
