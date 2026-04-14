import requests
import json
import time

api_key = "29pdc7qri3raxlwbzo8bl9brr7sf16hd0rw6yikq07exg7gtjdfpaypjxors94r8"
url = "http://test-phishing.com"

scan_url = "https://developers.bolster.ai/api/neo/scan"
payload = {"apiKey": api_key, "urlInfo": {"url": url}, "insights": True}
headers = {"Content-Type": "application/json", "User-Agent": "Cybermon/1.0"}

try:
    resp = requests.post(scan_url, json=payload, headers=headers)
    job_id = resp.json().get('jobID')
    if job_id:
        status_url = "https://developers.bolster.ai/api/neo/scan/status"
        for _ in range(5):
            time.sleep(2)
            s_resp = requests.post(status_url, json={"apiKey": api_key, "jobID": job_id, "insights": True}, headers=headers)
            data = s_resp.json()
            if data.get('status') == 'DONE':
                print(json.dumps(data, indent=2))
                break
    else:
        print(resp.text)
except Exception as e:
    print(f"Error: {e}")
