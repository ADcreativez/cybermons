import requests
import json

api_key = "29pdc7qri3raxlwbzo8bl9brr7sf16hd0rw6yikq07exg7gtjdfpaypjxors94r8"
url = "http://test-phishing.com"

scan_url = "https://checkphish.ai/api/v2/scan"
payload = {"apiKey": api_key, "urlInfo": {"url": url}}
headers = {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}

try:
    resp = requests.post(scan_url, json=payload, headers=headers)
    print(f"Status Code: {resp.status_code}")
    print(f"Response Body: {resp.text}")
except Exception as e:
    print(f"Error: {e}")
