import json
import os
import re
from datetime import datetime
from ..extensions import db
from ..models import SystemLog, Inventory, Threat, DismissedAlert
from flask_login import current_user
from sqlalchemy import or_, and_

DARKWEB_CONFIG_FILE = 'darkweb_config.json'
FEED_FILE = 'feeds.json'
DEFAULT_FEEDS = [
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.us-cert.gov/ncas/alerts.xml",
    "https://threatpost.com/feed/",
    "https://www.ransomware.live/rss.xml"
]

def load_darkweb_config():
    # Use instance folder path if available, or current dir
    config_path = os.path.join(os.getcwd(), DARKWEB_CONFIG_FILE)
    defaults = {
        'hibp_api_key': '', 'intelx_api_key': '', 'hudsonrock_api_key': '',
        'abuse_ch_api_key': '', 'vt_api_key': '', 'abuseipdb_api_key': '',
        'checkphish_api_key': '', 'urlscan_api_key': '',
        'show_credentials': True, 'show_ransomware': True, 'show_paste': True,
        'show_stealer': True, 'show_passwords': True, 'show_infra': True,
        'show_defacements': True, 'show_ioc_intel': True, 'show_wayback': True,
        'show_infra_recon': True,
        'show_breach_intel': True,
        'sync_interval': 360
    }
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            try:
                data = json.load(f)
                return {**defaults, **data}
            except:
                return defaults
    return defaults

def save_darkweb_config(config):
    config_path = os.path.join(os.getcwd(), DARKWEB_CONFIG_FILE)
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=4)

def load_feeds():
    feeds = []
    feed_path = os.path.join(os.getcwd(), FEED_FILE)
    if os.path.exists(feed_path):
        try:
            with open(feed_path, 'r') as f:
                data = json.load(f)
                if data and isinstance(data, list):
                    if not data: feeds = []
                    elif isinstance(data[0], str):
                        feeds = [{"url": url, "status": "Unknown", "last_checked": None, "category": "threat"} for url in data]
                    else:
                        feeds = data
                        for feed in feeds:
                            if 'category' not in feed: feed['category'] = 'threat'
                else:
                    feeds = [{"url": url, "status": "Unknown", "last_checked": None, "category": "threat"} for url in DEFAULT_FEEDS]
        except:
             feeds = [{"url": url, "status": "Unknown", "last_checked": None, "category": "threat"} for url in DEFAULT_FEEDS]
    else:
        feeds = [{"url": url, "status": "Unknown", "last_checked": None, "category": "threat"} for url in DEFAULT_FEEDS]
    return feeds

def save_feeds(feeds):
    feed_path = os.path.join(os.getcwd(), FEED_FILE)
    with open(feed_path, 'w') as f:
        json.dump(feeds, f, indent=4)

def log_event(message, category='info'):
    new_log = SystemLog(
        message=message,
        category=category,
        user_id=current_user.id if current_user.is_authenticated else None
    )
    db.session.add(new_log)
    db.session.commit()

def determine_severity(title, summary, category='threat'):
    clean_summary = re.sub(r'<[^>]*>', ' ', summary) if summary else ''
    title_lower = title.lower() if title else ''
    summary_lower = clean_summary.lower()
    combined = f"{title_lower} {summary_lower}"
    
    # 1. Check for explicit "N/A" or "0.0" score first
    if re.search(r'\b0\.0\b\s*(na|n/a)?', combined) or 'severity: n/a' in combined or 'score: n/a' in combined or 'severity: unknown' in combined:
        return 'Info'

    # 2. News Category (Specific heuristic for headlines)
    if category == 'news':
        critical_news = ['zero-day', '0-day', 'fbi', 'police', 'dismantle', 'takedown', 'emergency patch', 'breach', 'actively exploited']
        if any(re.search(rf'\b{kw}\b', combined) for kw in critical_news): return 'Critical'
        high_news = ['apt', 'lazarus', 'campaign', 'nation-state', 'ransomware', 'massive', 'millions', 'malware']
        if any(re.search(rf'\b{kw}\b', combined) for kw in high_news): return 'High'
        medium_news = ['phishing', 'warning', 'disclosure', 'leak', 'hacker', 'exploit']
        if any(re.search(rf'\b{kw}\b', combined) for kw in medium_news): return 'Medium'
        return 'Info'

    # 3. Explicit Labels/Scores (Priority 1)
    label_matches = re.search(r'\b(?:severity|rating|base severity|level)\b[:\s]*(?:v\d[\.\s]+)?(?:([\d.]+)\s*\|?\s*)?\b(critical|high|medium|low|info)\b', combined)
    if label_matches:
        if label_matches.group(1):
            try:
                score = float(label_matches.group(1))
                if score >= 9.0: return 'Critical'
                if score >= 7.0: return 'High'
                if score >= 4.0: return 'Medium'
                if score > 0: return 'Low'
                return 'Info'
            except: pass
        return label_matches.group(2).capitalize()

    # 3b. CVSS Score check (Priority 2)
    cvss_matches = re.findall(r'\b(?:cvss|base score|v3|v2)[:\s]*(\d+\.\d+)', combined)
    if cvss_matches:
        try:
            score = max(float(m) for m in cvss_matches)
            if score >= 9.0: return 'Critical'
            if score >= 7.0: return 'High'
            if score >= 4.0: return 'Medium'
            if score > 0: return 'Low'
            return 'Info'
        except: pass

    # 4. Ransomware/Sectors
    if 'ransomware' in combined or 'victim' in combined or 'just published' in combined:
        critical_sectors = ['banking', 'financial', 'bank', 'credit union', 'insurance', 'medical', 'healthcare', 'hospital', 'dental', 'biotech', 'pharma', 'government', 'military', 'police', 'ministry', 'federal', 'state', 'energy', 'utility', 'telecom', 'infrastructure', 'power', 'water']
        if any(re.search(rf'\b{sector}\b', combined) for sector in critical_sectors): return 'Critical'
        return 'High'

    # 5. Keywords (Priority 3)
    critical_keywords = ['critical', 'zero-day', '0-day', 'rce', 'unauthenticated', 'emergency', 'active exploit', 'actively exploited']
    high_keywords = ['high', 'out-of-band', 'privilege escalation', 'massive']
    medium_keywords = ['medium', 'warning', 'patch', 'vulnerability', 'dos', 'denial of service', 'unauthorized access', 'exploit']
    low_keywords = ['low', 'disclosure', 'minor', 'notice']

    if any(re.search(rf'\b{kw}\b', combined) for kw in critical_keywords): return 'Critical'
    if any(re.search(rf'\b{kw}\b', combined) for kw in high_keywords): return 'High'
    if any(re.search(rf'\b{kw}\b', combined) for kw in medium_keywords): return 'Medium'
    if any(re.search(rf'\b{kw}\b', combined) for kw in low_keywords): return 'Low'
    
    # 6. Exploit Category
    if category == 'exploit':
        critical_exploit = ['rce', 'zero-day', '0-day', 'unauthenticated', 'remote code execution', 'kernel', 'root']
        if any(re.search(rf'\b{kw}\b', combined) for kw in critical_exploit): return 'Critical'
        high_exploit = ['exploit', 'poc', 'privilege escalation', 'bypass', 'authenticated']
        if any(re.search(rf'\b{kw}\b', combined) for kw in high_exploit): return 'High'
        return 'Medium'

    # 7. Fallback for CVEs
    if 'cve' in combined: return 'Medium'
    return 'Info'

def get_inventory_alerts(group_id, severity=None):
    if not group_id: return []
    dismissed_ids = [d.threat_id for d in DismissedAlert.query.filter_by(group_id=group_id).all()]
    group_inventory = Inventory.query.filter_by(group_id=group_id).all()
    alerts = []
    for item in group_inventory:
        brand_lower = item.brand.lower()
        module_lower = item.module.lower()
        query = Threat.query.filter(or_(
            and_(Threat.title.ilike(f"%{brand_lower}%"), Threat.title.ilike(f"%{module_lower}%")),
            and_(Threat.summary.ilike(f"%{brand_lower}%"), Threat.summary.ilike(f"%{module_lower}%"))
        ))
        if severity: query = query.filter(Threat.severity.ilike(severity))
        if dismissed_ids: query = query.filter(Threat.id.notin_(dismissed_ids))
        matches = query.all()
        for match in matches:
            alerts.append({
                'inventory_item': f"{item.brand} {item.module} {item.version if item.version else ''}".strip(),
                'threat': match
            })
    
    # Sort alerts by threat published date DESC (Newest first)
    alerts.sort(key=lambda x: x['threat'].published, reverse=True)
    return alerts

def normalize_url(url):
    """Ensure URL has a protocol prefix (https://) if missing."""
    if not url or url == '#': return '#'
    url = url.strip()
    # Check if starts with a known protocol
    if not re.match(r'^[a-z]+://', url, re.I):
        # Default to https:// if missing
        return f"https://{url}"
    return url

def find_binary(name):
    """
    Search for a binary in three locations:
    1. Workspace ./bin/ folder (Private Env)
    2. Virtual Environment bin/ folder
    3. System PATH
    """
    import shutil
    # 1. Project local bin
    local_bin = os.path.join(os.getcwd(), 'bin', name)
    if os.path.exists(local_bin) and os.access(local_bin, os.X_OK):
        return local_bin
    
    # 2. Venv bin
    venv_bin = os.path.join(os.getcwd(), 'venv', 'bin', name)
    if os.path.exists(venv_bin) and os.access(venv_bin, os.X_OK):
        return venv_bin
        
    # 3. System Path
    return shutil.which(name)
