import requests
import time
from datetime import datetime, timedelta
from flask import request, abort
from .extensions import db
from .models import IPAccessControl, GeoSettings, BlockedCountry, VisitorLog
from .utils.helpers import log_event
from user_agents import parse

knock_tracker = {}
flood_tracker = {}
geo_cache = {}

def get_ip_country(ip):
    if not ip or ip in ['127.0.0.1', '::1']:
        return 'ID', 'Indonesia'
    if ip in geo_cache:
        return geo_cache[ip]
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode", timeout=3)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                res = (data.get('countryCode'), data.get('country'))
                geo_cache[ip] = res
                return res
    except: pass
    return None, None

def is_bot_request(ua_string):
    # Industrial Scanners & Modern Recon Tools
    bot_keywords = [
        'bot', 'crawler', 'spider', 'slurp', 'search', 'fetch', 
        'nmap', 'nikto', 'dirbuster', 'sqlmap', 'zaproxy', 'masscan', 'censys', 'shodan', 
        'python-requests', 'curl', 'wget',
        'nessus', 'acunetix', 'netsparker', 'appscan', 'burpsuite', 'gobuster', 'feroxbuster', 
        'nuclei', 'katana', 'ffuf', 'amass', 'subfinder'
    ]
    if not ua_string: return True
    ua_lower = ua_string.lower()
    return any(keyword in ua_lower for keyword in bot_keywords)

def security_check():
    if request.path.startswith('/static/'): return
    client_ip = request.remote_addr
    
    # 1. WHITELIST BYPASS (Localhost)
    if client_ip in ['127.0.0.1', '::1']: return

    # --- SETTINGS & CONTEXT ---
    geo_settings = GeoSettings.query.first()
    country_code, country_name = get_ip_country(client_ip)
    
    # --- 2. RATE LIMITER (ANTI-DDOS / BRUTE FORCE) ---
    rpm_limit = geo_settings.rate_limit_max if geo_settings else 60
    now_ts = time.time()
    ip_stats = flood_tracker.get(client_ip, {'count': 0, 'start_time': now_ts})
    
    if now_ts - ip_stats['start_time'] > 60:
        # Reset window
        ip_stats = {'count': 1, 'start_time': now_ts}
    else:
        ip_stats['count'] += 1
    
    flood_tracker[client_ip] = ip_stats
    
    if ip_stats['count'] > rpm_limit:
        auto_ban(client_ip, f"DDoS/Flood protection: {ip_stats['count']} RPM exceeded.", country_code)
        abort(429, description="Too many requests. Your IP has been temporarily flagged.")

    # --- 3. SECRET KNOCK LOGIC ---
    secret_key = geo_settings.secret_knock_key if geo_settings else '1337'
    secret_path = f"/path/to/cybermon/{secret_key}"
    knock_max = geo_settings.secret_knock_max if geo_settings else 3
    
    if request.path == secret_path:
        stats = knock_tracker.get(client_ip, {'count': 0})
        stats['count'] += 1
        knock_tracker[client_ip] = stats
        
        if stats['count'] >= knock_max:
            existing = IPAccessControl.query.filter_by(ip=client_ip, category='whitelist').first()
            if not existing:
                new_whitelist = IPAccessControl(ip=client_ip, category='whitelist', reason="SECRET KNOCK SUCCESS")
                db.session.add(new_whitelist)
                db.session.commit()
                log_event(f"SECRET KNOCK: IP {client_ip} has been auto-whitelisted.", "warning")
            knock_tracker[client_ip] = {'count': 0}
            return "AUTHENTICATION SUCCESS: IP Whitelisted. Please reload the application."
        
        log_visit(client_ip, country_code)
        abort(404) 
    else:
        if client_ip in knock_tracker:
            knock_tracker[client_ip] = {'count': 0}

    # --- 4. ACCESS CONTROL (Whitelist/Blacklist/Geo) ---
    whitelisted = IPAccessControl.query.filter_by(ip=client_ip, category='whitelist').first()
    is_strict = geo_settings.is_strict_ip_mode if geo_settings else False
    
    if is_strict and not whitelisted:
        log_visit(client_ip, country_code)
        abort(403, description="STRICT MODE: Access restricted to whitelisted IP addresses only.")
    
    if whitelisted: return

    blacklisted = IPAccessControl.query.filter_by(ip=client_ip, category='blacklist').first()
    if blacklisted:
        # Check Expiry Management
        if blacklisted.expires_at and blacklisted.expires_at < datetime.utcnow():
            db.session.delete(blacklisted)
            try:
                db.session.commit()
                log_event(f"AUTO-BAN EXPIRED: Access restored for IP {client_ip}.", "info")
            except:
                db.session.rollback()
        else:
            log_visit(client_ip, country_code)
            expiry_str = f" until {blacklisted.expires_at.strftime('%Y-%m-%d %H:%M')}" if blacklisted.expires_at else " permanently"
            abort(403, description=f"Your IP has been blacklisted{expiry_str} due to suspicious activity.")

    if country_code:
        is_whitelist_geo = geo_settings.is_whitelist_mode if geo_settings else False
        is_blocked = False
        if is_whitelist_geo:
            allowed = BlockedCountry.query.filter_by(country_code=country_code).first()
            if not allowed: is_blocked = True
        else:
            blocked = BlockedCountry.query.filter_by(country_code=country_code).first()
            if blocked: is_blocked = True
        
        if is_blocked:
            log_visit(client_ip, country_code)
            abort(403, description=f"Access from your location ({country_name}) is currently restricted.")

    # --- 5. HONEYPOT TRAPS ---
    honeypots = [
        '/.env', '/.git', '/wp-admin', '/phpmyadmin', '/config.php', 
        '/backup.sql', '/shell.php', '/.aws/credentials', '/admin/setup'
    ]
    if request.path.lower() in honeypots:
        auto_ban(client_ip, f"Honeypot Trap Triggered: {request.path}", country_code)
        abort(404)

    # --- 6. ADVANCED PAYLOAD MATCHING (WAF) ---
    ua_string = request.headers.get('User-Agent', '')
    payload = (request.path + str(request.args) + str(request.form)).lower()
    
    is_malicious = False
    block_reason = ""
    
    if is_bot_request(ua_string):
        is_malicious = True
        block_reason = "Industrial Scanner or Verification Tool detected."
    
    # Modern Attack Signatures
    signatures = {
        'XSS': ['<script>', 'alert(', 'onerror=', 'onload=', 'javascript:'],
        'SSTI': ['{{', '${', '@{', '#{', '{{7*7}}'],
        'SQLi': ['union select', 'order by', "' or '1'='1", '--', '/*', 'information_schema', 'drop table'],
        'CmdInj': ['; whoami', '&& whoami', '| whoami', '$(whoami)', 'etc/passwd', 'cat /']
    }
    
    for category, patterns in signatures.items():
        if any(p in payload for p in patterns):
            is_malicious = True
            block_reason = f"{category} Attack Pattern detected."
            break

    if is_malicious:
        # Industrial Scanner Header Check
        scanner_headers = ['X-Scanner', 'Acunetix-Aspect', 'X-Nessus-ID', 'X-Netsparker-Identify']
        if any(h in request.headers for h in scanner_headers):
            block_reason = "Confirmed Industrial Vulnerability Scanner detected via headers."

        auto_ban(client_ip, block_reason, country_code)
        abort(403, description=block_reason)

    # --- 7. SUCCESSFUL PASS ---
    log_visit(client_ip, country_code)

def auto_ban(ip, reason, country_code):
    geo_settings = GeoSettings.query.first()
    duration_days = geo_settings.auto_ban_duration if geo_settings else 0
    
    expires_at = None
    if duration_days > 0:
        expires_at = datetime.utcnow() + timedelta(days=duration_days)
        
    existing = IPAccessControl.query.filter_by(ip=ip, category='blacklist').first()
    if not existing:
        new_ban = IPAccessControl(ip=ip, category='blacklist', reason=reason, expires_at=expires_at)
        try:
            db.session.add(new_ban)
            db.session.commit()
            log_event(f"AUTO-BAN: IP {ip} blacklisted for {reason}. Expiry: {expires_at or 'Permanent'}", "danger")
        except:
            db.session.rollback()
    elif expires_at:
        # Update expiry if already blacklisted
        existing.expires_at = expires_at
        existing.reason = reason
        try:
            db.session.commit()
        except:
            db.session.rollback()
            
    log_visit(ip, country_code)

def log_visit(ip, country_code):
    ua_string = request.headers.get('User-Agent', '')
    parsed_ua = parse(ua_string)

    device_info = f"{'Mobile' if parsed_ua.is_mobile else 'Tablet' if parsed_ua.is_tablet else 'PC'} / {parsed_ua.device.family}"
    os_info = f"{parsed_ua.os.family} {parsed_ua.os.version_string}".strip()
    browser_info = f"{parsed_ua.browser.family} {parsed_ua.browser.version_string}".strip()
    if country_code:
        browser_info += f" ({country_code})"

    new_log = VisitorLog(
        ip=ip, user_agent=ua_string,
        device=device_info[:100], 
        os=os_info[:100],
        browser=browser_info[:100],
        path=request.path, method=request.method
    )
    db.session.add(new_log)
    try:
        db.session.commit()
    except:
        db.session.rollback()
