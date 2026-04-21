import requests
from flask import request, abort
from .extensions import db
from .models import IPAccessControl, GeoSettings, BlockedCountry, VisitorLog
from .utils.helpers import log_event
from user_agents import parse

knock_tracker = {}
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
    bot_keywords = ['bot', 'crawler', 'spider', 'slurp', 'search', 'fetch', 'nmap', 'nikto', 'dirbuster', 'sqlmap', 'zaproxy', 'masscan', 'censys', 'shodan', 'python-requests', 'curl', 'wget']
    if not ua_string: return True
    ua_lower = ua_string.lower()
    return any(keyword in ua_lower for keyword in bot_keywords)

def security_check():
    if request.path.startswith('/static/'): return
    client_ip = request.remote_addr
    if client_ip in ['127.0.0.1', '::1']: return

    # --- 1. SETTINGS & CONTEXT ---
    geo_settings = GeoSettings.query.first()
    country_code, country_name = get_ip_country(client_ip)
    
    # --- 2. SECRET KNOCK LOGIC ---
    secret_key = geo_settings.secret_knock_key if geo_settings else '1337'
    secret_path = f"/path/to/cybermon/{secret_key}"
    knock_max = geo_settings.secret_knock_max if geo_settings else 3
    
    is_knock_path = (request.path == secret_path)
    
    if is_knock_path:
        stats = knock_tracker.get(client_ip, {'count': 0})
        stats['count'] += 1
        knock_tracker[client_ip] = stats
        
        if stats['count'] >= knock_max:
            # Auto-whitelist
            existing = IPAccessControl.query.filter_by(ip=client_ip, category='whitelist').first()
            if not existing:
                new_whitelist = IPAccessControl(ip=client_ip, category='whitelist', reason="SECRET KNOCK SUCCESS")
                db.session.add(new_whitelist)
                db.session.commit()
                log_event(f"SECRET KNOCK: IP {client_ip} has been auto-whitelisted.", "warning")
            
            knock_tracker[client_ip] = {'count': 0}
            return "AUTHENTICATION SUCCESS: IP Whitelisted. Please reload the application."
        
        # Log the knock and hide the existence
        log_visit(client_ip, country_code)
        abort(404) 
    else:
        # Reset knock if other path accessed (consecutive required)
        if client_ip in knock_tracker:
            knock_tracker[client_ip] = {'count': 0}

    # --- 3. ACCESS CONTROL (Whitelist/Blacklist/Geo) ---
    whitelisted = IPAccessControl.query.filter_by(ip=client_ip, category='whitelist').first()
    is_strict = geo_settings.is_strict_ip_mode if geo_settings else False
    
    if is_strict:
        if not whitelisted:
            log_visit(client_ip, country_code)
            abort(403, description="STRICT MODE: Access restricted to whitelisted IP addresses only.")
        return # Whitelisted in strict mode is ALWAYS allowed

    if whitelisted: return

    blacklisted = IPAccessControl.query.filter_by(ip=client_ip, category='blacklist').first()
    if blacklisted:
        log_visit(client_ip, country_code)
        abort(403, description="Your IP has been blacklisted due to suspicious activity.")

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

    # --- 4. BEHAVIORAL SECURITY (Bots/Malicious) ---
    ua_string = request.headers.get('User-Agent', '')
    is_malicious = False
    block_reason = ""
    
    if is_bot_request(ua_string):
        is_malicious = True
        block_reason = f"Bot signature detected."
        
    malicious_patterns = ['../', 'etc/passwd', '<script>', 'phpinfo', '.env', 'eval(', 'config.php']
    if any(pattern in request.path.lower() for pattern in malicious_patterns) or any(pattern in str(request.args).lower() for pattern in malicious_patterns):
        is_malicious = True
        block_reason = "Suspicious payload or path detected."

    if is_malicious:
        new_ban = IPAccessControl(ip=client_ip, category='blacklist', reason=block_reason)
        try:
            db.session.add(new_ban)
            db.session.commit()
            log_event(f"AUTO-BAN: IP {client_ip} blacklisted.", "danger")
        except:
            db.session.rollback()
        log_visit(client_ip, country_code)
        abort(403, description=block_reason)

    # --- 5. LOGGING ---
    log_visit(client_ip, country_code)

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
