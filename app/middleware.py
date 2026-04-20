import requests
from flask import request, abort
from .extensions import db
from .models import IPAccessControl, GeoSettings, BlockedCountry, VisitorLog
from .utils.helpers import log_event

knock_tracker = {}

def security_check():
    if request.path.startswith('/static/'): return
    client_ip = request.remote_addr
    if client_ip in ['127.0.0.1', '::1']: return

    # --- SECRET KNOCK LOGIC ---
    geo_settings = GeoSettings.query.first()
    secret_key = geo_settings.secret_knock_key if geo_settings else '1337'
    secret_path = f"/path/to/cybermon/{secret_key}"

    if request.path == secret_path:
        stats = knock_tracker.get(client_ip, {'count': 0})
        stats['count'] += 1
        knock_tracker[client_ip] = stats
        
        if stats['count'] >= 3:
            # Auto-whitelist
            existing = IPAccessControl.query.filter_by(ip=client_ip, category='whitelist').first()
            if not existing:
                new_whitelist = IPAccessControl(ip=client_ip, category='whitelist', reason="SECRET KNOCK SUCCESS")
                db.session.add(new_whitelist)
                db.session.commit()
                log_event(f"SECRET KNOCK: IP {client_ip} has been auto-whitelisted.", "warning")
            
            knock_tracker[client_ip] = {'count': 0}
            return "AUTHENTICATION SUCCESS: IP Whitelisted. Please reload the application."
        
        abort(404) # Hide existence until 3rd knock
    else:
        # Reset knock if other path accessed (consecutive required)
        if client_ip in knock_tracker:
            knock_tracker[client_ip] = {'count': 0}
    # --------------------------

geo_cache = {}

def get_ip_country(ip):
    if not ip or ip == '127.0.0.1' or ip == '::1':
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

    whitelisted = IPAccessControl.query.filter_by(ip=client_ip, category='whitelist').first()
    
    # Check for Strict IP Mode
    geo_settings = GeoSettings.query.first()
    is_strict = geo_settings.is_strict_ip_mode if geo_settings else False
    
    if is_strict:
        if not whitelisted:
            abort(403, description="STRICT MODE: Access restricted to whitelisted IP addresses only.")
        return # Whitelisted in strict mode is ALWAYS allowed

    if whitelisted: return

    blacklisted = IPAccessControl.query.filter_by(ip=client_ip, category='blacklist').first()
    if blacklisted:
        abort(403, description="Your IP has been blacklisted due to suspicious activity.")

    country_code, country_name = get_ip_country(client_ip)
    if country_code:
        geo_settings = GeoSettings.query.first()
        is_whitelist = geo_settings.is_whitelist_mode if geo_settings else False
        is_blocked = False
        if is_whitelist:
            allowed = BlockedCountry.query.filter_by(country_code=country_code).first()
            if not allowed: is_blocked = True
        else:
            blocked = BlockedCountry.query.filter_by(country_code=country_code).first()
            if blocked: is_blocked = True
        if is_blocked:
            abort(403, description=f"Access from your location ({country_name}) is currently restricted.")

    ua = request.headers.get('User-Agent', '')
    is_malicious = False
    block_reason = ""
    if is_bot_request(ua):
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
        abort(403, description=block_reason)

    ua_parsed = request.user_agent
    new_log = VisitorLog(
        ip=client_ip, user_agent=ua,
        device=ua_parsed.platform or 'Unknown', os=ua_parsed.platform or 'Unknown',
        browser=f"{ua_parsed.browser or 'Unknown'} ({country_code})" if country_code else (ua_parsed.browser or 'Unknown'),
        path=request.path, method=request.method
    )
    db.session.add(new_log)
    db.session.commit()
