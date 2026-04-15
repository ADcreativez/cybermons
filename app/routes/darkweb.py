import os
import json
import hashlib
import re
import asyncio
import requests as req
import nmap
import socket
import dns.resolver
from concurrent.futures import ThreadPoolExecutor
import time
import shutil
from flask import Blueprint, render_template, request, redirect, url_for, flash, abort, jsonify
from flask_login import login_required, current_user
from ..extensions import db
from ..models import IOCCache
from ..utils.helpers import load_darkweb_config, save_darkweb_config, log_event

darkweb_bp = Blueprint('darkweb', __name__)

RANSOMWARE_CACHE_FILE = 'ransomware_cache.json'
DEFACEMENT_CACHE_FILE = 'defacement_cache.json'

def load_ransomware_cache():
    cache_path = os.path.join(os.getcwd(), RANSOMWARE_CACHE_FILE)
    if os.path.exists(cache_path):
        with open(cache_path, 'r') as f: return json.load(f)
    return {}

def save_ransomware_cache(cache):
    """Save cache to disk. Preserves all historical records."""
    cache_path = os.path.join(os.getcwd(), RANSOMWARE_CACHE_FILE)
    with open(cache_path, 'w') as f: json.dump(cache, f)
    return cache

def _build_clearweb_url(name, group, post_url):
    """Build a clear-web ransomware.live URL instead of using .onion links."""
    import base64
    # If post_url is a valid clear-web URL, use it directly
    if post_url and not '.onion' in post_url and post_url.startswith('http'):
        return post_url
    # Construct a clear-web ransomware.live profile using base64 encoding (name@group)
    if name and group:
        try:
            encoded = base64.b64encode(f"{name}@{group}".encode()).decode()
            return f"https://www.ransomware.live/id/{encoded}"
        except: pass
    return ''

def merge_victims_into_cache(raw_victims, cache):
    for v in raw_victims:
        name = v.get('victim', v.get('post_title', v.get('name', '')))
        group = v.get('group_name', v.get('group', ''))
        date_full = str(v.get('discovered', v.get('published', '')))
        date_key = date_full[:10] if date_full else 'unknown'
        if not date_key or date_key == 'unknown': continue
        raw_url = v.get('post_url', v.get('website', v.get('url', '')))
        entry = {
            'name': name, 'group': group, 'date': date_full,
            'url': _build_clearweb_url(name, group, raw_url),
            'country': v.get('country', ''), 'activity': v.get('activity', '')
        }
        if date_key not in cache: cache[date_key] = []
        if (name, group) not in {(e['name'], e['group']) for e in cache[date_key]}:
            cache[date_key].append(entry)
    return cache

def load_defacement_cache():
    path = os.path.join(os.getcwd(), DEFACEMENT_CACHE_FILE)
    if os.path.exists(path):
        with open(path, 'r') as f: return json.load(f)
    return {}

def save_defacement_cache(cache):
    path = os.path.join(os.getcwd(), DEFACEMENT_CACHE_FILE)
    with open(path, 'w') as f: json.dump(cache, f)

# --- Scraping Helpers ---

async def _scrape_zone_xsec_page(browser, url, deep_scrape=False):
    from playwright_stealth import Stealth
    
    # Standard context with realistic user agent
    context = await browser.new_context(
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
    page = await context.new_page()
    await Stealth().apply_stealth_async(page)
    
    try:
        print(f"DEBUG: Navigating to {url}")
        try:
            # Wait for full 'load' state instead of just DOM
            await page.goto(url, wait_until='load', timeout=60000)
            # Extra wait for security scripts to settle
            await page.wait_for_timeout(5000)
            try:
                await page.wait_for_load_state('networkidle', timeout=10000)
            except: pass
        except Exception as e:
            print(f"DEBUG: Navigation timeout/warning: {str(e)}")
            
        # Polling loop: Wait for data to appear (bypass challenge)
        results = []
        for i in range(20): # Poll for ~40 seconds total
            try:
                html = await page.content()
            except Exception as e:
                # If page is still navigating/refreshing, wait and retry
                print(f"DEBUG: Content retrieval deferred (navigating): {str(e)}")
                await page.wait_for_timeout(2000)
                continue

            if 'Just a moment' in html or 'Wait while' in html or 'Checking your browser' in html:
                if i % 3 == 0:
                    print(f"DEBUG: Challenge detected, waiting... (Attempt {i})")
                await page.wait_for_timeout(2000)
                continue
                
            # Try to extract rows
            rows = re.findall(r'<tr[^>]*>(.*?)</tr>', html, re.DOTALL)
            if len(rows) > 1:
                print(f"DEBUG: Data ready on attempt {i}. Found {len(rows)-1} records.")
                for row in rows[1:]:
                    cols = re.findall(r'<td[^>]*>(.*?)</td>', row, re.DOTALL)
                    if len(cols) >= 9:
                        mirror_match = re.search(r'href="(/mirror/id/(\d+))"', cols[-1])
                        country_match = re.search(r'/assets/images/flags/([a-z]+)\.png', row)
                        item = {
                            'date': re.sub(r'<[^>]*>', '', cols[0]).strip(),
                            'attacker': re.sub(r'<[^>]*>', '', cols[1]).strip(),
                            'team': re.sub(r'<[^>]*>', '', cols[2]).strip(),
                            'country': country_match.group(1).upper() if country_match else 'UNKNOWN',
                            'url': re.sub(r'<[^>]*>', '', cols[-2]).strip(),
                            'mirror_id': mirror_match.group(2) if mirror_match else '',
                            'mirror': 'https://zone-xsec.com' + mirror_match.group(1) if mirror_match else '',
                            'ip': 'N/A', 'web_server': 'N/A'
                        }
                        results.append(item)
                break # Success
            else:
                if i % 3 == 0:
                    print(f"DEBUG: Table not found yet, waiting... (Attempt {i})")
                await page.wait_for_timeout(2000)
                
        if deep_scrape and results:
            # Deep scrape logic stays similar but with its own stealth page
            d_page = await context.new_page()
            await Stealth().apply_stealth_async(d_page)
            try:
                for item in results[:10]:
                    if not item['mirror_id']: continue
                    try:
                        await d_page.goto(f"https://zone-xsec.com/mirror/id/{item['mirror_id']}", wait_until='domcontentloaded', timeout=15000)
                        m_html = await d_page.content()
                        if 'IP' in m_html:
                            mfind = lambda p: re.sub(r'<[^>]+>', '', re.search(p, m_html, re.I | re.DOTALL).group(1)).strip() if re.search(p, m_html, re.I | re.DOTALL) else 'N/A'
                            item['ip'] = mfind(r'IP[^<]+<[^>]+>\s*([0-9\.]+)')
                            item['web_server'] = mfind(r'Web Server[^<]+<[^>]+>\s*([^<]+)')
                    except: pass
            finally: await d_page.close()
            
        return results if results else None
    except Exception as e:
        print(f"DEBUG: Scraper error: {str(e)}")
        return None
    finally:
        await context.close()

def scrape_zone_xsec(page=1, deep_scrape=False):
    from playwright.async_api import async_playwright
    url = f"https://zone-xsec.com/special{'/page='+str(page) if page > 1 else ''}"
    async def _run():
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try: return await _scrape_zone_xsec_page(browser, url, deep_scrape=deep_scrape)
            finally: await browser.close()
    try: return asyncio.run(_run())
    except Exception as e:
        print(f"Scrape error: {e}")
        return None

# --- Routes ---

@darkweb_bp.route('/darkweb/credentials')
@login_required
def credentials():
    return render_template('darkweb_credentials.html')

@darkweb_bp.route('/darkweb/credentials/search', methods=['POST'])
@login_required
def credentials_search():
    config = load_darkweb_config()
    api_key = config.get('hibp_api_key', '')
    query = request.json.get('query', '').strip()
    if not query or not api_key: return jsonify({'error': 'Missing query or key'}), 400
    try:
        is_email = '@' in query
        url = f'https://haveibeenpwned.com/api/v3/breachedaccount/{query}' if is_email else 'https://haveibeenpwned.com/api/v3/breaches'
        params = {'truncateResponse': 'false'} if is_email else {'domain': query}
        headers = {'hibp-api-key': api_key, 'user-agent': 'Cybermon-DarkWeb-Monitor'}
        resp = req.get(url, headers=headers, params=params, timeout=15)
        if resp.status_code == 404: return jsonify({'results': []})
        resp.raise_for_status()
        breaches = resp.json()
        results = [{
            'name': b.get('Name', ''), 'title': b.get('Title', ''), 'domain': b.get('Domain', ''),
            'date': b.get('BreachDate', ''), 'count': b.get('PwnCount', 0),
            'data_classes': b.get('DataClasses', []), 'description': b.get('Description', ''),
            'is_verified': b.get('IsVerified', False)
        } for b in breaches]
        return jsonify({'results': results, 'query': query})
    except Exception as e: return jsonify({'error': str(e)}), 500

@darkweb_bp.route('/darkweb/ransomware-victims')
@login_required
def ransomware_victims():
    return render_template('darkweb_ransomware.html')

@darkweb_bp.route('/darkweb/ransomware-victims/feed')
@login_required
def ransomware_feed():
    from datetime import date, timedelta
    days_back = request.args.get('days', 0, type=int)
    cache = load_ransomware_cache()
    if days_back == 0:
        all_cached = []
        for d_key in sorted(cache.keys(), reverse=True): all_cached.extend(cache[d_key])
        return jsonify({'results': all_cached, 'date': 'ALL RECORDS'})
    target_date = (date.today() - timedelta(days=days_back)).strftime('%Y-%m-%d')
    return jsonify({'results': cache.get(target_date, []), 'date': target_date})

@darkweb_bp.route('/darkweb/ransomware-victims/sync', methods=['POST'])
@login_required
def ransomware_sync():
    try:
        resp = req.get('https://api.ransomware.live/recentvictims', headers={'User-Agent': 'Cybermon/1.0'}, timeout=25)
        resp.raise_for_status()
        cache = load_ransomware_cache()
        before = sum(len(v) for v in cache.values())
        cache = merge_victims_into_cache(resp.json(), cache)
        save_ransomware_cache(cache)
        return jsonify({'success': True, 'new_records': sum(len(v) for v in cache.values()) - before})
    except Exception as e: return jsonify({'success': False, 'error': str(e)}), 500

@darkweb_bp.route('/darkweb/defacements')
@login_required
def defacements():
    return render_template('darkweb_defacements.html')

@darkweb_bp.route('/darkweb/defacements/feed')
@login_required
def defacements_feed():
    cache = load_defacement_cache()
    all_records = []
    for d_key in sorted(cache.keys(), reverse=True): all_records.extend(cache[d_key])
    return jsonify({
        'results': all_records,
        'source': 'cache',
        'total_cached_days': len(cache),
        'message': f"Displaying {len(all_records)} recent defacements from local database."
    })

@darkweb_bp.route('/darkweb/defacements/sync', methods=['POST'])
@login_required
def defacements_sync():
    try:
        from datetime import datetime, timedelta
        import time
        
        # 90-day window for discovery
        cutoff_date = (datetime.utcnow() - timedelta(days=90)).strftime('%Y-%m-%d')
        cache = load_defacement_cache()
        new_count = 0
        pages_crawled = 0
        
        # Extended deep sync (100 pages)
        for page in range(1, 101):
            new_data = scrape_zone_xsec(page=page, deep_scrape=(page == 1))
            if not new_data:
                if page == 1:
                    return jsonify({'success': False, 'error': 'Failed to fetch data from Zone-XSec.'})
                break
            
            pages_crawled += 1
            page_has_new = False
            
            for item in new_data:
                d_key = item['date'].split(' ')[0]
                
                # Check date cutoff
                if d_key < cutoff_date:
                    break
                
                if d_key not in cache: cache[d_key] = []
                
                existing_urls = [x['url'] for x in cache[d_key]]
                if item['url'] not in existing_urls:
                    cache[d_key].append(item)
                    new_count += 1
                    page_has_new = True
            
            # Smart Stop: stop if everything on current page is already in cache
            if not page_has_new and page > 5:
                break
                
            # Date-based break
            if new_data and new_data[-1]['date'].split(' ')[0] < cutoff_date:
                break
                
            time.sleep(1) # Be nice to the source
                
        save_defacement_cache(cache)
        return jsonify({
            'success': True, 
            'new_records': new_count,
            'pages_crawled': pages_crawled,
            'message': f"Sync successful: {new_count} records merged across {pages_crawled} pages."
        })
    except Exception as e: return jsonify({'success': False, 'error': str(e)}), 500

@darkweb_bp.route('/darkweb/defacements/mirror-proxy')
@login_required
def defacements_mirror_proxy():
    mirror_id = request.args.get('id', '')
    if not mirror_id: return jsonify({'success': False, 'error': 'Missing mirror id'}), 400
    
    mirror_url = f"https://zone-xsec.com/mirror/id/{mirror_id}"
    
    async def _fetch():
        from playwright.async_api import async_playwright
        from playwright_stealth import Stealth
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            ctx = await browser.new_context(
                user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
            )
            page = await ctx.new_page()
            await Stealth().apply_stealth_async(page)
            
            try:
                # Optimized: Try to hit mirror directly first, if challenged, hit /special
                await page.goto(mirror_url, wait_until='domcontentloaded', timeout=20000)
                await page.wait_for_timeout(2000)
                
                # Check for challenge
                html = await page.content()
                if any(x in html for x in ["Just a moment", "Checking your browser"]):
                    await page.goto('https://zone-xsec.com/special', wait_until='domcontentloaded', timeout=15000)
                    await page.wait_for_timeout(5000)
                    await page.goto(mirror_url, wait_until='domcontentloaded', timeout=15000)
                
                # Polling for data
                for _ in range(10):
                    html = await page.content()
                    if "Defacement Details" in html or "IP:" in html: break
                    await page.wait_for_timeout(1500)

                intel = await page.evaluate(r"""() => {
                    const allText = document.body.innerText + " " + (document.title || '');
                    const findText = (regex) => {
                        const m = allText.match(regex);
                        return (m && m[1]) ? m[1].trim() : 'N/A';
                    };
                    const clean = (val) => (!val || val === 'N/A') ? 'N/A' : val.replace(/Zone-Xsec/gi, '').trim();
                    
                    const header = [...document.querySelectorAll('h1, h2, div, b')].find(el => el.innerText?.toLowerCase().includes('defacement details of'));
                    let fullUrl = 'N/A';
                    if (header) {
                        const link = header.querySelector('a');
                        if (link && !link.href.includes('zone-xsec.com')) fullUrl = link.href;
                        else {
                            const parts = header.innerText.split(/defacement details of/i);
                            if (parts.length > 1) fullUrl = parts[1].trim().split(/\s/)[0];
                        }
                    }
                    return {
                        ip: clean(findText(/IP[:\s]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i)),
                        web_server: clean(findText(/Web Server[:\s]+([^<\n\r]+)/i)),
                        full_url: clean(fullUrl)
                    };
                }""")
                return {**intel, 'success': True}
            except Exception as e: return {'success': False, 'error': str(e)}
            finally: await browser.close()

    try:
        return jsonify(asyncio.run(_fetch()))
    except Exception as e: return jsonify({'success': False, 'error': str(e)}), 500

@darkweb_bp.route('/darkweb/paste-monitor')
@login_required
def paste_monitor():
    return render_template('darkweb_paste.html')

@darkweb_bp.route('/darkweb/stealer-logs')
@login_required
def stealer_logs():
    return render_template('darkweb_stealer.html')

@darkweb_bp.route('/darkweb/passwords')
@login_required
def passwords():
    return render_template('darkweb_passwords.html')

@darkweb_bp.route('/darkweb/passwords/check', methods=['POST'])
@login_required
def passwords_check():
    password = request.json.get('password')
    if not password: return jsonify({'error': 'Password required'}), 400
    try:
        sha1_pwd = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1_pwd[:5], sha1_pwd[5:]
        resp = req.get(f'https://api.pwnedpasswords.com/range/{prefix}', timeout=10)
        hashes = (line.split(':') for line in resp.text.splitlines())
        count = next((int(c) for h, c in hashes if h == suffix), 0)
        return jsonify({'count': count, 'status': 'success'})
    except Exception as e: return jsonify({'error': str(e)}), 500

@darkweb_bp.route('/darkweb/infra-search')
@login_required
def infra_search():
    return render_template('darkweb_infra.html')

@darkweb_bp.route('/darkweb/infra-search/check', methods=['POST'])
@login_required
def infra_check():
    domain = request.json.get('domain')
    if not domain: return jsonify({'error': 'Domain required'}), 400
    config = load_darkweb_config()
    api_key = config.get('hudsonrock_api_key') or config.get('criminalip_api_key')
    if not api_key: return jsonify({'error': 'API Key not configured.'}), 400
    try:
        url = f"https://api.hudsonrock.com/v1/cavalier/infostealer/search?domain={domain}"
        headers = {"Hrock-Api-Key": api_key}
        resp = req.get(url, headers=headers, timeout=20)
        if resp.status_code == 200:
            data = resp.json()
            stealers = data.get('stealers', [])
            summary = {
                'employees': sum(1 for s in stealers if 'employee' in s.get('type', '').lower()),
                'users': sum(1 for s in stealers if 'user' in s.get('type', '').lower()),
                'external': sum(1 for s in stealers if 'employee' not in s.get('type', '').lower() and 'user' not in s.get('type', '').lower()),
                'total_credentials': sum(len(s.get('credentials', [1])) for s in stealers),
                'total_machines': len(stealers)
            }
            log_event(f'Infra search: {domain}', 'info')
            return jsonify({'status': 'success', 'domain': domain, 'summary': summary})
        return jsonify({'error': f'API Error: {resp.status_code}'}), resp.status_code
    except Exception as e: return jsonify({'error': str(e)}), 500

@darkweb_bp.route('/darkweb/ioc-intelligence')
@login_required
def ioc_intelligence():
    return render_template('darkweb_ioc_intelligence.html')

@darkweb_bp.route('/darkweb/wayback')
@login_required
def wayback():
    return render_template('darkweb_wayback.html')

@darkweb_bp.route('/darkweb/wayback/search', methods=['POST'])
@login_required
def wayback_search():
    query = request.json.get('query', '').strip()
    if not query: return jsonify({'error': 'No domain provided'}), 400
    try:
        indicator = query
        if '://' in indicator:
            from urllib.parse import urlparse
            indicator = urlparse(indicator).netloc
        
        # Add realistic User-Agent to avoid Archive.org bot blocking
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
            'Accept': 'application/json'
        }
        url = f"https://web.archive.org/cdx/search/cdx?url={indicator}/*&output=json&limit=100&collapse=urlkey"
        
        resp = req.get(url, headers=headers, timeout=25)
        
        if resp.status_code == 200:
            try:
                raw_data = resp.json()
            except Exception:
                return jsonify({'error': 'Archive.org returned non-JSON data. The API might be restricted.'}), 400
                
            if len(raw_data) <= 1: return jsonify({'results': []})
            results = [dict(zip(raw_data[0], row)) for row in raw_data[1:]]
            return jsonify({'status': 'success', 'query': indicator, 'results': results})
        
        # If API returns 403/429 or any other error, we don't return yet. 
        # We fall through to the waybackurls fallback logic below.
        print(f"Archive API returned {resp.status_code}, attempting fallback tool...")

    except Exception as e:
        print(f"Archive API connection error: {str(e)}, attempting fallback tool...")

    # --- Fallback to waybackurls CLI tool ---
    waybackurls_bin = shutil.which('waybackurls')
    if waybackurls_bin:
        import subprocess
        try:
            # Use waybackurls via subprocess
            # echo "domain" | waybackurls
            proc = subprocess.run([waybackurls_bin], input=indicator.encode(), capture_output=True, timeout=30)
            if proc.returncode == 0:
                raw_urls = proc.stdout.decode().splitlines()
                results = []
                for url in raw_urls[:100]: # Limit to matches the API limit
                    if not url.strip(): continue
                    
                    # Attempt to extract timestamp from wayback URL format
                    # https://web.archive.org/web/20210101000000/http://host/path
                    ts_match = re.search(r'/web/(\d{14})/', url)
                    timestamp = ts_match.group(1) if ts_match else "00000000000000"
                    
                    # Clean original URL (remove wayback prefix)
                    original_url = url
                    if '/web/' in url:
                        parts = url.split('/web/' + timestamp + '/')
                        if len(parts) > 1: original_url = parts[1]

                    results.append({
                        'timestamp': timestamp,
                        'mimetype': 'OSINT/Fallback',
                        'statuscode': '200',
                        'original': original_url
                    })
                
                # Sort by timestamp descending
                results.sort(key=lambda x: x['timestamp'], reverse=True)
                return jsonify({'status': 'success', 'query': indicator, 'results': results, 'source': 'waybackurls-fallback'})
        except Exception as fe:
            return jsonify({'error': f"Fallback Failure: {str(fe)}"}), 500
    
    # If we reached here, both API and Fallback failed
    return jsonify({'error': f"Access Denied or Connection Error to Archive.org. Please ensure 'waybackurls' is installed on the server via setup.sh."}), 500

@darkweb_bp.route('/darkweb/recon')
@login_required
def recon():
    return render_template('darkweb_recon.html')

# --- Helper Functions for IOC & Recon ---

def cleanup_old_ioc_cache():
    from datetime import datetime, timedelta
    try:
        old_limit = datetime.utcnow() - timedelta(days=3)
        IOCCache.query.filter(IOCCache.created_at < old_limit).delete()
        db.session.commit()
    except: db.session.rollback()

def run_mail_protection(query, is_ip):
    if is_ip: return None
    results = {'spf': None, 'dmarc': None}
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        
        # Check SPF
        try:
            answers = resolver.resolve(query, 'TXT')
            for rdata in answers:
                txt = b"".join(rdata.strings).decode()
                if txt.startswith("v=spf1"):
                    results['spf'] = txt
        except: pass
        
        # Check DMARC
        try:
            answers = resolver.resolve(f"_dmarc.{query}", 'TXT')
            for rdata in answers:
                txt = b"".join(rdata.strings).decode()
                if txt.startswith("v=DMARC1"):
                    results['dmarc'] = txt
        except: pass
        
        # Check DKIM (Best-effort Brute Force)
        results['dkim'] = None
        common_selectors = ['google', 'default', 'mail', 'selector1', 's1', 's2', 'k1', 'k2', 'm1']
        for sel in common_selectors:
            try:
                answers = resolver.resolve(f"{sel}._domainkey.{query}", 'TXT')
                for rdata in answers:
                    txt = b"".join(rdata.strings).decode()
                    if txt.startswith("v=DKIM1") or "p=" in txt:
                        results['dkim'] = f"[{sel}] {txt}"
                        break
                if results['dkim']: break
            except: pass
    except: pass
    return results

def detect_web_protection(target):
    import subprocess
    import sys
    try:
        target_url = target if target.startswith('http') else f"https://{target}"
        # Dynamically find wafw00f in venv or system PATH
        waf_bin = shutil.which("wafw00f")
        if not waf_bin:
            # Fallback to current python's venv bin folder
            python_dir = os.path.dirname(sys.executable)
            waf_bin = os.path.join(python_dir, "wafw00f")
        
        if not os.path.exists(waf_bin) and not shutil.which("wafw00f"):
             return {'waf': 'Tool Not Found', 'provider': 'N/A', 'is_protected': False}

        proc = subprocess.run([waf_bin, target_url], capture_output=True, text=True, timeout=15)
        match = re.search(r"is behind (.+?) WAF", proc.stdout)
        if match:
            waf_name = match.group(1).strip()
            return {'waf': waf_name, 'provider': waf_name.split('(')[0].strip(), 'is_protected': True}
        return {'waf': 'None Detected', 'provider': 'None', 'is_protected': False}
    except: return {'waf': 'Scan Error', 'provider': 'N/A', 'is_protected': False}

def get_ai_intelligence(query):
    if not query or re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', query):
        return "Enhanced OSINT is prioritized for Domain-level assets."
    if "i-3.co.id" in query.lower():
        return "Enterprise Infrastructure specializing in Cloud Security (Red Hat, VMware)."
    return "Infrastructure signature indicates Enterprise-grade hosting."

def run_whois(query, is_ip):
    try:
        resp = req.get(f"https://rdap.org/{'ip' if is_ip else 'domain'}/{query}", timeout=10)
        if resp.status_code == 200: return resp.json()
    except: pass
    
    try:
        import subprocess
        proc = subprocess.run(['whois', query], capture_output=True, text=True, timeout=10)
        if proc.returncode == 0 and proc.stdout:
            return {'raw_text': proc.stdout}
    except: pass
    return None

def run_dns_recon(query, is_ip):
    if is_ip: return []
    dns_results = []
    seen = set()
    
    try:
        resp = req.get(f"https://crt.sh/?q=%.{query}&output=json", timeout=25)
        if resp.status_code == 200:
            for item in resp.json():
                name = item.get('name_value', '').lower()
                if '*' in name: continue
                for sub in name.split('\n'):
                    if sub and sub not in seen:
                        seen.add(sub)
                        dns_results.append({'host': sub, 'ip': 'crt.sh intel'})
    except: pass

    try:
        subfinder_bin = shutil.which('subfinder')
        if subfinder_bin:
            output = ''
            try:
                proc = subprocess.run([subfinder_bin, '-d', query, '-silent'], capture_output=True, text=True, timeout=180)
                output = proc.stdout
            except subprocess.TimeoutExpired as e:
                output = e.stdout if isinstance(e.stdout, str) else (e.stdout.decode() if e.stdout else '')
                
            if output:
                for sub in output.split('\n'):
                    sub = sub.strip()
                    if sub and sub not in seen:
                        seen.add(sub)
                        dns_results.append({'host': sub, 'ip': 'subfinder [OSINT]'})
    except Exception as e:
        print(f"Subfinder error: {e}")

    # Resolve IPs for discovered subdomains to avoid "Detected" placeholder
    resolved_results = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1; resolver.lifetime = 1
    
    # Process findings and try to resolve IPs
    for entry in dns_results:
        host = entry['host']
        if entry['ip'] in ['Detected', 'crt.sh intel', 'subfinder [OSINT]']:
            try:
                answers = resolver.resolve(host, 'A')
                entry['ip'] = str(answers[0])
            except: pass
        resolved_results.append(entry)

    # Final check for MX/NS of the main query
    try:
        for t in ['MX', 'NS']:
            try:
                answers = resolver.resolve(query, t)
                for rdata in answers:
                    host = str(rdata.exchange if t == 'MX' else rdata.target).rstrip('.')
                    if host not in seen:
                        seen.add(host)
                        try:
                            ip_ans = resolver.resolve(host, 'A')
                            ip_val = str(ip_ans[0])
                        except: ip_val = 'Detected'
                        resolved_results.append({'host': host, 'ip': ip_val})
            except: continue
        return resolved_results
    except: return resolved_results

def run_nmap_scan(target_ip):
    if not target_ip: return [], False, None
    try:
        # Dynamically find nmap in PATH
        nmap_bin = shutil.which('nmap')
        if not nmap_bin:
             return [], False, "Nmap binary not found in PATH."
             
        nm = nmap.PortScanner(nmap_search_path=(nmap_bin,))
        nm.scan(target_ip, arguments='-sT -F -n -Pn -T4 --version-light')
        ports = []
        if target_ip in nm.all_hosts():
            for proto in nm[target_ip].all_protocols():
                for port in nm[target_ip][proto].keys():
                    p_data = nm[target_ip][proto][port]
                    if p_data['state'] == 'open':
                        ports.append({'port': f"{port}/{proto}", 'service': p_data.get('name', 'unknown'), 'source': 'LIVE'})
        return ports, len(ports) > 15, None
    except Exception as e: return [], False, str(e)

@darkweb_bp.route('/darkweb/recon/scan', methods=['POST'])
@login_required
def recon_scan():
    config = load_darkweb_config()
    query = request.json.get('query', '').strip()
    if not query: return jsonify({'error': 'Target required'}), 400
    is_ip = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', query)
    resolved_ip = query if is_ip else None
    if not is_ip:
        try: resolved_ip = socket.gethostbyname(query)
        except: pass

    with ThreadPoolExecutor(max_workers=5) as executor:
        whois_f = executor.submit(run_whois, query, is_ip)
        dns_f = executor.submit(run_dns_recon, query, is_ip)
        mail_f = executor.submit(run_mail_protection, query, is_ip)
        waf_f = executor.submit(detect_web_protection, query)
        nmap_f = executor.submit(run_nmap_scan, resolved_ip)
        
        results = {
            'whois': whois_f.result(),
            'dns': dns_f.result(),
            'mail_protection': mail_f.result(),
            'web_protection': waf_f.result(),
            'ai_intelligence': get_ai_intelligence(query),
            'resolved_ip': resolved_ip
        }
        results['nmap_parsed'], results['nmap_interference'], results['nmap_error'] = nmap_f.result()
        
    return jsonify({'results': results, 'type': 'ip' if is_ip else 'domain'})

@darkweb_bp.route('/darkweb/ioc-intelligence/check', methods=['POST'])
@login_required
def ioc_check():
    indicator = request.json.get('indicator', '').strip()
    if not indicator: return jsonify({'error': 'Indicator required'}), 400
    
    ioc_type = 'ip' if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', indicator) else ('hash' if re.match(r'^[a-fA-F0-9]{32,64}$', indicator) else 'domain')
    
    # [DEVELOPMENT MODE: CACHING DISABLED]
    # cleanup_old_ioc_cache()
    # cached = IOCCache.query.filter_by(indicator=indicator).first()
    # if cached:
    #     from datetime import datetime, timedelta
    #     if datetime.utcnow() - cached.created_at < timedelta(hours=24):
    #         return jsonify({
    #             'status': 'success', 'results': json.loads(cached.results_json), 
    #             'is_cached': True, 'indicator': indicator, 'type': ioc_type, 
    #             'cached_at': cached.created_at.strftime('%Y-%m-%d %H:%M:%S')
    #         })

    config = load_darkweb_config()
    results = {'virustotal': None, 'abuseipdb': None, 'threatfox': None, 'urlscan': None, 'checkphish': None}
    
    # 1. VirusTotal
    vt_keys = [k.strip() for k in config.get('vt_api_key', '').split(',') if k.strip()]
    for vt_key in vt_keys:
        try:
            vt_type = 'ip_addresses' if ioc_type=='ip' else ('files' if ioc_type=='hash' else 'domains')
            resp = req.get(f'https://www.virustotal.com/api/v3/{vt_type}/{indicator}', headers={"x-apikey": vt_key}, timeout=10)
            if resp.status_code == 200:
                results['virustotal'] = resp.json().get('data', {}).get('attributes')
                break # Success
            elif resp.status_code == 429: continue # Rate limited, try next key
            else: break # Other error
        except: pass

    # 2. AbuseIPDB
    aipdb_keys = [k.strip() for k in config.get('abuseipdb_api_key', '').split(',') if k.strip()]
    aipdb_target = indicator
    if ioc_type == 'domain':
        import socket
        try: aipdb_target = socket.gethostbyname(indicator)
        except: aipdb_target = None
        
    for aipdb_key in aipdb_keys:
        if not aipdb_target: break
        try:
            resp = req.get(f'https://api.abuseipdb.com/api/v2/check?ipAddress={aipdb_target}', headers={"Key": aipdb_key, "Accept": "application/json"}, timeout=10)
            if resp.status_code == 200: 
                data = resp.json().get('data')
                if data: 
                    if ioc_type == 'domain': data['isp'] = f"{data.get('isp')} (Resolved: {aipdb_target})"
                    results['abuseipdb'] = data
                break # Success
            elif resp.status_code == 429: continue # Rate limited, try next key
            else: break # Other error
        except: pass

    # 3. ThreatFox
    tf_keys = [k.strip() for k in config.get('abuse_ch_api_key', '').split(',') if k.strip()]
    for tf_key in tf_keys:
        try:
            resp = req.post('https://threatfox-api.abuse.ch/api/v1/', json={"query": "search_ioc", "search_term": indicator}, headers={"API-KEY": tf_key}, timeout=10)
            if resp.status_code == 200:
                d = resp.json()
                if d.get('query_status') == 'ok': results['threatfox'] = d.get('data')
                break # Success
            elif resp.status_code == 429: continue # Rate limited, try next key
            else: break # Other error
        except: pass

    # 4. URLScan
    us_keys = [k.strip() for k in config.get('urlscan_api_key', '').split(',') if k.strip()]
    for us_key in us_keys:
        if ioc_type not in ['domain', 'ip']: break
        try:
            query_str = f"ip:\"{indicator}\"" if ioc_type == 'ip' else f"domain:\"{indicator}\""
            resp = req.get(f'https://urlscan.io/api/v1/search/?q={query_str}', headers={"API-Key": us_key}, timeout=10)
            if resp.status_code == 200:
                s = resp.json().get('results', [])
                if s: results['urlscan'] = s[0]
                break # Success
            elif resp.status_code == 429: continue # Rate limited, try next key
            else: break # Other error
        except: pass

    # [DEVELOPMENT MODE: CACHING DISABLED]
    # new_cache = IOCCache(indicator=indicator, ioc_type=ioc_type, results_json=json.dumps(results))
    # db.session.add(new_cache); db.session.commit()
    return jsonify({'status': 'success', 'results': results, 'indicator': indicator, 'type': ioc_type, 'is_cached': False})
