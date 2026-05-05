import feedparser
import dateutil.parser
from flask import Blueprint, render_template, request, redirect, url_for, abort, jsonify, flash
from flask_login import login_required, current_user
import re
import asyncio
import requests
import os
import threading
import csv
import io
import time
from datetime import datetime, timedelta
import json
from ..extensions import db
from ..models import Threat, DismissedAlert, Inventory
from ..utils.helpers import load_feeds, save_feeds, determine_severity, log_event, get_inventory_alerts, normalize_url, load_darkweb_config

monitoring_bp = Blueprint('monitoring', __name__)

async def _scrape_telegram_page(browser, url):
    from playwright_stealth import Stealth
    context = await browser.new_context(
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
    page = await context.new_page()
    await Stealth().apply_stealth_async(page)
    
    results = []
    try:
        print(f"DEBUG: Fetching Telegram Source: {url}")
        await page.goto(url, wait_until='networkidle', timeout=30000)
        await page.wait_for_timeout(3000)
        
        wraps = await page.query_selector_all('.tgme_widget_message_wrap')
        for wrap in wraps:
            try:
                text_el = await wrap.query_selector('.tgme_widget_message_text')
                date_el = await wrap.query_selector('.tgme_widget_message_date time')
                link_el = await wrap.query_selector('.tgme_widget_message_date')
                
                if not text_el or not date_el: continue
                
                text = await text_el.inner_text()
                published_str = await date_el.get_attribute('datetime')
                msg_link = await link_el.get_attribute('href') if link_el else url
                
                # Link Extraction Fix
                link = msg_link
                found_links = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text)
                for fl in found_links:
                    if 't.me/' not in fl and 'twitter.com' not in fl:
                        link = fl
                        break
                
                lines = text.strip().split('\n')
                title = lines[0][:200] if lines else "Telegram Update"
                
                results.append({
                    'title': title,
                    'link': normalize_url(link),
                    'published': dateutil.parser.parse(published_str) if published_str else datetime.now(),
                    'summary': text.replace('\n', '<br>'),
                    'source': "Telegram: " + url.split('/')[-1]
                })
            except Exception as e:
                print(f"DEBUG: Error parsing TG message: {e}")
    except Exception as e:
        print(f"DEBUG: Telegram Scrape Error ({url}): {e}")
    finally:
        await context.close()
    return results

def scrape_telegram_source(channel_handle):
    from playwright.async_api import async_playwright
    url = f"https://t.me/s/{channel_handle}"
    try:
        async def run():
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(headless=True)
                data = await _scrape_telegram_page(browser, url)
                await browser.close()
                return data
        return asyncio.run(run())
    except Exception as e:
        print(f"DEBUG: scrape_telegram_source failed: {e}")
        return []

def fetch_nvd_cves():
    """Fetch recent vulnerabilities directly from NVD API with improved scoring."""
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=14)
    start_str = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
    end_str = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate={start_str}&lastModEndDate={end_str}&resultsPerPage=50"
    
    results = []
    try:
        res = requests.get(url, timeout=20)
        if res.status_code == 200:
            data = res.json()
            for item in data.get('vulnerabilities', []):
                cve = item.get('cve', {})
                cve_id = cve.get('id', 'Unknown CVE')
                desc = "No Description Available"
                descriptions = cve.get('descriptions', [])
                for d in descriptions:
                    if d.get('lang') == 'en':
                        desc = d.get('value')
                        break
                published = cve.get('published', '')
                metrics = cve.get('metrics', {})
                score = 0
                v31 = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore')
                v30 = metrics.get('cvssMetricV30', [{}])[0].get('cvssData', {}).get('baseScore')
                v2 = metrics.get('cvssMetricV2', [{}])[0].get('cvssData', {}).get('baseScore')
                if isinstance(v31, (int, float)): score = v31
                elif isinstance(v30, (int, float)): score = v30
                elif isinstance(v2, (int, float)): score = v2
                severity = 'Info'
                if score >= 9.0: severity = 'Critical'
                elif score >= 7.0: severity = 'High'
                elif score >= 4.0: severity = 'Medium'
                elif score > 0: severity = 'Low'
                else: severity = determine_severity(cve_id, desc, category='threat')
                results.append({
                    'title': f"{cve_id}: {desc[:150]}...",
                    'link': f"https://www.cve.org/CVERecord?id={cve_id}",
                    'published': dateutil.parser.parse(published) if published else datetime.now(),
                    'summary': desc,
                    'source': "NVD / CVE.org",
                    'severity': severity
                })
    except Exception as e:
        print(f"DEBUG: NVD Fetch Error: {e}")
    results.sort(key=lambda x: x['published'], reverse=True)
    return results[:50]

def fetch_exploitdb_entries():
    """Fetch recent exploits from the official Exploit-DB CSV mirror (GitLab)."""
    url = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
    results = []
    try:
        r = requests.get(url, timeout=15, headers={'User-Agent': 'Mozilla/5.0'}, verify=False)
        if r.status_code == 200:
            reader = csv.DictReader(io.StringIO(r.text))
            thirty_days_ago = datetime.utcnow() - timedelta(days=30)
            for row in reader:
                pub_date_str = row.get('date_published')
                if pub_date_str:
                    try:
                        pub_date = datetime.strptime(pub_date_str, '%Y-%m-%d')
                        if pub_date >= thirty_days_ago:
                            results.append({
                                'title': row['description'],
                                'link': f"https://www.exploit-db.com/exploits/{row['id']}",
                                'published': pub_date,
                                'summary': f"Type: {row['type']} | Platform: {row['platform']} | Author: {row['author']}",
                                'source': 'Exploit-DB'
                            })
                    except: continue
    except Exception as e:
        print(f"DEBUG: Exploit-DB Fetch Error: {e}")
    results.sort(key=lambda x: x['published'], reverse=True)
    return results

def fetch_rss_robust(url):
    headers = {'User-Agent': 'Mozilla/5.0'}
    try:
        r = requests.get(url, timeout=15, headers=headers, verify=False)
        return feedparser.parse(r.text)
    except Exception as e:
        print(f"DEBUG: Robust RSS Fetch failed for {url}: {e}")
        return feedparser.parse("")

def fetch_cisa_kev_entries():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    results = []
    try:
        r = requests.get(url, timeout=15, headers={'User-Agent': 'Mozilla/5.0'}, verify=False)
        if r.status_code == 200:
            data = r.json()
            vulnerabilities = data.get('vulnerabilities', [])
            limit_date = datetime.now() - timedelta(days=60)
            for v in vulnerabilities:
                date_str = v.get('dateAdded')
                if date_str:
                    try:
                        if 'T' in date_str: date_str = date_str.split('T')[0]
                        date_added = datetime.strptime(date_str.strip(), '%Y-%m-%d')
                        if date_added >= limit_date:
                            results.append({
                                'title': f"{v['vulnerabilityName']} ({v['cveID']})",
                                'link': f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog#{v['cveID']}",
                                'published': date_added,
                                'summary': f"CVE ID: {v['cveID']} | Product: {v['product']} | Vendor: {v.get('vendorProject', 'Unknown')} | Description: {v.get('shortDescription', 'No details available')}.",
                                'source': 'CISA KEV'
                            })
                    except Exception as de:
                        print(f"DEBUG: CISA Date parse error: {de}")
    except Exception as e:
        print(f"DEBUG: CISA KEV Fatal Error: {e}")
    results.sort(key=lambda x: x['published'], reverse=True)
    return results

fetch_lock = threading.Lock()

def fetch_and_store_all_data(force=False):
    """Unified background sync manager for all dashboard data."""
    if not fetch_lock.acquire(blocking=False):
        return 0
    
    try:
        from ..utils.helpers import load_darkweb_config, save_darkweb_config
        config = load_darkweb_config()
        sync_interval_sec = int(config.get('sync_interval', 360)) * 60
        
        last_sync_str = config.get('last_sync')
        if not force and last_sync_str:
            try:
                last_sync = datetime.strptime(last_sync_str, "%Y-%m-%d %H:%M:%S")
                if (datetime.now() - last_sync).total_seconds() < sync_interval_sec:
                    return 0
            except: pass

        print(f"GLOBAL SYNC: Starting data update (Force: {force})")
        
        # 1. Threat Intelligence
        feeds = load_feeds()
        new_count = 0
        updated_feeds = []
        for feed_item in feeds:
            feed_url = feed_item.get('url')
            feed_category = feed_item.get('category', 'threat')
            if not force and feed_item.get('last_checked'):
                try:
                    lc = datetime.strptime(feed_item['last_checked'], "%Y-%m-%d %H:%M:%S")
                    if (datetime.now() - lc).total_seconds() < sync_interval_sec:
                        updated_feeds.append(feed_item); continue
                except: pass
            
            try:
                if feed_url.startswith('nvd://'): results = fetch_nvd_cves()
                elif feed_url.startswith('telegram://') or 't.me/s/' in feed_url:
                    results = scrape_telegram_source(feed_url.split('/')[-1])
                elif feed_url.startswith('exploitdb://'): results = fetch_exploitdb_entries()
                elif feed_url.startswith('cisakev://'): results = fetch_cisa_kev_entries()
                else:
                    rss = fetch_rss_robust(feed_url)
                    results = []
                    if rss and hasattr(rss, 'entries'):
                        for entry in rss.entries:
                            pub_dt = None
                            if hasattr(entry, 'published'):
                                try: pub_dt = dateutil.parser.parse(entry.published)
                                except: pass
                                     # Data Quality Filter: Skip entries that are just version numbers with no summary
                            is_version_only = re.match(r'^[\d\.]+$', entry.title.strip())
                            if (not entry.get('summary') or len(entry.get('summary', '').strip()) < 5) and is_version_only:
                                continue
                            
                            # Specific filter for known spammy patterns
                            entry_source = getattr(entry, 'source', '')
                            if "Service Updates" in entry_source and is_version_only:
                                continue

                            results.append({
                                'title': entry.title, 'link': entry.link, 
                                'published': pub_dt, 'summary': entry.get('summary', ''),
                                'source': rss.feed.get('title', feed_url)
                            })
                
                for entry in results:
                    # Robust duplicate check
                    if entry.get('source') == 'CISA KEV':
                        if Threat.query.filter((Threat.link == entry['link']) | (Threat.title == entry['title'])).first(): continue
                    else:
                        if Threat.query.filter_by(link=entry['link']).first(): continue
                    
                    severity = entry.get('severity') or determine_severity(entry['title'], entry['summary'], category=feed_category)
                    threat = Threat(
                        title=entry['title'], link=entry['link'],
                        published=entry['published'],
                        published_str=entry['published'].strftime("%Y-%m-%d %H:%M") if entry['published'] else "Unknown",
                        summary=entry['summary'], source=entry['source'],
                        severity=severity, category=feed_category
                    )
                    db.session.add(threat)
                    new_count += 1
                    print(f"SYNC: Added {entry['source']} - {entry['title'][:50]}...")
                db.session.commit()
                feed_item['status'] = 'OK'; feed_item['last_error'] = None
                feed_item['last_checked'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            except Exception as e:
                db.session.rollback(); feed_item['status'] = 'Error'; feed_item['last_error'] = str(e)
            updated_feeds.append(feed_item); save_feeds(updated_feeds + feeds[len(updated_feeds):])

        # 2. Ransomware
        from .darkweb import run_ransomware_sync
        run_ransomware_sync()

        # 3. Defacement
        from .darkweb import run_defacements_sync
        run_defacements_sync(limit_pages=15 if not force else 50)

        # 4. Breach Market
        from .breach_intel import run_breach_market_sync, _build_indonesia_cache
        run_breach_market_sync()
        
        # 5. Indonesia Breach (Background)
        threading.Thread(target=_build_indonesia_cache, daemon=True).start()

        config['last_sync'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        save_darkweb_config(config)
        print(f"GLOBAL SYNC: Finished. {new_count} items identified.")
    except Exception as e: print(f"GLOBAL SYNC Error: {e}")
    finally:
        try: db.session.remove()
        except: pass
        fetch_lock.release()
    return new_count

def render_dashboard(category_filter, page_title):
    severity_filter = request.args.get('severity')
    date_filter = request.args.get('date')
    source_filter = request.args.get('source')
    search_query = request.args.get('q')
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', '10', type=str) 
    per_page = 1000 if limit == 'all' else int(limit) if limit.isdigit() else 10

    from flask import current_app
    app = current_app._get_current_object()
    def sync_task(app_context):
        with app_context.app_context(): fetch_and_store_all_data(force=False)
    threading.Thread(target=sync_task, args=(app,), daemon=True).start()

    from ..utils.helpers import load_darkweb_config
    config = load_darkweb_config()
    last_sync = config.get('last_sync', 'Never')

    query = Threat.query.filter_by(category=category_filter)
    if search_query:
        search_filter = (Threat.title.ilike(f'%{search_query}%')) | (Threat.summary.ilike(f'%{search_query}%'))
        query = query.filter(search_filter)
    if severity_filter: query = query.filter_by(severity=severity_filter)
    if source_filter: query = query.filter_by(source=source_filter)
    if date_filter:
        try:
             target_date = datetime.strptime(date_filter, '%Y-%m-%d').date()
             query = query.filter(db.func.date(Threat.published) == target_date)
        except: pass 

    query = query.order_by(Threat.published.desc().nullslast())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    threats = pagination.items
    
    query_category = 'threat' if category_filter == 'main_dashboard' else category_filter
    sources = [s[0] for s in db.session.query(Threat.source).filter_by(category=query_category).distinct().all()]
    
    stats = {
        'total': Threat.query.filter_by(category=query_category).count(),
        'critical': Threat.query.filter_by(category=query_category, severity='Critical').count(),
        'high': Threat.query.filter_by(category=query_category, severity='High').count(),
        'medium': Threat.query.filter_by(category=query_category, severity='Medium').count(),
        'low': Threat.query.filter_by(category=query_category, severity='Low').count(),
        'info': Threat.query.filter_by(category=query_category, severity='Info').count()
    }
    
    end_date = datetime.now().date()
    start_date = end_date - timedelta(days=6)
    trend_query = db.session.query(db.func.date(Threat.published).label('date'), db.func.count(Threat.id).label('count')).filter(Threat.category == query_category, db.func.date(Threat.published) >= start_date).group_by(db.func.date(Threat.published)).all()
    trend_dict = {str(r.date): r.count for r in trend_query}
    trend_dates = [(start_date + timedelta(days=i)).strftime('%Y-%m-%d') for i in range(7)]
    trend_counts = [trend_dict.get(d, 0) for d in trend_dates]

    country_targeting_names, country_targeting_counts = [], []
    try:
        with open(os.path.join(os.getcwd(), 'ransomware_cache.json'), 'r') as f: rc = json.load(f)
        country_counts = {}
        COUNTRY_MAP = {'US': 'USA', 'ID': 'Indonesia', 'TW': 'Taiwan', 'DE': 'Germany', 'JP': 'Japan', 'GB': 'UK', 'CN': 'China', 'RU': 'Russia', 'BR': 'Brazil', 'CA': 'Canada', 'AU': 'Australia', 'FR': 'France', 'IT': 'Italy', 'ES': 'Spain', 'NL': 'Netherlands', 'IN': 'India', 'KR': 'South Korea', 'SG': 'Singapore', 'TH': 'Thailand', 'PH': 'Philippines', 'MY': 'Malaysia', 'VN': 'Vietnam'}
        for d, victims in rc.items():
            for v in victims:
                c_name = COUNTRY_MAP.get(v.get('country'), v.get('country', 'Unknown'))
                if c_name != 'Unknown': country_counts[c_name] = country_counts.get(c_name, 0) + 1
        top_c = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        country_targeting_names = [x[0] for x in top_c]; country_targeting_counts = [x[1] for x in top_c]
    except: pass

    chart_data = {'trend_dates': json.dumps(trend_dates), 'trend_counts': json.dumps(trend_counts), 'top_sources_names': json.dumps(country_targeting_names), 'top_sources_counts': json.dumps(country_targeting_counts)}

    if category_filter == 'main_dashboard':
        from .breach_intel import INDONESIA_INCIDENTS, SECTOR_MAP
        b_sec = {s: 0 for s in SECTOR_MAP.keys()}
        for inc in INDONESIA_INCIDENTS:
            s = inc.get('sector', 'Lainnya')
            b_sec[s] = b_sec.get(s, 0) + 1
        try:
            with open(os.path.join(os.getcwd(), 'breach_market_cache.json'), 'r') as f:
                for item in json.load(f):
                    s = item.get('sector', 'Lainnya')
                    b_sec[s] = b_sec.get(s, 0) + 1
        except: pass
        top_b = sorted(b_sec.items(), key=lambda x: x[1], reverse=True)[:7]
        chart_data['breach_names'] = json.dumps([x[0] for x in top_b]); chart_data['breach_counts'] = json.dumps([x[1] for x in top_b])

        try:
            with open(os.path.join(os.getcwd(), 'ransomware_cache.json'), 'r') as f:
                rc = json.load(f); rg = {}
                for d, l in rc.items():
                    for v in l: g = v.get('group'); rg[g] = rg.get(g, 0) + 1
            top_rw = sorted(rg.items(), key=lambda x: x[1], reverse=True)[:5]
            chart_data['rw_names'] = json.dumps([x[0][:15] for x in top_rw]); chart_data['rw_counts'] = json.dumps([x[1] for x in top_rw])
        except: chart_data['rw_names'] = chart_data['rw_counts'] = '[]'

        try:
            with open(os.path.join(os.getcwd(), 'defacement_cache.json'), 'r') as f:
                dc = json.load(f); dt = {}
                for d, l in dc.items():
                    for v in l: t = v.get('team'); dt[t] = dt.get(t, 0) + 1
            top_df = sorted(dt.items(), key=lambda x: x[1], reverse=True)[:5]
            chart_data['def_names'] = json.dumps([x[0][:15] for x in top_df]); chart_data['def_counts'] = json.dumps([x[1] for x in top_df])
        except: chart_data['def_names'] = chart_data['def_counts'] = '[]'

        alerts = get_inventory_alerts(current_user.group_id)
        categories = ['Critical', 'High', 'Medium', 'Low', 'Info']
        inv_risk_counts = {cat: 0 for cat in categories}
        for a in alerts:
            sev = (a['threat'].severity or 'Info').capitalize()
            if sev in inv_risk_counts: inv_risk_counts[sev] += 1
        chart_data['inv_names'] = json.dumps(categories); chart_data['inv_counts'] = json.dumps([inv_risk_counts[c] for c in categories])

        exp_stats = {cat: 0 for cat in categories}
        for exp in Threat.query.filter_by(category='exploit').all():
            sev = (exp.severity or 'Info').capitalize()
            if sev in exp_stats: exp_stats[sev] += 1
        chart_data['exp_names'] = json.dumps(categories); chart_data['exp_counts'] = json.dumps([exp_stats[c] for c in categories])

    is_syncing = fetch_lock.locked()
    return render_template('index.html', threats=threats, stats=stats, current_severity=severity_filter, current_date=date_filter, current_source=source_filter, current_search=search_query, pagination=pagination, current_limit=limit, sources=sources, page_title=page_title, current_category=category_filter, chart_data=chart_data, last_sync=last_sync, is_syncing=is_syncing)

@monitoring_bp.route('/')
@login_required
def main_dashboard():
    return render_dashboard('main_dashboard', 'EXECUTIVE OVERVIEW')

@monitoring_bp.route('/threat')
@login_required
def index():
    return render_dashboard('threat', 'THREAT INTELLIGENCE')

@monitoring_bp.route('/news')
@login_required
def news():
    return render_dashboard('news', 'CYBER NEWS')

@monitoring_bp.route('/exploits')
@login_required
def exploit_database():
    return render_dashboard('exploit', 'EXPLOIT DATABASE')

@monitoring_bp.route('/ransomware')
@login_required
def ransomware():
    return render_dashboard('ransomware', 'RANSOMWARE MONITORING')

@monitoring_bp.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete_threat(id):
    if current_user.role != 'admin': abort(403)
    threat = Threat.query.get_or_404(id)
    try:
        db.session.delete(threat); db.session.commit()
        log_event('Item deleted successfully.', 'success')
    except: db.session.rollback()
    return redirect(request.referrer or url_for('monitoring.index'))

@monitoring_bp.route('/refresh')
@login_required
def refresh_data():
    if current_user.role != 'admin': abort(403)
    from flask import current_app
    app = current_app._get_current_object()
    def manual_sync_task(app_context):
        with app_context.app_context(): fetch_and_store_all_data(force=True)
    if fetch_lock.locked():
        flash("A synchronization task is already in progress.", "warning")
    else:
        threading.Thread(target=manual_sync_task, args=(app,), daemon=True).start()
        flash("Manual synchronization initiated. This process runs in the background and may take a few minutes.", "success")
    return redirect(request.referrer or url_for('monitoring.index'))

@monitoring_bp.route('/whats-new')
@login_required
def whats_new():
    date_filter = request.args.get('date')
    if date_filter:
        try:
            target_date = datetime.strptime(date_filter, '%Y-%m-%d').date()
            cutoff_start = datetime.combine(target_date, datetime.min.time())
            cutoff_end = datetime.combine(target_date, datetime.max.time()); date_mode = True
        except:
            target_date = datetime.utcnow().date(); cutoff_start = datetime.combine(target_date, datetime.min.time()); cutoff_end = datetime.utcnow(); date_mode = False
    else:
        target_date = datetime.utcnow().date(); cutoff_start = datetime.combine(target_date, datetime.min.time()); cutoff_end = datetime.utcnow(); date_mode = False

    feed = []
    threats = Threat.query.filter(Threat.published >= cutoff_start, Threat.published <= cutoff_end).all() if date_mode else Threat.query.filter(Threat.published >= cutoff_start).all()
    for item in threats:
        f_type = 'THREAT'
        if item.source in ['Daily Dark Web', 'DarkWeb Informer']:
            f_type = 'DAILY DARKWEB'
            if item.category == 'FRAUD': f_type = 'FRAUD'
        elif item.category == 'exploit': f_type = 'EXPLOIT'
        elif item.category == 'cyber_crime': f_type = 'CRIME'
        elif item.category == 'news': f_type = 'NEWS'
        feed.append({
            'source': item.source or 'Global Intelligence', 
            'title': item.title, 
            'time': item.published, 
            'category': item.category, 
            'severity': item.severity or 'info', 
            'summary': item.summary, 
            'link': item.link, 
            'type': f_type
        })

    try:
        with open(os.path.join(os.getcwd(), 'ransomware_cache.json'), 'r') as f:
            for d_key, victims in json.load(f).items():
                try:
                    dt = datetime.strptime(d_key, '%Y-%m-%d')
                    for v in victims: feed.append({'source': v.get('group', 'Unknown'), 'title': f"Ransomware Victim: {v.get('name')}", 'time': dt, 'category': 'cyber_crime', 'severity': 'high', 'summary': f"Victim in {v.get('country')}. Industry: {v.get('activity')}", 'link': v.get('url', '#'), 'type': 'RANSOMWARE_VICTIM'})
                except: pass
    except: pass

    try:
        with open(os.path.join(os.getcwd(), 'defacement_cache.json'), 'r') as f:
            for d_key, defaces in json.load(f).items():
                try:
                    dt = datetime.strptime(d_key, '%Y-%m-%d')
                    for v in defaces: feed.append({'source': v.get('team', 'Unknown'), 'title': f"Defacement: {v.get('domain')}", 'time': dt, 'category': 'defacement', 'severity': 'medium', 'summary': f"Notifier: {v.get('notifier')}. Target: {v.get('domain')}", 'link': normalize_url(v.get('mirror') or v.get('url', '#')), 'type': 'DEFACEMENT', 'mirror_id': v.get('mirror_id', ''), 'attacker': v.get('attacker', ''), 'team': v.get('team', ''), 'domain': v.get('domain', ''), 'date_str': dt.strftime('%Y-%m-%d %H:%M:%S')})
                except: pass
    except: pass

    try:
        with open(os.path.join(os.getcwd(), 'breach_market_cache.json'), 'r') as f:
            for b in json.load(f):
                try:
                    dt = datetime.strptime(b.get('added_date', '')[:10], '%Y-%m-%d')
                    feed.append({'source': 'Breach Market', 'title': f"Breach: {b.get('title')}", 'time': dt, 'category': 'data_leak', 'severity': b.get('risk_label', 'low').lower(), 'summary': f"Domain: {b.get('domain')}. Records: {b.get('pwn_count', 0)}. Sector: {b.get('sector', 'Other')}", 'link': f"https://haveibeenpwned.com/PwnedWebsites#{b.get('name')}", 'type': 'BREACH'})
                except: pass
    except: pass

    available_dates = set()
    try:
        for d in db.session.query(db.func.date(Threat.published)).distinct().all():
            if d[0]: available_dates.add(str(d[0]))
        for f_name in ['ransomware_cache.json', 'defacement_cache.json']:
            if os.path.exists(f_name):
                with open(f_name, 'r') as f:
                    for d_key in json.load(f).keys():
                         if re.match(r'\d{4}-\d{2}-\d{2}', d_key): available_dates.add(d_key)
    except: pass

    # Pre-filtering to ensure item['time'] is valid before accessing .date()
    feed = [item for item in feed if item.get('time') and item['time'].date() == target_date]
    for item in feed: item['link'] = normalize_url(item['link'])
    feed.sort(key=lambda x: x['time'], reverse=True)
    display_date = date_filter or target_date.strftime('%Y-%m-%d')
    config = load_darkweb_config()
    last_sync = config.get('last_sync', 'Never')
    is_syncing = fetch_lock.locked()

    return render_template('whats_new.html', feed=feed, page_title='WHATS NEW TODAY', current_date=display_date, available_dates=sorted(list(available_dates), reverse=True), last_sync=last_sync, is_syncing=is_syncing)

@monitoring_bp.route('/about')
@login_required
def about():
    return render_template('about.html')
