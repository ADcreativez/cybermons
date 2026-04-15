import feedparser
import dateutil.parser
from flask import Blueprint, render_template, request, redirect, url_for, abort, jsonify
from flask_login import login_required, current_user
import re
import asyncio
import requests
import os
import threading
from datetime import datetime, timedelta
import json
from ..extensions import db
from ..models import Threat, DismissedAlert, Inventory
from ..utils.helpers import load_feeds, save_feeds, determine_severity, log_event

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
                
                # Link Extraction Fix: Look for external URLs in text
                # We prioritize cve.org, mitre.org, or any news site
                link = msg_link
                found_links = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text)
                for fl in found_links:
                    if 't.me/' not in fl and 'twitter.com' not in fl:
                        link = fl
                        break # Take the first external link as primary
                
                lines = text.strip().split('\n')
                title = lines[0][:200] if lines else "Telegram Update"
                
                results.append({
                    'title': title,
                    'link': link,
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
    print("NVD Sync: Fetching Recent CVEs from NVD API...")
    
    # Calculate date range for the last 14 days to get "Active" intel
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=14)
    
    start_str = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
    end_str = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
    
    # Official NVD API v2 with date filters
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate={start_str}&lastModEndDate={end_str}&resultsPerPage=50"
    
    results = []
    try:
        res = requests.get(url, timeout=20)
        if res.status_code == 200:
            data = res.json()
            for item in data.get('vulnerabilities', []):
                cve = item.get('cve', {})
                cve_id = cve.get('id', 'Unknown CVE')
                
                # Get the best description
                desc = "No Description Available"
                descriptions = cve.get('descriptions', [])
                for d in descriptions:
                    if d.get('lang') == 'en':
                        desc = d.get('value')
                        break
                
                published = cve.get('published', '')
                
                # Advanced Severity scoring
                metrics = cve.get('metrics', {})
                score = 0
                
                # 1. Try CVSS v3.1 then v3.0
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
                else:
                    # Fallback to keyword-based detection if no CVSS score is yet assigned (common for new entries)
                    severity = determine_severity(cve_id, desc, category='threat')
                
                results.append({
                    'title': f"{cve_id}: {desc[:150]}...",
                    'link': f"https://www.cve.org/CVERecord?id={cve_id}",
                    'published': dateutil.parser.parse(published) if published else datetime.now(),
                    'summary': desc,
                    'source': "NVD / CVE.org",
                    'severity': severity
                })
        else:
            print(f"DEBUG: NVD API returned status {res.status_code}")
    except Exception as e:
        print(f"DEBUG: NVD Fetch Error: {e}")
    
    # Sort by published date desc
    results.sort(key=lambda x: x['published'], reverse=True)
    return results[:50]


fetch_lock = threading.Lock()

def fetch_and_store_threats(force=False):
    if not fetch_lock.acquire(blocking=False):
        return 0
    
    # We'll use a local session if possible or ensure we are in a context
    try:
        feeds = load_feeds()
        new_count = 0
        updated_feeds = []
        
        for feed_item in feeds:
            feed_url = feed_item.get('url')
            feed_category = feed_item.get('category', 'threat')
            
            # Cooldown check: Skip if checked recently, UNLESS it's currently in an Error state
            if not force and feed_item.get('last_checked'):
                try:
                    from ..utils.helpers import load_darkweb_config
                    config = load_darkweb_config()
                    sync_interval_sec = int(config.get('sync_interval', 360)) * 60

                    last_checked = datetime.strptime(feed_item['last_checked'], "%Y-%m-%d %H:%M:%S")
                    time_diff = (datetime.now() - last_checked).total_seconds()
                    # Use dynamic interval, but bypass if status is Error or if it was never checked successfully
                    is_error = feed_item.get('status') == 'Error'
                    if time_diff < sync_interval_sec and not is_error:
                        updated_feeds.append(feed_item)
                        continue
                except: pass
            
            try:
                # Detect NVD Source
                if feed_url.startswith('nvd://'):
                    results = fetch_nvd_cves()
                    feed_item['status'] = 'OK'
                    feed_item['last_error'] = None
                    feed_item['last_checked'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    for entry in results:
                        if Threat.query.filter_by(link=entry['link']).first(): continue
                        threat = Threat(
                            title=entry['title'], link=entry['link'],
                            published=entry['published'],
                            published_str=entry['published'].strftime("%Y-%m-%d %H:%M"),
                            summary=entry['summary'], source=entry['source'],
                            severity=entry['severity'], category=feed_category
                        )
                        db.session.add(threat)
                        new_count += 1
                    db.session.commit()
                    updated_feeds.append(feed_item)
                    continue

                # Detect Telegram Sources
                if feed_url.startswith('telegram://') or 't.me/s/' in feed_url:
                    handle = feed_url.split('/')[-1]
                    print(f"Social Sync: Fetching Telegram Channel @{handle}")
                    results = scrape_telegram_source(handle)
                    
                    feed_item['status'] = 'OK'
                    feed_item['last_error'] = None
                    feed_item['last_checked'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    
                    for entry in results:
                        if Threat.query.filter_by(link=entry['link']).first():
                            continue
                        
                        severity = determine_severity(entry['title'], entry['summary'], category=feed_category)
                        threat = Threat(
                            title=entry['title'],
                            link=entry['link'],
                            published=entry['published'],
                            published_str=entry['published'].strftime("%Y-%m-%d %H:%M"),
                            summary=entry['summary'],
                            source=entry['source'],
                            severity=severity,
                            category=feed_category
                        )
                        db.session.add(threat)
                        new_count += 1
                    db.session.commit()
                    updated_feeds.append(feed_item)
                    continue

                # Standard RSS Logic
                feed = feedparser.parse(feed_url)
                if feed.bozo and not feed.entries: raise Exception(f"Feed error: {feed.bozo_exception}")

                feed_item['status'] = 'OK'
                feed_item['last_error'] = None
                feed_item['last_checked'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                for entry in feed.entries: 
                    if Threat.query.filter_by(link=entry.link).first(): continue

                    published_dt = None
                    published_str = "Unknown Date"
                    if hasattr(entry, 'published'):
                        try:
                            published_dt = dateutil.parser.parse(entry.published)
                            published_str = published_dt.strftime("%Y-%m-%d %H:%M")
                        except: published_str = entry.published
                    
                    severity = determine_severity(entry.title, entry.get('summary', ''), category=feed_category)

                    threat = Threat(
                        title=entry.title, link=entry.link,
                        published=published_dt, published_str=published_str,
                        summary=entry.summary if hasattr(entry, 'summary') else '',
                        source=feed.feed.title if hasattr(feed.feed, 'title') else feed_url,
                        severity=severity, category=feed_category
                    )
                    db.session.add(threat)
                    new_count += 1
                
                # Commit after EACH feed to prevent context/transaction issues
                db.session.commit()
                feed_item['status'] = 'OK'
                feed_item['last_error'] = None
                feed_item['last_checked'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            except Exception as e:
                db.session.rollback()
                print(f"DEBUG: Feed Error ({feed_url}): {e}")
                feed_item['status'] = 'Error'
                feed_item['last_error'] = str(e)
                feed_item['last_checked'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            updated_feeds.append(feed_item)
            # Progressive save of feeds.json
            save_feeds(updated_feeds + feeds[len(updated_feeds):])
        
    except Exception as outer_e:
        print(f"DEBUG: Fatal sync error: {outer_e}")
    finally:
        # Final cleanup
        try:
            db.session.remove()
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

    # Move sync to background with application context to prevent UI blocking and DB locks
    from flask import current_app
    app = current_app._get_current_object()
    
    def sync_task(app_context):
        with app_context.app_context():
            fetch_and_store_threats(force=False)
            
    threading.Thread(target=sync_task, args=(app,), daemon=True).start()

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
    
    # For main_dashboard, pull stats/trend/sources from 'threat' category (actual data)
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
    
    # 7-Day Trend
    end_date = datetime.now().date()
    start_date = end_date - timedelta(days=6)
    
    trend_query = db.session.query(
        db.func.date(Threat.published).label('date'),
        db.func.count(Threat.id).label('count')
    ).filter(
        Threat.category == query_category,
        db.func.date(Threat.published) >= start_date
    ).group_by(db.func.date(Threat.published)).all()
    
    trend_dict = {str(r.date): r.count for r in trend_query}
    trend_dates = [(start_date + timedelta(days=i)).strftime('%Y-%m-%d') for i in range(7)]
    trend_counts = [trend_dict.get(d, 0) for d in trend_dates]

    # Top Targeted Countries (from Ransomware Data)
    country_targeting_names = []
    country_targeting_counts = []
    try:
        import os
        with open(os.path.join(os.getcwd(), 'ransomware_cache.json'), 'r') as f:
            rc = json.load(f)
        
        country_counts = {}
        # Mapping for professional display
        COUNTRY_MAP = {
            'US': 'USA', 'ID': 'Indonesia', 'TW': 'Taiwan', 'DE': 'Germany', 
            'JP': 'Japan', 'GB': 'United Kingdom', 'CN': 'China', 'RU': 'Russia', 
            'BR': 'Brazil', 'CA': 'Canada', 'AU': 'Australia', 'FR': 'France',
            'IT': 'Italy', 'ES': 'Spain', 'NL': 'Netherlands', 'IN': 'India',
            'KR': 'South Korea', 'SG': 'Singapore', 'TH': 'Thailand', 'PH': 'Philippines',
            'MY': 'Malaysia', 'VN': 'Vietnam', 'CL': 'Chile', 'ZA': 'South Africa', 
            'AR': 'Argentina', 'MX': 'Mexico', 'TR': 'Turkey', 'PL': 'Poland'
        }

        for date_key, victims in rc.items():
            for v in victims:
                c_code = v.get('country', 'Unknown')
                if not c_code or c_code == 'Unknown': continue
                
                c_name = COUNTRY_MAP.get(c_code, c_code)
                country_counts[c_name] = country_counts.get(c_name, 0) + 1
        
        top_countries = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        country_targeting_names = [x[0] for x in top_countries]
        country_targeting_counts = [x[1] for x in top_countries]
    except Exception as e:
        print(f"DEBUG: Error aggregating country stats: {e}")

    chart_data = {
        'trend_dates': json.dumps(trend_dates),
        'trend_counts': json.dumps(trend_counts),
        'top_sources_names': json.dumps(country_targeting_names),
        'top_sources_counts': json.dumps(country_targeting_counts)
    }

    if category_filter == 'main_dashboard':
        import os
        from .breach_intel import INDONESIA_INCIDENTS
        # Breach Stats — aggregate from 900+ HIBP records + curated Indonesian incidents
        b_sec = {}
        # 1. Start with high-fidelity curated incidents
        for inc in INDONESIA_INCIDENTS:
            s = inc.get('sector', 'Lainnya')
            b_sec[s] = b_sec.get(s, 0) + 1
        
        # 2. Add global HIBP records from cache with keyword classification
        try:
            mkt_cache = os.path.join(os.getcwd(), 'breach_market_cache.json')
            if os.path.exists(mkt_cache):
                with open(mkt_cache, 'r') as f:
                    mkt_data = json.load(f)
                
                # Global sector mapping keywords for 900+ HIBP records
                SECTOR_MAP = {
                    'Teknologi & IT':   ['tech', 'software', 'app', 'game', 'gaming', 'hosting', 'web', 'internet', 'social', 'media', 'network', 'digital', 'cloud', 'it service', 'forum', 'community'],
                    'Keuangan':         ['bank', 'finance', 'crypto', 'pay', 'loan', 'invest', 'trading', 'credit', 'insurance', 'money', 'stock', 'billing', 'accounting'],
                    'E-commerce':       ['shop', 'store', 'market', 'order', 'delivery', 'food', 'fashion', 'commerce', 'customer', 'retail', 'clothing', 'jewel', 'sneaker'],
                    'Hiburan':          ['movie', 'video', 'music', 'entertainment', 'travel', 'hotel', 'booking', 'dating', 'adult', 'lifestyle', 'hobby', 'fitness', 'fan'],
                    'Pemerintahan':     ['gov', 'ministry', 'agency', 'council', 'state', 'national', 'police', 'defense', 'military', 'public service', 'politics'],
                    'Pendidikan':       ['school', 'univ', 'edu', 'college', 'learn', 'student', 'teacher', 'academy', 'library'],
                    'Kesehatan':        ['health', 'med', 'hospital', 'pharma', 'clinic', 'dentist', 'patient', 'wellness', 'doctor', 'nursing']
                }

                for item in mkt_data:
                    title = item.get('title', '').lower()
                    domain = item.get('domain', '').lower()
                    desc = ' '.join(item.get('data_classes', [])).lower()
                    found = False
                    for sector, keywords in SECTOR_MAP.items():
                        if any(k in title for k in keywords) or any(k in domain for k in keywords) or any(k in desc for k in keywords):
                            b_sec[sector] = b_sec.get(sector, 0) + 1
                            found = True
                            break
                    if not found:
                        b_sec['Lainnya'] = b_sec.get('Lainnya', 0) + 1
        except:
            pass

        # Sort and take top 7 sectors for chart to look balanced
        top_b = sorted(b_sec.items(), key=lambda x: x[1], reverse=True)[:7]
        chart_data['breach_names'] = json.dumps([x[0] for x in top_b])
        chart_data['breach_counts'] = json.dumps([x[1] for x in top_b])

        # Ransomware Stats
        try:
            with open(os.path.join(os.getcwd(), 'ransomware_cache.json'), 'r') as f:
                rc = json.load(f)
            rg = {}
            for d, l in rc.items():
                for v in l:
                    g = v.get('group', 'Unknown')
                    if g: rg[g] = rg.get(g, 0) + 1
            top_rw = sorted(rg.items(), key=lambda x: x[1], reverse=True)[:5]
            chart_data['rw_names'] = json.dumps([x[0][:15] for x in top_rw])
            chart_data['rw_counts'] = json.dumps([x[1] for x in top_rw])
        except:
            chart_data['rw_names'] = '[]'
            chart_data['rw_counts'] = '[]'

        # Defacement Stats
        try:
            with open(os.path.join(os.getcwd(), 'defacement_cache.json'), 'r') as f:
                dc = json.load(f)
            dt = {}
            for d, l in dc.items():
                for v in l:
                    t = v.get('team', 'Unknown')
                    if t: dt[t] = dt.get(t, 0) + 1
            top_df = sorted(dt.items(), key=lambda x: x[1], reverse=True)[:5]
            chart_data['def_names'] = json.dumps([x[0][:15] for x in top_df])
            chart_data['def_counts'] = json.dumps([x[1] for x in top_df])
        except:
            chart_data['def_names'] = '[]'
            chart_data['def_counts'] = '[]'

        # Inventory Stats
        inv_query = db.session.query(
            Inventory.brand, db.func.count(Inventory.id).label('count')
        ).group_by(Inventory.brand).order_by(db.func.count(Inventory.id).desc()).limit(10).all()
        chart_data['inv_names'] = json.dumps([r.brand for r in inv_query])
        chart_data['inv_counts'] = json.dumps([r.count for r in inv_query])

    
    return render_template('index.html', 
                           threats=threats, stats=stats, 
                           current_severity=severity_filter, current_date=date_filter,
                           current_source=source_filter, current_search=search_query,
                           pagination=pagination, current_limit=limit,
                           sources=sources, page_title=page_title,
                           current_category=category_filter,
                           chart_data=chart_data)

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
        db.session.delete(threat)
        db.session.commit()
        log_event('Item deleted successfully.', 'success')
    except: db.session.rollback()
    return redirect(request.referrer or url_for('monitoring.index'))

@monitoring_bp.route('/refresh')
@login_required
def refresh_data():
    if current_user.role != 'admin': abort(403)
    count = fetch_and_store_threats(force=True)
    log_event(f"Intelligence Sync Complete. {count} new items identified.", "success")
    return redirect(request.referrer or url_for('monitoring.index'))

@monitoring_bp.route('/about')
@login_required
def about():
    return render_template('about.html')
