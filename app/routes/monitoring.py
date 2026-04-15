import feedparser
import dateutil.parser
from flask import Blueprint, render_template, request, redirect, url_for, abort, jsonify
from flask_login import login_required, current_user
from datetime import datetime
from ..extensions import db
from ..models import Threat, DismissedAlert
from ..utils.helpers import load_feeds, save_feeds, determine_severity, log_event

monitoring_bp = Blueprint('monitoring', __name__)

import asyncio
import requests
import re

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
    from datetime import timedelta
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

def fetch_and_store_threats(force=False):
    feeds = load_feeds()
    new_count = 0
    updated_feeds = []
    
    for feed_item in feeds:
        feed_url = feed_item.get('url')
        feed_category = feed_item.get('category', 'threat')
        
        if not force and feed_item.get('last_checked'):
            try:
                last_checked = datetime.strptime(feed_item['last_checked'], "%Y-%m-%d %H:%M:%S")
                time_diff = (datetime.now() - last_checked).total_seconds()
                if time_diff < 21600:
                    updated_feeds.append(feed_item)
                    continue
            except: pass
        
        try:
            # Detect NVD Source
            if feed_url.startswith('nvd://'):
                results = fetch_nvd_cves()
                feed_item['status'] = 'OK'
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
        except Exception as e:
            feed_item['status'] = 'Error'
            feed_item['last_error'] = str(e)
            feed_item['last_checked'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        updated_feeds.append(feed_item)
    
    save_feeds(updated_feeds)
    try:
        db.session.commit()
    except: db.session.rollback()
    return new_count

def render_dashboard(category_filter, page_title):
    severity_filter = request.args.get('severity')
    date_filter = request.args.get('date')
    source_filter = request.args.get('source')
    search_query = request.args.get('q')
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', '10', type=str) 
    
    per_page = 1000 if limit == 'all' else int(limit) if limit.isdigit() else 10

    fetch_and_store_threats(force=False)

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
    
    sources = [s[0] for s in db.session.query(Threat.source).filter_by(category=category_filter).distinct().all()]
    
    stats = {
        'total': Threat.query.filter_by(category=category_filter).count(),
        'critical': Threat.query.filter_by(category=category_filter, severity='Critical').count(),
        'high': Threat.query.filter_by(category=category_filter, severity='High').count(),
        'medium': Threat.query.filter_by(category=category_filter, severity='Medium').count(),
        'low': Threat.query.filter_by(category=category_filter, severity='Low').count(),
        'info': Threat.query.filter_by(category=category_filter, severity='Info').count()
    }
    
    return render_template('index.html', 
                           threats=threats, stats=stats, 
                           current_severity=severity_filter, current_date=date_filter,
                           current_source=source_filter, current_search=search_query,
                           pagination=pagination, current_limit=limit,
                           sources=sources, page_title=page_title,
                           current_category=category_filter)

@monitoring_bp.route('/')
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
