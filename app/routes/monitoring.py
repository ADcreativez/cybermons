import feedparser
import dateutil.parser
from flask import Blueprint, render_template, request, redirect, url_for, abort, jsonify
from flask_login import login_required, current_user
from datetime import datetime
from ..extensions import db
from ..models import Threat, DismissedAlert
from ..utils.helpers import load_feeds, save_feeds, determine_severity, log_event

monitoring_bp = Blueprint('monitoring', __name__)

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
