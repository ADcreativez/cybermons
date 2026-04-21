import pyotp
import qrcode
import io
import base64
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, login_required, logout_user, current_user
from datetime import datetime
from ..extensions import db, login_manager
from ..models import User, UserGroup, Threat, Contribution
from ..utils.helpers import log_event, determine_severity
from ..utils.scrapers import fetch_url_metadata, calculate_relevance

auth_bp = Blueprint('auth', __name__)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('monitoring.index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            if not user.mfa_enabled:
                time_diff = datetime.utcnow() - user.created_at
                if time_diff.total_seconds() > 86400:
                    user.is_active_account = False
                    db.session.commit()
                    log_event(f"User {user.username} disabled due to missing MFA after 24h.", "danger")
            
            if not user.is_active_account:
                flash('Account disabled. Please contact administrator.', 'danger')
                return redirect(url_for('auth.login'))

            if user.mfa_enabled:
                session['mfa_user_id'] = user.id
                return redirect(url_for('auth.mfa_verify'))
            
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('monitoring.index'))
        else:
            flash('Invalid username or password', 'danger')
            
    return render_template('login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('mfa_user_id', None)
    return redirect(url_for('auth.login'))

@auth_bp.route('/login/mfa', methods=['GET', 'POST'])
def mfa_verify():
    mfa_user_id = session.get('mfa_user_id')
    if not mfa_user_id:
        return redirect(url_for('auth.login'))
    
    user = User.query.get(mfa_user_id)
    if not user:
        return redirect(url_for('auth.login'))
        
    if request.method == 'POST':
        token = request.form.get('token')
        totp = pyotp.TOTP(user.mfa_secret)
        if totp.verify(token):
            session.pop('mfa_user_id', None)
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('monitoring.index'))
        else:
            flash('Invalid MFA token', 'danger')
            
    return render_template('mfa_verify.html')

@auth_bp.route('/settings/mfa/setup')
@login_required
def mfa_setup():
    if current_user.mfa_enabled:
        flash('MFA is already enabled.', 'info')
        return redirect(url_for('auth.profile'))
        
    if not current_user.mfa_secret:
        current_user.mfa_secret = pyotp.random_base32()
        db.session.commit()
    
    totp = pyotp.TOTP(current_user.mfa_secret)
    provisioning_uri = totp.provisioning_uri(name=current_user.username, issuer_name="Cybermon")
    
    img = qrcode.make(provisioning_uri)
    img_io = io.BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    img_base64 = base64.b64encode(img_io.getvalue()).decode('utf-8')
    
    return render_template('mfa_setup.html', qr_code=img_base64, secret=current_user.mfa_secret)

@auth_bp.route('/settings/mfa/enable', methods=['POST'])
@login_required
def mfa_enable():
    token = request.form.get('token')
    totp = pyotp.TOTP(current_user.mfa_secret)
    
    if totp.verify(token):
        current_user.mfa_enabled = True
        db.session.commit()
        flash('MFA has been successfully enabled!', 'success')
        log_event(f"User {current_user.username} enabled MFA.", "info")
    else:
        flash('Invalid verification token. MFA not enabled.', 'danger')
        
    return redirect(url_for('auth.profile'))

@auth_bp.route('/settings/mfa/disable', methods=['POST'])
@login_required
def mfa_disable():
    current_user.mfa_enabled = False
    current_user.mfa_secret = None
    db.session.commit()
    flash('MFA has been disabled.', 'warning')
    log_event(f"User {current_user.username} disabled MFA.", "warning")
    return redirect(url_for('auth.profile'))

@auth_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    return render_template('profile.html')

@auth_bp.route('/profile/change-password', methods=['POST'])
@login_required
def change_password():
    old_password = request.form.get('old_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    
    if not current_user.check_password(old_password):
        flash('Incorrect current password', 'danger')
    elif new_password != confirm_password:
        flash('New passwords do not match', 'danger')
    else:
        current_user.set_password(new_password)
        db.session.commit()
        flash('Password updated successfully!', 'success')
        log_event(f"User {current_user.username} updated their password.", "info")
        
    return redirect(url_for('auth.profile'))

@auth_bp.route('/profile/contribute', methods=['POST'])
@login_required
def contribute_link():
    url = request.form.get('url')
    category = request.form.get('category', 'threat')
    
    # 1. Detect and Handle Telegram Links
    if 't.me/' in url or 'telegram.me/' in url:
        handle = url.strip('/').split('/')[-1]
        if 's/' in url: handle = url.split('/s/')[-1].split('/')[0]
        
        from .monitoring import scrape_telegram_source
        messages = scrape_telegram_source(handle)
        
        if not messages:
            flash(f'No public messages found for Telegram channel: @{handle}', 'warning')
            return redirect(url_for('auth.profile'))
            
        added_count = 0
        for msg in messages:
            # Check for duplicate link
            if Contribution.query.filter_by(url=msg['link']).first(): continue
            
            score, is_relevant = calculate_relevance(f"{msg['title']} {msg['summary']}")
            
            new_contribution = Contribution(
                user_id=current_user.id, url=msg['link'],
                title=msg['title'], summary=msg['summary'],
                category=category, relevance_score=score,
                status='approved' if is_relevant else 'rejected'
            )
            db.session.add(new_contribution)
            
            if is_relevant:
                severity = determine_severity(msg['title'], msg['summary'], category=category)
                new_threat = Threat(
                    title=f"[COMMUNITY/TG] {msg['title']}", link=msg['link'],
                    published=msg['published'],
                    published_str=msg['published'].strftime("%Y-%m-%d %H:%M"),
                    summary=msg['summary'], source=f"Contributor: {current_user.username} (via TG)",
                    severity=severity, category=category
                )
                db.session.add(new_threat)
                added_count += 1
                
        db.session.commit()
        if added_count > 0:
            flash(f'Success! Synchronized {added_count} security updates from Telegram channel @{handle}.', 'success')
            log_event(f"COMMUNITY TG SYNC: User {current_user.username} synced {added_count} items from @{handle}", "success")
        else:
            flash('Telegram channel scanned, but no security-relevant messages were found.', 'info')
        return redirect(url_for('auth.profile'))

    # 2. Standard URL Processing (Single Link)
    # Check for duplicate
    existing = Contribution.query.filter_by(url=url).first()
    if existing:
        flash('This URL has already been submitted.', 'info')
        return redirect(url_for('auth.profile'))

    # Process Link
    metadata = fetch_url_metadata(url)
    if not metadata:
        flash('Failed to fetch content from the provided URL.', 'danger')
        return redirect(url_for('auth.profile'))
        
    # Security Relevance Check
    text_to_check = f"{metadata['title']} {metadata['summary']}"
    score, is_relevant = calculate_relevance(text_to_check)
    
    new_contribution = Contribution(
        user_id=current_user.id,
        url=url,
        title=metadata['title'],
        summary=metadata['summary'],
        category=category,
        relevance_score=score,
        status='approved' if is_relevant else 'rejected'
    )
    
    db.session.add(new_contribution)
    
    if is_relevant:
        # Add to Global Threat Inventory
        severity = determine_severity(metadata['title'], metadata['summary'], category=category)
        new_threat = Threat(
            title=f"[COMMUNITY] {metadata['title']}",
            link=url,
            published=datetime.utcnow(),
            published_str=datetime.utcnow().strftime("%Y-%m-%d %H:%M"),
            summary=metadata['summary'],
            source=f"Contributor: {current_user.username}",
            severity=severity,
            category=category
        )
        db.session.add(new_threat)
        flash('Thank you! Your contribution has been verified and added to the dashboard.', 'success')
        log_event(f"COMMUNITY CONTRIBUTION: User {current_user.username} added {url}", "success")
    else:
        flash('Contribution received, but it does not appear to be security-related. System rejected.', 'warning')
        log_event(f"REJECTED CONTRIBUTION: User {current_user.username} submitted irrelevant link: {url}", "warning")
        
    db.session.commit()
    return redirect(url_for('auth.profile'))
