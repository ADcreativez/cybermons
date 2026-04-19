import os
import shutil
import base64
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, abort, flash, jsonify, send_file, current_app
from flask_login import login_required, current_user
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from ..extensions import db
from ..models import User, UserGroup, SystemLog, VisitorLog, IPAccessControl, GeoSettings, BlockedCountry
from ..utils.helpers import load_feeds, save_feeds, load_darkweb_config, save_darkweb_config, log_event

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/settings')
@login_required
def settings():
    if current_user.role != 'admin': abort(403)
    feeds = load_feeds()
    logs = SystemLog.query.order_by(SystemLog.timestamp.desc()).limit(100).all()
    return render_template('settings.html', feeds=feeds, logs=logs, darkweb_config=load_darkweb_config())

@admin_bp.route('/admin/users')
@login_required
def users():
    if current_user.role != 'admin': abort(403)
    return render_template('user_management.html', users=User.query.all(), groups=UserGroup.query.all())

@admin_bp.route('/admin/users/add', methods=['POST'])
@login_required
def add_user():
    if current_user.role != 'admin': abort(403)
    username = request.form.get('username')
    password = request.form.get('password')
    role = request.form.get('role', 'user')
    if User.query.filter_by(username=username).first():
        flash('Username exists', 'danger')
    else:
        new_user = User(username=username, role=role, group_id=request.form.get('group_id'))
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        log_event(f'User {username} added.', 'success')
    return redirect(url_for('admin.users'))

@admin_bp.route('/admin/antibot')
@login_required
def antibot():
    if current_user.role != 'admin': abort(403)
    logs = VisitorLog.query.order_by(VisitorLog.timestamp.desc()).limit(500).all()
    blacklist = IPAccessControl.query.filter_by(category='blacklist').order_by(IPAccessControl.timestamp.desc()).all()
    whitelist = IPAccessControl.query.filter_by(category='whitelist').order_by(IPAccessControl.timestamp.desc()).all()
    geo_settings = GeoSettings.query.first() or GeoSettings(is_whitelist_mode=False)
    countries = [
        ('CN', 'China'), ('RU', 'Russia'), ('US', 'United States'), ('KP', 'North Korea'),
        ('IR', 'Iran'), ('BR', 'Brazil'), ('UA', 'Ukraine'), ('VN', 'Vietnam'),
        ('IN', 'India'), ('ID', 'Indonesia'), ('SG', 'Singapore'), ('MY', 'Malaysia'),
        ('TR', 'Turkey'), ('NL', 'Netherlands'), ('DE', 'Germany'), ('GB', 'United Kingdom'),
        ('FR', 'France'), ('IL', 'Israel'), ('TH', 'Thailand'), ('JP', 'Japan')
    ]
    blocked_codes = [c.country_code for c in BlockedCountry.query.all()]
    return render_template('antibot.html', logs=logs, blacklist=blacklist, whitelist=whitelist, countries=countries, blocked_codes=blocked_codes, geo_settings=geo_settings)

@admin_bp.route('/settings/darkweb-keys', methods=['POST'])
@login_required
def save_keys():
    if current_user.role != 'admin': abort(403)
    config = load_darkweb_config()
    # API Keys
    for key in ['hibp_api_key', 'intelx_api_key', 'hudsonrock_api_key', 'criminalip_api_key',
                'vt_api_key', 'abuseipdb_api_key', 'checkphish_api_key', 'urlscan_api_key',
                'abuse_ch_api_key', 'breachdirectory_api_key']:
        # Get list of inputs with same name, strip and filter empty
        values = [v.strip() for v in request.form.getlist(key) if v.strip()]
        config[key] = ','.join(values)
    # Visibility toggles
    for toggle in ['show_credentials', 'show_ransomware', 'show_paste', 'show_stealer',
                   'show_passwords', 'show_infra', 'show_defacements', 'show_ioc_intel',
                   'show_wayback', 'show_infra_recon', 'show_breach_intel']:
        config[toggle] = toggle in request.form
    config['sync_interval'] = int(request.form.get('sync_interval', 360))
    save_darkweb_config(config)
    flash('Settings updated.', 'success')
    return redirect(url_for('admin.settings'))

@admin_bp.route('/settings/test_feed', methods=['POST'])
@login_required
def test_feed():
    import feedparser
    import requests as req
    url = request.json.get('url', '').strip()
    
    # Handle Telegram Testing
    if url.startswith('telegram://') or 't.me/' in url:
        handle = url.replace('telegram://', '').split('/')[-1]
        try:
            # Quick check if channel is accessible and has preview
            test_url = f"https://t.me/s/{handle}"
            r = req.get(test_url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
            if r.status_code == 200 and ('tgme_widget_message_wrap' in r.text or 'tgme_channel_info_header' in r.text):
                # Repair status if successful
                feeds = load_feeds()
                for f in feeds:
                    if f['url'] == url:
                        f['status'] = 'OK'
                        f['last_error'] = None
                        break
                save_feeds(feeds)
                return jsonify({'success': True, 'message': f"Telegram channel @{handle} is active and accessible."})
            else:
                return jsonify({'success': False, 'message': f"Channel @{handle} not found or has no public preview."})
        except Exception as e:
            return jsonify({'success': False, 'message': f"Connection error: {str(e)}"})

    # Handle NVD Testing
    if url.startswith('nvd://'):
        try:
            # Simple check of NVD API availability
            r = req.get("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1", timeout=10)
            if r.status_code == 200:
                feeds = load_feeds()
                for f in feeds:
                    if f['url'] == url:
                        f['status'] = 'OK'
                        f['last_error'] = None
                        break
                save_feeds(feeds)
                return jsonify({'success': True, 'message': "NVD API is reachable and responding correctly."})
            else:
                return jsonify({'success': False, 'message': f"NVD API returned error status: {r.status_code}"})
        except Exception as e:
            return jsonify({'success': False, 'message': f"NVD Connection error: {str(e)}"})

    # Handle Exploit-DB Testing
    if url.startswith('exploitdb://'):
        try:
            # Simple check of GitLab mirror availability
            r = req.get("https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv", timeout=10, stream=True)
            if r.status_code == 200:
                feeds = load_feeds()
                for f in feeds:
                    if f['url'] == url:
                        f['status'] = 'OK'
                        f['last_error'] = None
                        break
                save_feeds(feeds)
                return jsonify({'success': True, 'message': "Exploit-DB GitLab mirror is reachable and responding correctly."})
            else:
                return jsonify({'success': False, 'message': f"GitLab returned error status: {r.status_code}"})
        except Exception as e:
            return jsonify({'success': False, 'message': f"Exploit-DB Connection error: {str(e)}"})

    # Handle CISA KEV Testing
    if url.startswith('cisakev://'):
        try:
            r = req.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=10, stream=True, verify=False)
            if r.status_code == 200:
                feeds = load_feeds()
                for f in feeds:
                    if f['url'] == url:
                        f['status'] = 'OK'
                        f['last_error'] = None
                        break
                save_feeds(feeds)
                return jsonify({'success': True, 'message': "CISA KEV official feed is reachable and responding correctly."})
            else:
                return jsonify({'success': False, 'message': f"CISA Server returned error status: {r.status_code}"})
        except Exception as e:
            return jsonify({'success': False, 'message': f"CISA KEV Connection error: {str(e)}"})

    # Standard RSS testing
    try:
        # Use requests with User-Agent and verify=False to avoid being blocked by security sites with cert issues
        r = req.get(url, timeout=15, headers={'User-Agent': 'Mozilla/5.0'}, verify=False)
        if r.status_code != 200:
            return jsonify({'success': False, 'message': f"Mirror/Server returned HTTP {r.status_code}"})
            
        feed = feedparser.parse(r.text)
        if feed.entries:
            # Repair status if successful
            feeds = load_feeds()
            for f in feeds:
                if f['url'] == url:
                    f['status'] = 'OK'
                    f['last_error'] = None
                    break
            save_feeds(feeds)
            
            return jsonify({
                'success': True,
                'message': f"Available. Found {len(feed.entries)} entries.",
                'title': feed.feed.title if hasattr(feed.feed, 'title') else 'Unknown Title'
            })
        elif feed.bozo:
            return jsonify({'success': False, 'message': f"Parse Error: {feed.bozo_exception}"})
        else:
            return jsonify({'success': False, 'message': "Source accessible but no items found."})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@admin_bp.route('/settings/logs/clear', methods=['POST'])
@login_required
def clear_system_logs():
    if current_user.role != 'admin': abort(403)
    num = db.session.query(SystemLog).delete()
    db.session.commit()
    log_event(f"Logs cleared ({num} entries).", "success")
    return redirect(url_for('admin.settings'))

@admin_bp.route('/settings/logs/delete/<int:id>', methods=['POST'])
@login_required
def delete_log(id):
    if current_user.role != 'admin': abort(403)
    log = SystemLog.query.get_or_404(id)
    db.session.delete(log)
    db.session.commit()
    return redirect(url_for('admin.settings'))

@admin_bp.route('/settings/feeds/add', methods=['POST'])
@login_required
def add_feed():
    if current_user.role != 'admin': abort(403)
    url = request.form.get('url', '').strip()
    category = request.form.get('category', 'threat')
    
    if url:
        # Normalize Telegram Inputs
        if url.startswith('@'):
            url = f"telegram://{url[1:]}"
        elif 't.me/' in url:
            # Handles https://t.me/s/channel, https://t.me/channel, etc.
            handle = url.strip('/').split('/')[-1]
            url = f"telegram://{handle}"
            
        feeds = load_feeds()
        if not any(f['url'] == url for f in feeds):
            feeds.append({"url": url, "status": "OK", "last_checked": None, "category": category})
            save_feeds(feeds)
            flash('Feed added.', 'success')
    return redirect(url_for('admin.settings'))

@admin_bp.route('/settings/feeds/remove', methods=['POST'])
@login_required
def remove_feed():
    if current_user.role != 'admin': abort(403)
    url = request.form.get('url')
    if url:
        feeds = load_feeds()
        feeds = [f for f in feeds if f['url'] != url]
        save_feeds(feeds)
        flash('Feed removed.', 'success')
    return redirect(url_for('admin.settings'))

@admin_bp.route('/admin/users/reset-password/<int:id>', methods=['POST'])
@login_required
def admin_reset_password(id):
    if current_user.role != 'admin': abort(403)
    user = User.query.get_or_404(id)
    new_password = request.form.get('new_password')
    if new_password:
        user.set_password(new_password)
        db.session.commit()
        log_event(f"Admin reset password for user {user.username}", "warning")
        flash(f"Password for {user.username} has been reset.", "success")
    return redirect(url_for('admin.users'))

@admin_bp.route('/admin/antibot/ip/add', methods=['POST'])
@login_required
def add_ip():
    if current_user.role != 'admin': abort(403)
    ip = request.form.get('ip')
    category = request.form.get('category') 
    reason = request.form.get('reason', 'Manual Entry')
    if ip and category:
        existing = IPAccessControl.query.filter_by(ip=ip).first()
        if existing:
            existing.category = category
            existing.reason = reason
        else:
            new_ip = IPAccessControl(ip=ip, category=category, reason=reason)
            db.session.add(new_ip)
        db.session.commit()
        log_event(f"IP {ip} added to {category}.", "success")
    return redirect(url_for('admin.antibot'))

@admin_bp.route('/admin/antibot/ip/delete/<int:id>', methods=['POST'])
@login_required
def delete_ip(id):
    if current_user.role != 'admin': abort(403)
    ip_entry = IPAccessControl.query.get_or_404(id)
    ip_val = ip_entry.ip
    db.session.delete(ip_entry)
    db.session.commit()
    log_event(f"IP {ip_val} removed.", "info")
    return redirect(url_for('admin.antibot'))

@admin_bp.route('/admin/antibot/geo/update', methods=['POST'])
@login_required
def update_geo():
    if current_user.role != 'admin': abort(403)
    db.session.query(BlockedCountry).delete()
    selected_codes = request.form.getlist('blocked_countries')
    for code in selected_codes:
        new_block = BlockedCountry(country_code=code)
        db.session.add(new_block)
    db.session.commit()
    log_event("Geo-blocking policy updated.", "success")
    return redirect(url_for('admin.antibot'))

@admin_bp.route('/admin/antibot/geo/mode', methods=['POST'])
@login_required
def geo_mode():
    if current_user.role != 'admin': abort(403)
    mode = request.form.get('mode')
    settings = GeoSettings.query.first() or GeoSettings(is_whitelist_mode=False)
    settings.is_whitelist_mode = (mode == 'whitelist')
    db.session.add(settings) 
    db.session.commit()
    log_event(f"Geo-Blocking mode changed to {mode.upper()}.", "info")
    return redirect(url_for('admin.antibot'))

@admin_bp.route('/admin/antibot/logs/clear', methods=['POST'])
@login_required
def clear_visitor_logs():
    if current_user.role != 'admin': abort(403)
    db.session.query(VisitorLog).delete()
    db.session.commit()
    log_event("Visitor logs cleared.", "success")
    return redirect(url_for('admin.antibot'))

@admin_bp.route('/admin/groups/add', methods=['POST'])
@login_required
def add_group():
    if current_user.role != 'admin': abort(403)
    name = request.form.get('group_name')
    if name:
        if UserGroup.query.filter_by(name=name).first():
            log_event('Group already exists.', 'warning')
        else:
            new_group = UserGroup(name=name)
            db.session.add(new_group)
            db.session.commit()
            log_event(f'Group "{name}" created.', 'success')
    return redirect(url_for('admin.users'))

@admin_bp.route('/admin/users/delete/<int:id>', methods=['POST'])
@login_required
def delete_user(id):
    if current_user.role != 'admin': abort(403)
    user = User.query.get_or_404(id)
    if user.id == current_user.id:
        flash('Cannot delete your own account.', 'warning')
    else:
        username = user.username
        db.session.delete(user)
        db.session.commit()
        log_event(f'User {username} deleted.', 'warning')
    return redirect(url_for('admin.users'))

@admin_bp.route('/admin/users/toggle/<int:id>', methods=['POST'])
@login_required
def toggle_user_status(id):
    if current_user.role != 'admin': abort(403)
    user = User.query.get_or_404(id)
    if user.id != current_user.id:
        user.is_active_account = not user.is_active_account
        db.session.commit()
        status = "enabled" if user.is_active_account else "disabled"
        log_event(f"User {user.username} has been {status} by admin.", "info")
    return redirect(url_for('admin.users'))

def derive_key(password: str) -> bytes:
    # A static system salt is required so the encryption and decryption match across boots.
    salt = b'cybermon_static_system_salt_9x2@'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

@admin_bp.route('/settings/database/export', methods=['POST'])
@login_required
def export_database():
    if current_user.role != 'admin': abort(403)
    
    pwd = request.form.get('admin_password')
    if not pwd or not current_user.check_password(pwd):
        flash("Invalid Admin Password.", "danger")
        return redirect(url_for('admin.settings'))

    db_path = os.path.join(current_app.instance_path, 'cybermon_v2.db')
    if os.path.exists(db_path):
        key = derive_key(pwd)
        f = Fernet(key)
        
        with open(db_path, 'rb') as dbf:
            data = dbf.read()
            
        encrypted_data = f.encrypt(data)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"cybermon_v2_backup_{timestamp}.db.enc"
        
        # Save temp encrypted file
        enc_path = os.path.join(current_app.instance_path, filename)
        with open(enc_path, 'wb') as ef:
            ef.write(encrypted_data)
            
        log_event("Encrypted Database exported by admin.", "info")
        return send_file(enc_path, as_attachment=True, download_name=filename)
    else:
        flash("Database file not found.", "danger")
        return redirect(url_for('admin.settings'))

@admin_bp.route('/settings/database/import', methods=['POST'])
@login_required
def import_database():
    if current_user.role != 'admin': abort(403)
    
    # 1. Clear any existing session issues
    db.session.rollback()
    
    pwd = request.form.get('admin_password')
    if not pwd or not current_user.check_password(pwd):
        flash("Invalid Encryption Password.", "danger")
        return redirect(url_for('admin.settings'))

    if 'database' not in request.files:
        flash("No file part provided.", "danger")
        return redirect(url_for('admin.settings'))
        
    db_file = request.files['database']
    if db_file.filename == '':
        flash("No selected file.", "danger")
        return redirect(url_for('admin.settings'))
        
    if db_file and db_file.filename.endswith('.enc'):
        db_path = os.path.join(current_app.instance_path, 'cybermon_v2.db')
        backup_path = os.path.join(current_app.instance_path, 'cybermon_v2.db.bak')
        temp_path = os.path.join(current_app.instance_path, 'temp_upload.db')
        
        try:
            # Read uploaded file
            encrypted_data = db_file.read()
            key = derive_key(pwd)
            f = Fernet(key)
            
            try:
                decrypted_data = f.decrypt(encrypted_data)
            except Exception:
                flash("Decryption failed: Incorrect Password or Corrupted Backup File.", "danger")
                return redirect(url_for('admin.settings'))
                
            # 1. Save decrypted file to temp path
            with open(temp_path, 'wb') as tf:
                tf.write(decrypted_data)
            
            # 2. Backup current DB if it exists
            if os.path.exists(db_path):
                shutil.copy2(db_path, backup_path)
                
            # 3. Terminate all active database handles
            # remove() clears the session registry for this thread
            db.session.remove()
            db.engine.dispose()
            
            # 4. Swap database files
            shutil.move(temp_path, db_path)
            
            # 5. Fix file permissions to ensure it is WRITABLE by the web server
            try:
                os.chmod(db_path, 0o664)
            except Exception as pe:
                print(f"Warning: Could not set permissions on db: {pe}")
            
            # 6. Re-initiate connection with a clean commit
            log_event("Encrypted Database decrypted and successfully imported.", "success")
            flash("Encrypted Database successfully decrypted and restored.", "success")
            
        except Exception as e:
            db.session.rollback()
            flash(f"Error during import: {str(e)}", "danger")
            log_event(f"Database import failed: {str(e)}", "danger")
            
    else:
        flash("Invalid file format. Must be a .enc file.", "danger")
        
    return redirect(url_for('admin.settings'))
