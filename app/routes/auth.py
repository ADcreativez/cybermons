import pyotp
import qrcode
import io
import base64
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from flask_login import login_user, login_required, logout_user, current_user
from datetime import datetime
from ..extensions import db, login_manager
from ..models import User, UserGroup
from ..utils.helpers import log_event

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
        return redirect(url_for('auth.change_password'))
        
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
        
    return redirect(url_for('auth.change_password'))

@auth_bp.route('/settings/mfa/disable', methods=['POST'])
@login_required
def mfa_disable():
    current_user.mfa_enabled = False
    current_user.mfa_secret = None
    db.session.commit()
    flash('MFA has been disabled.', 'warning')
    log_event(f"User {current_user.username} disabled MFA.", "warning")
    return redirect(url_for('auth.change_password'))

@auth_bp.route('/profile/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
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
            return redirect(url_for('monitoring.index'))
            
    return render_template('change_password.html')
