from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from .extensions import db

class Threat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(300), nullable=False)
    link = db.Column(db.String(500), unique=True, nullable=False)
    published = db.Column(db.DateTime, nullable=True)
    published_str = db.Column(db.String(100))
    summary = db.Column(db.Text, nullable=True)
    source = db.Column(db.String(100))
    severity = db.Column(db.String(20))
    category = db.Column(db.String(50), default='threat')

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'link': self.link,
            'published': self.published_str,
            'summary': self.summary,
            'source': self.source,
            'severity': self.severity,
            'category': self.category
        }

class UserGroup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    users = db.relationship('User', backref='group', lazy=True)
    inventory_items = db.relationship('Inventory', backref='group', lazy=True)

class SystemLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    message = db.Column(db.String(500), nullable=False)
    category = db.Column(db.String(20), default='info')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    user = db.relationship('User', backref='logs', lazy=True)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')
    group_id = db.Column(db.Integer, db.ForeignKey('user_group.id'), nullable=True)
    mfa_secret = db.Column(db.String(32), nullable=True)
    mfa_enabled = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active_account = db.Column(db.Boolean, default=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Inventory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('user_group.id'), nullable=False)
    brand = db.Column(db.String(100), nullable=False)
    module = db.Column(db.String(100), nullable=False)
    version = db.Column(db.String(50))
    added_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    added_by = db.relationship('User', foreign_keys=[added_by_id])

class VisitorLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(50), nullable=False)
    user_agent = db.Column(db.String(500))
    device = db.Column(db.String(100))
    os = db.Column(db.String(100))
    browser = db.Column(db.String(100))
    path = db.Column(db.String(500))
    method = db.Column(db.String(10))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class IPAccessControl(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(50), unique=True, nullable=False)
    category = db.Column(db.String(20), nullable=False) # 'blacklist' or 'whitelist'
    reason = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class DismissedAlert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('user_group.id'), nullable=False)
    threat_id = db.Column(db.Integer, db.ForeignKey('threat.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    group = db.relationship('UserGroup', backref='dismissals', lazy=True)
    threat = db.relationship('Threat', backref='dismissals', lazy=True)

class BlockedCountry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    country_code = db.Column(db.String(5), unique=True, nullable=False)
    country_name = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class GeoSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    is_whitelist_mode = db.Column(db.Boolean, default=False)
    is_strict_ip_mode = db.Column(db.Boolean, default=False)
    secret_knock_key = db.Column(db.String(50), default='1337')

class IOCCache(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    indicator = db.Column(db.String(255), unique=True, nullable=False)
    ioc_type = db.Column(db.String(50), nullable=False)
    results_json = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
