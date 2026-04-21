import os
from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix
from .extensions import db, login_manager, migrate
from .middleware import security_check
from .models import User, UserGroup

def create_app():
    app = Flask(__name__, instance_relative_config=True)
    
    # Handle Proxy headers
    app.wsgi_app = ProxyFix(
        app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
    )

    # Configuration
    app.config.from_mapping(
        SECRET_KEY='cybermon_secret_key',
        SQLALCHEMY_DATABASE_URI='sqlite:///' + os.path.join(app.instance_path, 'cybermon_v2.db'),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
    )

    # Ensure instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # Initialize Extensions
    db.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)

    # Automatic Schema Repair
    repair_database(app)

    # Register Blueprints
    from .routes.auth import auth_bp
    from .routes.monitoring import monitoring_bp
    from .routes.darkweb import darkweb_bp
    from .routes.inventory import inventory_bp
    from .routes.admin import admin_bp
    from .routes.mitre import mitre_bp
    from .routes.breach_intel import breach_intel_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(monitoring_bp)
    app.register_blueprint(darkweb_bp)
    app.register_blueprint(inventory_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(mitre_bp)
    app.register_blueprint(breach_intel_bp)

    # Apply Global Middleware
    @app.before_request
    def run_security_check():
        return security_check()

    # Shared Context Processors
    @app.context_processor
    def inject_common():
        from .utils.helpers import load_darkweb_config
        from .routes.inventory import get_inventory_alerts
        from flask_login import current_user
        from datetime import datetime
        
        config = load_darkweb_config()
        alert_count = 0
        mfa_warning = False
        mfa_remaining = 0
        
        if current_user.is_authenticated:
            alert_count = len(get_inventory_alerts(current_user.group_id))
            if not current_user.mfa_enabled:
                time_diff = datetime.utcnow() - current_user.created_at
                mfa_remaining = max(0, 86400 - int(time_diff.total_seconds()))
                mfa_warning = True
                
        return dict(
            darkweb_config=config, 
            alert_count=alert_count,
            mfa_warning=mfa_warning,
            mfa_remaining_seconds=mfa_remaining
        )

    return app

def repair_database(app):
    """
    Automatically repair the database schema by adding missing columns.
    This avoids OperationalErrors in production when models are updated.
    """
    from sqlalchemy import inspect, text
    with app.app_context():
        # Ensure all tables exist first
        db.create_all()
        
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        
        # Define all required column updates for existing tables
        schema_updates = {
            'geo_settings': {
                'secret_knock_max': 'INTEGER DEFAULT 3',
                'rate_limit_max': 'INTEGER DEFAULT 60',
                'auto_ban_duration': 'INTEGER DEFAULT 0',
                'is_strict_ip_mode': 'BOOLEAN DEFAULT 0'
            },
            'ip_access_control': {
                'expires_at': 'DATETIME'
            },
            'user': {
                'mfa_secret': 'VARCHAR(32)',
                'mfa_enabled': 'BOOLEAN DEFAULT 0',
                'is_active_account': 'BOOLEAN DEFAULT 1',
                'created_at': 'DATETIME'
            }
        }
        
        for table_name, columns_to_add in schema_updates.items():
            if table_name in tables:
                existing_columns = [c['name'] for c in inspector.get_columns(table_name)]
                for col_name, col_def in columns_to_add.items():
                    if col_name not in existing_columns:
                        print(f"[*] AUTO-REPAIR: Adding column {col_name} to {table_name}")
                        try:
                            db.session.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_def}"))
                            db.session.commit()
                        except Exception as e:
                            db.session.rollback()
                            print(f"[!] AUTO-REPAIR FAILED for {table_name}.{col_name}: {e}")

def bootstrap_db(app):
    with app.app_context():
        db.create_all()
        default_group = UserGroup.query.filter_by(name='INTERNAL_CORE').first()
        if not default_group:
            default_group = UserGroup(name='INTERNAL_CORE')
            db.session.add(default_group)
            db.session.commit()
        
        admin = User.query.filter_by(role='admin').first()
        if not admin:
            admin = User(username='admin', role='admin', group_id=default_group.id)
            admin.set_password('cybermon2026') 
            db.session.add(admin)
            db.session.commit()
