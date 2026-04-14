import os
from flask import Flask
from .extensions import db, login_manager, migrate
from .middleware import security_check
from .models import User, UserGroup

def create_app():
    app = Flask(__name__, instance_relative_config=True)
    
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
