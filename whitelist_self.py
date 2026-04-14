import sys
import os
from app import create_app
from app.extensions import db
from app.models import IPAccessControl, BlockedCountry, GeoSettings

def fix_lockout(ip_to_whitelist=None):
    app = create_app()
    with app.app_context():
        print("--- Cybermon Lockout Recovery ---")
        
        # 1. Remove US from Blocked Countries
        us_block = BlockedCountry.query.filter_by(country_code='US').first()
        if us_block:
            db.session.delete(us_block)
            print("✓ Removed 'United States' from blocked countries.")
        else:
            print("- United States is not currently blocked.")

        # 2. Disable Whitelist Mode (ensure it is in Blacklist mode)
        settings = GeoSettings.query.first()
        if settings and settings.is_whitelist_mode:
            settings.is_whitelist_mode = False
            print("✓ Changed Geo-blocking mode to BLACKLIST (Allow all except blocked).")

        # 3. Whitelist specific IP if provided
        if ip_to_whitelist:
            existing = IPAccessControl.query.filter_by(ip=ip_to_whitelist).first()
            if existing:
                existing.category = 'whitelist'
                existing.reason = 'Manual Recovery Whitelist'
            else:
                new_wl = IPAccessControl(ip=ip_to_whitelist, category='whitelist', reason='Manual Recovery Whitelist')
                db.session.add(new_wl)
            print(f"✓ IP {ip_to_whitelist} has been WHITELISTED.")

        db.session.commit()
        print("--- Recovery Complete. Please refresh your browser. ---")

if __name__ == "__main__":
    ip = sys.argv[1] if len(sys.argv) > 1 else None
    fix_lockout(ip)
