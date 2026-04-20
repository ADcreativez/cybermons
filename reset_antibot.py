import sys
import os
from app import create_app
from app.extensions import db
from app.models import IPAccessControl, GeoSettings, BlockedCountry, VisitorLog

def reset_all():
    app = create_app()
    with app.app_context():
        print("--- CYBERMON ANTIBOT EMERGENCY RESET ---")
        
        try:
            # 1. Clear IP Access Control (Whitelist & Blacklist)
            num_ip = db.session.query(IPAccessControl).delete()
            print(f"[*] Cleared {num_ip} IP Access Control entries.")
            
            # 2. Clear Blocked Countries
            num_geo = db.session.query(BlockedCountry).delete()
            print(f"[*] Cleared {num_geo} Geo-Blocking entries.")
            
            # 3. Reset Geo Settings Mode
            settings = GeoSettings.query.first()
            if settings:
                settings.is_whitelist_mode = False
                print("[*] Geo-Blocking Mode reset to BLACKLIST (Block Selected).")
            else:
                new_settings = GeoSettings(is_whitelist_mode=False)
                db.session.add(new_settings)
                print("[*] Initialized Geo-Blocking Mode to BLACKLIST.")
            
            # 4. Optional: Clear Visitor Logs (Comment out if not needed)
            # num_logs = db.session.query(VisitorLog).delete()
            # print(f"[*] Cleared {num_logs} Visitor Logs.")
            
            db.session.commit()
            print("\n[+] SUCCESS: All security barriers have been reset.")
            print("[+] SYSTEM ACCESS HAS BEEN OPENED TO ALL IPs.")
            
        except Exception as e:
            db.session.rollback()
            print(f"\n[!] ERROR: Could not reset settings: {str(e)}")
            sys.exit(1)

if __name__ == "__main__":
    reset_all()
