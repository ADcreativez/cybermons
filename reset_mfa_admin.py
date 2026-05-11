import os
from app import create_app, db
from app.models import User

def reset_admin_mfa():
    app = create_app()
    with app.app_context():
        admin = User.query.filter_by(username='admin').first()
        if admin:
            admin.mfa_enabled = False
            admin.mfa_secret = None
            admin.is_active_account = True # Re-activate the account
            db.session.commit()
            print("[+] Success: MFA for user 'admin' has been reset and account REACTIVATED.")
            print("[!] You can now login using only your password.")
        else:
            print("[-] Error: User 'admin' not found.")

if __name__ == "__main__":
    reset_admin_mfa()
