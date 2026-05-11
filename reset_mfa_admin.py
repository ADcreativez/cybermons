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
            db.session.commit()
            print("[+] Success: MFA for user 'admin' has been reset.")
            print("[!] You can now login using only your password.")
        else:
            print("[-] Error: User 'admin' not found.")

if __name__ == "__main__":
    reset_admin_mfa()
