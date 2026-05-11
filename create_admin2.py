import sqlite3
import os
from werkzeug.security import generate_password_hash

def create_backup_admin():
    # New Simple Credentials
    password = 'admin123'
    password_hash = generate_password_hash(password)
    usernames = ['admin', 'admin2']
    
    # List all possible database names and locations
    base_dir = os.path.abspath(os.path.dirname(__file__))
    db_paths = [
        os.path.join(base_dir, 'instance', 'cybermon_v2.db'),
        os.path.join(base_dir, 'instance', 'cybermon.db'),
        os.path.join(base_dir, 'cybermon_v2.db'),
        os.path.join(base_dir, 'cybermon.db')
    ]
    
    found_any = False
    for path in db_paths:
        if os.path.exists(path):
            abs_path = os.path.abspath(path)
            print(f"[*] Scanning database: {abs_path}")
            try:
                conn = sqlite3.connect(abs_path)
                cursor = conn.cursor()
                
                # 1. Get the default group ID (INTERNAL_CORE)
                cursor.execute("SELECT id FROM user_group WHERE name='INTERNAL_CORE'")
                group_res = cursor.fetchone()
                group_id = group_res[0] if group_res else 1
                
                for username in usernames:
                    # 2. Check if user exists
                    cursor.execute("SELECT id FROM user WHERE username=?", (username,))
                    if cursor.fetchone():
                        print(f"[+] Updating existing user '{username}' in {path}...")
                        cursor.execute("UPDATE user SET password_hash=?, role='admin', is_active_account=1, mfa_enabled=0 WHERE username=?", 
                                     (password_hash, username))
                    else:
                        # 3. Insert new admin
                        cursor.execute("""
                            INSERT INTO user (username, password_hash, role, group_id, mfa_enabled, is_active_account, created_at)
                            VALUES (?, ?, 'admin', ?, 0, 1, datetime('now'))
                        """, (username, password_hash, group_id))
                        print(f"[+] SUCCESS: Created new user '{username}' in {path}")
                
                conn.commit()
                conn.close()
                found_any = True
            except Exception as e:
                print(f"[X] Error processing {path}: {e}")
    
    if found_any:
        print("\n[!] Master Reset Finished.")
        print(f"[!] You can now login with:")
        print(f"    Username : admin ATAU admin2")
        print(f"    Password : {password}")
    else:
        print("[-] Error: No database files found.")

if __name__ == "__main__":
    create_backup_admin()
