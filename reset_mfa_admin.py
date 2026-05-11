import sqlite3
import os

def force_reset_all_dbs():
    # List all possible database names and locations
    base_dir = os.path.abspath(os.path.dirname(__file__))
    db_paths = [
        os.path.join(base_dir, 'instance', 'cybermon_v2.db'),
        os.path.join(base_dir, 'instance', 'cybermon.db'),
        os.path.join(base_dir, 'cybermon_v2.db'),
        os.path.join(base_dir, 'cybermon.db'),
        'instance/cybermon_v2.db',
        'instance/cybermon.db',
        'cybermon_v2.db',
        'cybermon.db'
    ]
    
    found_any = False
    for path in db_paths:
        if os.path.exists(path):
            abs_path = os.path.abspath(path)
            print(f"[*] Attempting to fix database at: {abs_path}")
            try:
                conn = sqlite3.connect(abs_path)
                cursor = conn.cursor()
                
                # Reset admin MFA and Activate account
                cursor.execute("UPDATE user SET mfa_enabled=0, mfa_secret=NULL, is_active_account=1 WHERE username='admin'")
                
                if cursor.rowcount > 0:
                    conn.commit()
                    print(f"[+] SUCCESS: Fixed 'admin' in {path}")
                    found_any = True
                else:
                    print(f"[-] Warning: User 'admin' not found in {path}")
                
                conn.close()
            except Exception as e:
                print(f"[X] Error fixing {path}: {e}")
    
    if not found_any:
        print("[-] Critical Error: No database files found or 'admin' user not found in any of them.")
        print("[*] Please check your current directory with 'ls -R'")

if __name__ == "__main__":
    force_reset_all_dbs()
