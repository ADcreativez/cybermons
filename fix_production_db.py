import sqlite3
import os

def fix_db():
    # Identify the database path
    # On the server, it should be in instance/cybermon_v2.db
    # We check relative and absolute paths
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
    
    db_path = None
    for path in db_paths:
        if os.path.exists(path):
            db_path = path
            break
    
    if not db_path:
        print("[-] Error: Could not find cybermon_v2.db.")
        print(f"[*] Looked in: {db_paths}")
        print("[*] Current directory: " + os.getcwd())
        return

    print(f"[*] Found database at: {os.path.abspath(db_path)}")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        # 1. Check geo_settings columns
        print("[*] Checking geo_settings table...")
        cursor.execute("PRAGMA table_info(geo_settings)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if not columns:
            print("[-] Table 'geo_settings' does not exist yet.")
        else:
            # Missing columns to add
            updates = {
                'secret_knock_max': 'INTEGER DEFAULT 3',
                'rate_limit_max': 'INTEGER DEFAULT 60',
                'auto_ban_duration': 'INTEGER DEFAULT 0',
                'is_strict_ip_mode': 'BOOLEAN DEFAULT 0'
            }
            
            for col_name, col_def in updates.items():
                if col_name not in columns:
                    print(f"[+] Adding column {col_name} to geo_settings...")
                    cursor.execute(f"ALTER TABLE geo_settings ADD COLUMN {col_name} {col_def}")
                    conn.commit()
                else:
                    print(f"[-] Column {col_name} already exists.")

        # 2. Check for contribution table
        print("[*] Checking contribution table...")
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='contribution'")
        if not cursor.fetchone():
            print("[+] Creating contribution table...")
            cursor.execute("""
                CREATE TABLE contribution (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, 
                    user_id INTEGER NOT NULL, 
                    url VARCHAR(500) NOT NULL, 
                    title VARCHAR(300), 
                    summary TEXT, 
                    category VARCHAR(50), 
                    status VARCHAR(20), 
                    relevance_score INTEGER, 
                    created_at DATETIME, 
                    FOREIGN KEY(user_id) REFERENCES user (id)
                )
            """)
            conn.commit()
        else:
            print("[-] Table 'contribution' already exists.")

        print("[!] Database repair process finished.")

    except Exception as e:
        print(f"[!] Error during repair: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    fix_db()
