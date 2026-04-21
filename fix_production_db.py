import sqlite3
import os

def fix_db():
    # Identify the database path
    # On the server, it should be in instance/cybermon_v2.db
    # We check common locations
    db_paths = [
        'instance/cybermon_v2.db',
        'instance/cybermon.db',
        'cybermon.db'
    ]
    
    db_path = None
    for path in db_paths:
        if os.path.exists(path):
            db_path = path
            break
    
    if not db_path:
        print("[-] Could not find cybermon_v2.db in instance/ or root.")
        return

    print(f"[*] Found database at: {db_path}")
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        # 1. Check geo_settings columns
        cursor.execute("PRAGMA table_info(geo_settings)")
        columns = [col[1] for col in cursor.fetchall()]
        
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
                print(f"[-] Column {col_name} already exists in geo_settings.")

        # 2. Check for contribution table
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='contribution'")
        if not cursor.fetchone():
            print("[+] Creating contribution table...")
            cursor.execute("""
                CREATE TABLE contribution (
                    id INTEGER NOT NULL, 
                    user_id INTEGER NOT NULL, 
                    url VARCHAR(500) NOT NULL, 
                    title VARCHAR(300), 
                    summary TEXT, 
                    category VARCHAR(50), 
                    status VARCHAR(20), 
                    relevance_score INTEGER, 
                    created_at DATETIME, 
                    PRIMARY KEY (id), 
                    FOREIGN KEY(user_id) REFERENCES user (id)
                )
            """)
            conn.commit()
        else:
            print("[-] Table 'contribution' already exists.")

        print("[!] Database repair completed successfully.")

    except Exception as e:
        print(f"[!] Error during repair: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    fix_db()
