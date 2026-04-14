import sqlite3
import os
from datetime import datetime

db_path = 'instance/cybermon_v2.db'
if not os.path.exists(db_path):
    db_path = 'cybermon_v2.db'

if os.path.exists(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Check if columns exist
    cursor.execute("PRAGMA table_info(user)")
    columns = [col[1] for col in cursor.fetchall()]
    
    if 'mfa_secret' not in columns:
        cursor.execute('ALTER TABLE user ADD COLUMN mfa_secret VARCHAR(32)')
        print("Added mfa_secret column")
        
    if 'mfa_enabled' not in columns:
        cursor.execute('ALTER TABLE user ADD COLUMN mfa_enabled BOOLEAN DEFAULT 0')
        print("Added mfa_enabled column")

    if 'created_at' not in columns:
        # Default existing users to a time in the past to avoid immediate lockout if desired, 
        # but here we'll just use current time for new ones.
        # For existing, let's set it to now.
        cursor.execute('ALTER TABLE user ADD COLUMN created_at DATETIME')
        now_str = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute(f"UPDATE user SET created_at = '{now_str}' WHERE created_at IS NULL")
        print("Added created_at column and initialized existing users.")
        
    if 'is_active_account' not in columns:
        cursor.execute('ALTER TABLE user ADD COLUMN is_active_account BOOLEAN DEFAULT 1')
        print("Added is_active_account column")
        
    conn.commit()
    conn.close()
    print("Migration complete.")
else:
    print(f"Database not found at {db_path}")
