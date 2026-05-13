import sqlite3
import os

# Mencoba beberapa kemungkinan path database
possible_paths = [
    'instance/cybermon.db',
    'cybermon.db',
    '../instance/cybermon.db',
    '/home/security/Tools/Cybermons/instance/cybermon.db'
]

db_path = None
for path in possible_paths:
    if os.path.exists(path):
        db_path = path
        break

if not db_path:
    print("ERROR: Database file not found in any common locations.")
    exit(1)

print(f"Using database found at: {db_path}")

try:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # List all tables to see what we have
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [t[0] for t in cursor.fetchall()]
    print(f"Available tables: {', '.join(tables)}")
    
    # Check for inventory table (case-insensitive)
    target_table = next((t for t in tables if t.lower() == 'inventory'), None)
    
    if target_table:
        print(f"Checking table schema for '{target_table}'...")
        cursor.execute(f"PRAGMA table_info({target_table})")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'category' not in columns:
            print(f"Column 'category' missing in '{target_table}'. Adding now...")
            cursor.execute(f"ALTER TABLE {target_table} ADD COLUMN category VARCHAR(100) DEFAULT 'Brand'")
            conn.commit()
            print(f"SUCCESS: Column 'category' added to '{target_table}' table.")
        else:
            print(f"INFO: Column 'category' already exists in '{target_table}'. No action needed.")
    else:
        print("ERROR: Table 'inventory' not found in database.")
        
    conn.close()
    print("\nDatabase migration process finished.")

except Exception as e:
    print(f"MIGRATION ERROR: {str(e)}")
