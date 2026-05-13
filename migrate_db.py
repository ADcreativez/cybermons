import sqlite3
import os

# Path ke database Cybermon
db_path = 'instance/cybermon.db'

if not os.path.exists(db_path):
    print(f"ERROR: Database not found at {db_path}")
    exit(1)

try:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    print(f"Checking table schema for 'inventory'...")
    
    # Check if category column already exists
    cursor.execute("PRAGMA table_info(inventory)")
    columns = [column[1] for column in cursor.fetchall()]
    
    if 'category' not in columns:
        print("Column 'category' missing. Adding now...")
        cursor.execute("ALTER TABLE inventory ADD COLUMN category VARCHAR(100) DEFAULT 'Brand'")
        conn.commit()
        print("SUCCESS: Column 'category' added to 'inventory' table.")
    else:
        print("INFO: Column 'category' already exists. No action needed.")
        
    conn.close()
    print("\nDatabase migration completed successfully. You can now restart the server.")

except Exception as e:
    print(f"MIGRATION ERROR: {str(e)}")
