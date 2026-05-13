import sqlite3
import os
import glob

# Cari semua file .db di proyek
db_files = glob.glob("**/*.db", recursive=True)

if not db_files:
    print("ERROR: No .db files found in the project.")
    exit(1)

print(f"Found {len(db_files)} database files. Starting global migration...\n")

for db_path in db_files:
    print(f"--- Processing: {db_path} ---")
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get list of tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [t[0] for t in cursor.fetchall()]
        
        # Check for inventory table (case-insensitive)
        target_table = next((t for t in tables if t.lower() == 'inventory'), None)
        
        if target_table:
            print(f"Table '{target_table}' found. Checking schema...")
            cursor.execute(f"PRAGMA table_info({target_table})")
            columns = [column[1] for column in cursor.fetchall()]
            
            if 'category' not in columns:
                print(f"Column 'category' missing. Adding now...")
                cursor.execute(f"ALTER TABLE {target_table} ADD COLUMN category VARCHAR(100) DEFAULT 'Brand'")
                conn.commit()
                print(f"SUCCESS: Migration applied to {db_path}")
            else:
                print(f"INFO: Column 'category' already exists. Skipping.")
        else:
            print(f"SKIP: Table 'inventory' not found in this file.")
            
        conn.close()
    except Exception as e:
        print(f"ERROR processing {db_path}: {str(e)}")
    print("-" * (15 + len(db_path)))

print("\nGlobal database migration process finished. Please restart your server.")
