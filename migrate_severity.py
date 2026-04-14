import os
import sys
from app import app, db, Threat, determine_severity

def migrate():
    print("--- Cybermon Severity Migration (5-Level) ---")
    with app.app_context():
        # Get all threats
        threats = Threat.query.all()
        total = len(threats)
        print(f"Found {total} threats to process.")
        
        updated_count = 0
        counts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Info': 0
        }
        
        for threat in threats:
            old_severity = threat.severity
            new_severity = determine_severity(threat.title, threat.summary, category=threat.category)
            
            if old_severity != new_severity:
                threat.severity = new_severity
                updated_count += 1
            
            if new_severity in counts:
                counts[new_severity] += 1
            else:
                counts[new_severity] = 1
            
            if updated_count % 100 == 0 and updated_count > 0:
                print(f"Processed {updated_count} updates...")

        db.session.commit()
        
        print("\nMigration Complete!")
        print(f"Total Updates: {updated_count}")
        print(f"New Status Distribution:")
        # Sort by standard order
        order = ['Critical', 'High', 'Medium', 'Low', 'Info']
        for sev in order:
            if sev in counts:
                print(f" - {sev}: {counts[sev]}")

if __name__ == '__main__':
    migrate()
