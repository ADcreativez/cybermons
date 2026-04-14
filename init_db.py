from app import app, db, IOCCache
with app.app_context():
    db.create_all()
    print("Database tables initialized successfully.")
