from db_setup import db, User, Device, UserDevice, Session, NetworkData
from server import app

def reset_database():
    with app.app_context():
        # Drop all tables
        print("Dropping all tables...")
        db.drop_all()
        
        # Create all tables with new schema
        print("Creating tables with new schema...")
        db.create_all()
        
        print("Database reset complete!")

if __name__ == '__main__':
    reset_database() 