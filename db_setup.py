from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os

# Initialize Flask App
app = Flask(__name__)

# PostgreSQL Database Configuration

DB_URI = "postgresql://postgres:omar@localhost:5432/network_data"  # Updated with correct password
app.config['SQLALCHEMY_DATABASE_URI'] = DB_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize Database
db = SQLAlchemy(app)

# ============================ DATABASE MODELS ============================ #

class User(db.Model):
    __tablename__ = 'users'
    email = db.Column(db.String(100), primary_key=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

class Device(db.Model):
    __tablename__ = 'devices'
    device_id = db.Column(db.String(100), primary_key=True)
    device_name = db.Column(db.String(100))
    last_seen = db.Column(db.DateTime, default=db.func.current_timestamp())

class UserDevice(db.Model):
    __tablename__ = 'user_devices'
    user_email = db.Column(db.String(100), db.ForeignKey('users.email', ondelete="CASCADE"), primary_key=True)
    device_id = db.Column(db.String(100), db.ForeignKey('devices.device_id', ondelete="CASCADE"), primary_key=True)
    added_at = db.Column(db.DateTime, default=db.func.current_timestamp())

class Session(db.Model):
    __tablename__ = 'sessions'
    session_id = db.Column(db.String(100), primary_key=True)
    user_email = db.Column(db.String(100), db.ForeignKey('users.email', ondelete="CASCADE"))
    device_id = db.Column(db.String(100), db.ForeignKey('devices.device_id', ondelete="CASCADE"))
    ip_address = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    expires_at = db.Column(db.DateTime, nullable=False)

class NetworkData(db.Model):
    __tablename__ = 'network_data'
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(100), db.ForeignKey('users.email', ondelete="CASCADE"))
    device_id = db.Column(db.String(100), db.ForeignKey('devices.device_id', ondelete="CASCADE"))
    operator = db.Column(db.String(100))
    signal_power = db.Column(db.Integer)
    sinr = db.Column(db.Integer)
    network_type = db.Column(db.String(10))
    frequency_band = db.Column(db.String(50))
    cell_id = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

# Create Tables
with app.app_context():
    db.create_all()
    print("Database and tables created successfully!")
