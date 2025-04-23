from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_socketio import SocketIO, emit
from datetime import datetime, timedelta
import bcrypt
import uuid
import socket

# Initialize Flask App
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")  # Enable real-time logs

# PostgreSQL Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:omar@localhost:5432/network_data"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'supersecret'  # Change in production

# Import database instance & models from db_setup.py
from db_setup import db, User, Device, UserDevice, Session, NetworkData

# Initialize the database with Flask app
db.init_app(app)

# Initialize JWT Manager
jwt = JWTManager(app)

# Store API logs
api_logs = []

def create_or_update_session(user_email, duration_hours=24):
    """Create a new session or update existing one for the user."""
    try:
        # Find existing session
        session = Session.query.filter_by(user_email=user_email).order_by(Session.created_at.desc()).first()
        current_time = datetime.now()
        
        if session and session.expires_at > current_time:
            # Update existing session
            session.expires_at = current_time + timedelta(hours=duration_hours)
        else:
            # Create new session with a unique session_id
            session = Session(
                session_id=str(uuid.uuid4()),  # Generate a unique session ID
                user_email=user_email,
                created_at=current_time,
                expires_at=current_time + timedelta(hours=duration_hours)
            )
            db.session.add(session)
        
        db.session.commit()
        return session
    except Exception as e:
        print(f"Error in create_or_update_session: {str(e)}")
        db.session.rollback()
        raise

# ============================ AUTHENTICATION ============================ #

@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        
        # Validate required fields
        if 'email' not in data or 'password' not in data:
            return jsonify({"msg": "email and password are required"}), 422
            
        # Validate email format
        if '@' not in data['email'] or '.' not in data['email']:
            return jsonify({"msg": "Invalid email format"}), 422
            
        # Check if user already exists
        existing_user = User.query.filter_by(email=data['email']).first()
        if existing_user:
            print(f"Signup failed: User with email {data['email']} already exists")
            return jsonify({"msg": "User already exists"}), 409
            
        # Hash password
        hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Create new user
        new_user = User(
            email=data['email'],
            password_hash=hashed_password
        )
        
        try:
            db.session.add(new_user)
            db.session.commit()
            print(f"User {data['email']} created successfully")
            return jsonify({"msg": "User created successfully"}), 201
        except Exception as e:
            print(f"Error creating user: {str(e)}")
            db.session.rollback()
            return jsonify({"msg": f"Error creating user: {str(e)}"}), 500
            
    except Exception as e:
        print(f"Signup error: {str(e)}")
        return jsonify({"msg": f"Server error: {str(e)}"}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        session_duration_hours = data.get('session_duration_hours', 24)  # Default to 24 hours if not specified

        if not email or not password:
            return jsonify({"msg": "Missing email or password"}), 400

        user = User.query.filter_by(email=email).first()
        if not user or not bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            return jsonify({"msg": "Invalid email or password"}), 401

        # Create or update session with specified duration
        session = create_or_update_session(email, session_duration_hours)
        
        # Create access token that expires with the session
        expires_delta = timedelta(hours=session_duration_hours)
        access_token = create_access_token(identity=email, expires_delta=expires_delta)
        
        return jsonify({
            "access_token": access_token,
            "user": {
                "email": user.email
            },
            "expires_at": session.expires_at.isoformat()
        }), 200
    except Exception as e:
        print(f"Error in login: {str(e)}")
        return jsonify({"msg": f"Server error: {str(e)}"}), 500

@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    user_email = get_jwt_identity()
    log_event(f"Refreshing token for user {user_email}")
    user = User.query.filter_by(email=user_email).first()
    
    if not user:
        log_event(f"User not found for email: {user_email}", error=True)
        return jsonify({"message": "User not found"}), 404
    
    # Create a new access token
    new_token = create_access_token(identity=user_email, expires_delta=timedelta(hours=24))
    
    return jsonify({
        "access_token": new_token,
        "user": {
            "email": user.email
        },
        "expires_in": 86400
    }), 200

@app.route('/signout', methods=['POST'])
@jwt_required()
def signout():
    try:
        user_email = get_jwt_identity()
        
        # Find the user's current session
        session = Session.query.filter_by(user_email=user_email).order_by(Session.created_at.desc()).first()
        if session:
            # Update the session's expiry time to current time instead of deleting
            session.expires_at = datetime.now()
            db.session.commit()
            
        return jsonify({"msg": "Successfully signed out"}), 200
    except Exception as e:
        print(f"Error in signout: {str(e)}")
        return jsonify({"msg": f"Server error: {str(e)}"}), 500

# ============================ DEVICE MANAGEMENT ============================ #

@app.route('/register_device', methods=['POST'])
@jwt_required()
def register_device():
    try:
        user_email = get_jwt_identity()
        data = request.get_json()
        
        # Validate required fields
        if 'device_id' not in data or 'device_name' not in data:
            return jsonify({"msg": "device_id and device_name are required"}), 422
        
        # Check if device already exists
        device = Device.query.filter_by(device_id=data['device_id']).first()
        if not device:
            # Create new device
            device = Device(
                device_id=data['device_id'],
                device_name=data['device_name']
            )
            try:
                db.session.add(device)
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                return jsonify({"msg": f"Error creating device: {str(e)}"}), 500
        
        # Check if user-device relationship already exists
        user_device = UserDevice.query.filter_by(
            user_email=user_email,
            device_id=data['device_id']
        ).first()
        
        if not user_device:
            # Create new user-device relationship
            user_device = UserDevice(
                user_email=user_email,
                device_id=data['device_id']
            )
            try:
                db.session.add(user_device)
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                return jsonify({"msg": f"Error creating user-device relationship: {str(e)}"}), 500
        
        return jsonify({"msg": "Device registered successfully"}), 200
        
    except Exception as e:
        return jsonify({"msg": f"Server error: {str(e)}"}), 500

# ============================ NETWORK DATA COLLECTION ============================ #

@app.route('/submit_data', methods=['POST'])
@jwt_required()
def submit_data():
    try:
        user_email = get_jwt_identity()
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['device_id', 'operator', 'signal_power', 'sinr', 'network_type', 'frequency_band', 'cell_id']
        for field in required_fields:
            if field not in data:
                return jsonify({"msg": f"Missing required field: {field}"}), 422
        
        # Validate data types
        try:
            signal_power = int(data['signal_power'])
            sinr = int(data['sinr'])
        except ValueError:
            return jsonify({"msg": "signal_power and sinr must be integers"}), 422
        
        # Get the client's IP address
        ip_address = request.remote_addr
        
        # Update existing session with device_id and ip_address
        session = Session.query.filter_by(user_email=user_email).order_by(Session.created_at.desc()).first()
        if session:
            session.device_id = data['device_id']
            session.ip_address = ip_address
            session.last_activity = datetime.now()
            db.session.commit()
        
        # Create new network data entry
        new_data = NetworkData(
            user_email=user_email,
            device_id=data['device_id'],
            operator=data['operator'],
            signal_power=signal_power,
            sinr=sinr,
            network_type=data['network_type'],
            frequency_band=data['frequency_band'],
            cell_id=data['cell_id']
        )
        
        try:
            db.session.add(new_data)
            db.session.commit()
            return jsonify({"msg": "Data stored successfully"}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({"msg": f"Database error: {str(e)}"}), 500
            
    except Exception as e:
        return jsonify({"msg": f"Server error: {str(e)}"}), 500

# ============================ DASHBOARD DATA ENDPOINT ============================ #
@app.route('/dashboard_data', methods=['GET'])
def dashboard_data():
    # Get current users and devices from the database
    users = [{"email": user.email} for user in User.query.all()]
    devices = [{"device_name": device.device_name, "device_id": device.device_id} for device in Device.query.all()]
    
    # Get the count of connected devices (devices with active sessions)
    current_time = datetime.now()
    active_sessions = Session.query.filter(Session.expires_at > current_time).all()
    connected_devices_count = len(set([session.device_id for session in active_sessions if session.device_id]))
    
    # Get IP addresses of previously and currently connected devices
    device_ips = []
    device_sessions = {}
    
    for session in Session.query.order_by(Session.created_at.desc()).all():
        if session.device_id and session.ip_address:
            # Only add each device once (most recent session)
            if session.device_id not in device_sessions:
                device = Device.query.get(session.device_id)
                device_name = device.device_name if device else "Unknown Device"
                
                device_sessions[session.device_id] = {
                    "device_id": session.device_id,
                    "device_name": device_name,
                    "ip_address": session.ip_address,
                    "last_active": session.created_at.isoformat(),
                    "is_active": session.expires_at > current_time
                }
    
    device_ips = list(device_sessions.values())
    
    # Get per-device statistics
    device_stats = {}
    for device_id in device_sessions.keys():
        # Get latest network data for this device
        latest_data = NetworkData.query.filter_by(device_id=device_id).order_by(NetworkData.timestamp.desc()).first()
        
        # Calculate average signal power and SINR
        avg_data = db.session.query(
            db.func.avg(NetworkData.signal_power).label('avg_signal'),
            db.func.avg(NetworkData.sinr).label('avg_sinr'),
            db.func.count(NetworkData.id).label('count')
        ).filter_by(device_id=device_id).first()
        
        if latest_data and avg_data:
            device_stats[device_id] = {
                "last_operator": latest_data.operator,
                "last_network_type": latest_data.network_type,
                "last_signal_power": latest_data.signal_power,
                "last_sinr": latest_data.sinr,
                "frequency_band": latest_data.frequency_band,
                "avg_signal_power": round(avg_data.avg_signal, 2) if avg_data.avg_signal else None,
                "avg_sinr": round(avg_data.avg_sinr, 2) if avg_data.avg_sinr else None,
                "data_points": avg_data.count
            }
    
    logs = api_logs[-20:]  # Last 20 log entries
    return jsonify({
        "users": users, 
        "devices": devices, 
        "logs": logs,
        "connected_devices_count": connected_devices_count,
        "device_ips": device_ips,
        "device_stats": device_stats
    })

# ============================ SERVER DASHBOARD PAGE ============================ #

@app.route('/')
def dashboard():
    # Render the dashboard page (the data will be fetched via AJAX)
    return render_template('dashboard.html')

# ============================ STATISTICS ENDPOINTS ============================ #

@app.route('/get_statistics', methods=['POST'])
def get_statistics():
    try:
        data = request.get_json()
        print(f"Received statistics request, data: {data}")
        
        # Check if there's authentication
        auth_header = request.headers.get('Authorization')
        user_email = None
        
        if auth_header and auth_header.startswith('Bearer '):
            # If authenticated, get the user from the token
            try:
                from flask_jwt_extended import decode_token
                token = auth_header.replace('Bearer ', '')
                user_claims = decode_token(token)
                user_email = user_claims.get('sub')  # 'sub' contains the user identity
                print(f"Authenticated request from: {user_email}")
            except Exception as e:
                print(f"Token validation error: {str(e)}")
                # Continue as unauthenticated
                pass
        
        # Validate required fields
        if 'start_date' not in data or 'end_date' not in data:
            return jsonify({"msg": "start_date and end_date are required"}), 422
            
        # Try different date formats
        date_formats = [
            '%Y-%m-%dT%H:%M:%S',  # ISO format with T separator
            '%Y-%m-%dT%H:%M',     # ISO format without seconds
            '%Y-%m-%d %H:%M:%S',  # Space separator with time
            '%Y-%m-%d',           # Just date
            '%Y/%m/%d',          
            '%d-%m-%Y',
            '%d/%m/%Y'
        ]
        
        start_date = None
        end_date = None
        
        # Try to parse start date
        for fmt in date_formats:
            try:
                start_date = datetime.strptime(data['start_date'], fmt)
                print(f"Parsed start_date with format {fmt}: {start_date}")
                break
            except ValueError:
                continue
                
        # Try to parse end date
        for fmt in date_formats:
            try:
                end_date = datetime.strptime(data['end_date'], fmt)
                print(f"Parsed end_date with format {fmt}: {end_date}")
                break
            except ValueError:
                continue
                
        if not start_date or not end_date:
            print(f"Date parsing failed - start_date: {data['start_date']}, end_date: {data['end_date']}")
            return jsonify({
                "msg": "Invalid date format. Supported formats: YYYY-MM-DD, YYYY-MM-DD HH:MM:SS, YYYY/MM/DD, DD-MM-YYYY, DD/MM/YYYY"
            }), 422
            
        # Determine target user for data retrieval
        target_user = None
        
        # If user_email is specified in the request, use it
        if 'user_email' in data and data['user_email']:
            # For unauthenticated requests, allow viewing any user's data
            if not user_email:
                target_user = data['user_email']
                print(f"Unauthenticated request for user data: {target_user}")
            # For authenticated requests, check permissions
            else:
                # If user is viewing their own data
                if user_email == data['user_email']:
                    target_user = data['user_email']
                    print(f"User viewing own data: {target_user}")
                # If user is trying to view someone else's data
                else:
                    # Simple admin check - all users are considered admins for demo
                    all_users = User.query.all()
                    admin_emails = [user.email for user in all_users]
                    
                    if user_email in admin_emails:
                        # Admin can view any user's data
                        target_user = data['user_email']
                        print(f"Admin access granted to view {target_user}'s data")
                    else:
                        # Non-admins can only view their own data
                        print(f"Permission denied for {user_email} to view {data['user_email']}'s data")
                        return jsonify({"msg": "You don't have permission to view this user's data"}), 403
        # If no user_email in request but user is authenticated
        elif user_email:
            target_user = user_email
        else:
            # No user specified and not authenticated
            return jsonify({"msg": "Please select a user to view statistics"}), 400
        
        # Get all network data for the user within the date range
        network_data = NetworkData.query.filter(
            NetworkData.user_email == target_user,
            NetworkData.timestamp >= start_date,
            NetworkData.timestamp <= end_date
        ).all()
        
        # Initialize statistics
        statistics = {
            'total_entries': len(network_data),
            'network_types': {},
            'operators': {},
            'frequency_bands': {},
            'network_type_stats': {},
            'device_stats': {},
            'has_data': len(network_data) > 0,
            'message': 'No data available for the selected time range' if len(network_data) == 0 else None
        }
        
        if network_data:
            # Initialize counters for each network type and device
            for entry in network_data:
                network_type = entry.network_type
                device_id = entry.device_id
                
                # Initialize network type stats if not exists
                if network_type not in statistics['network_type_stats']:
                    statistics['network_type_stats'][network_type] = {
                        'count': 0,
                        'total_signal_power': 0,
                        'total_sinr': 0
                    }
                
                # Initialize device stats if not exists
                if device_id not in statistics['device_stats']:
                    statistics['device_stats'][device_id] = {
                        'count': 0,
                        'total_signal_power': 0,
                        'total_sinr': 0  # Added SINR tracking for devices
                    }
                
                # Update network type statistics
                network_stats = statistics['network_type_stats'][network_type]
                network_stats['count'] += 1
                network_stats['total_signal_power'] += entry.signal_power
                network_stats['total_sinr'] += entry.sinr
                
                # Update device statistics
                device_stats = statistics['device_stats'][device_id]
                device_stats['count'] += 1
                device_stats['total_signal_power'] += entry.signal_power
                device_stats['total_sinr'] += entry.sinr  # Update device SINR total
                
                # Count network types
                if network_type in statistics['network_types']:
                    statistics['network_types'][network_type] += 1
                else:
                    statistics['network_types'][network_type] = 1
                    
                # Count operators
                if entry.operator in statistics['operators']:
                    statistics['operators'][entry.operator] += 1
                else:
                    statistics['operators'][entry.operator] = 1
                    
                # Count frequency bands
                if entry.frequency_band in statistics['frequency_bands']:
                    statistics['frequency_bands'][entry.frequency_band] += 1
                else:
                    statistics['frequency_bands'][entry.frequency_band] = 1
            
            # Calculate averages for each network type
            for network_type, stats in statistics['network_type_stats'].items():
                stats['average_signal_power'] = stats['total_signal_power'] / stats['count']
                stats['average_sinr'] = stats['total_sinr'] / stats['count']
            
            # Calculate averages for each device
            for device_id, stats in statistics['device_stats'].items():
                stats['average_signal_power'] = stats['total_signal_power'] / stats['count']
                stats['average_sinr'] = stats['total_sinr'] / stats['count']  # Calculate average SINR for devices
        
        return jsonify(statistics), 200
    except Exception as e:
        print(f"Error in get_statistics: {str(e)}")
        return jsonify({"msg": f"Server error: {str(e)}"}), 500

@app.route('/statistics')
@jwt_required()
def statistics():
    # Get the current user's email
    user_email = get_jwt_identity()
    
    # Get the user's devices
    user_devices = UserDevice.query.filter_by(user_email=user_email).all()
    device_ids = [ud.device_id for ud in user_devices]
    
    # Get the user's network data
    network_data = NetworkData.query.filter(
        NetworkData.user_email == user_email,
        NetworkData.device_id.in_(device_ids)
    ).order_by(NetworkData.timestamp.desc()).limit(100).all()
    
    # Prepare the data for the template
    devices = []
    for device_id in device_ids:
        device = Device.query.get(device_id)
        if device:
            devices.append({
                'device_id': device.device_id,
                'device_name': device.device_name
            })
    
    return render_template('statistics.html', devices=devices, network_data=network_data)

# Updated route that doesn't require authentication
@app.route('/statistics_page')
def statistics_page():
    return render_template('statistics.html')

@app.route('/download_statistics', methods=['POST'])
@jwt_required()
def download_statistics():
    try:
        user_email = get_jwt_identity()
        data = request.get_json()
        
        # Validate required fields
        if 'start_date' not in data or 'end_date' not in data:
            return jsonify({"msg": "start_date and end_date are required"}), 422
            
        # Try different date formats
        date_formats = ['%Y-%m-%d', '%Y-%m-%d %H:%M:%S', '%Y/%m/%d', '%d-%m-%Y', '%d/%m/%Y']
        start_date = None
        end_date = None
        
        for fmt in date_formats:
            try:
                if not start_date:
                    start_date = datetime.strptime(data['start_date'], fmt)
                if not end_date:
                    end_date = datetime.strptime(data['end_date'], fmt)
            except ValueError:
                continue
                
        if not start_date or not end_date:
            return jsonify({
                "msg": "Invalid date format. Supported formats: YYYY-MM-DD, YYYY-MM-DD HH:MM:SS, YYYY/MM/DD, DD-MM-YYYY, DD/MM/YYYY"
            }), 422
            
        # Get all network data for the user within the date range
        network_data = NetworkData.query.filter(
            NetworkData.user_email == user_email,
            NetworkData.timestamp >= start_date,
            NetworkData.timestamp <= end_date
        ).all()
        
        if not network_data:
            return jsonify({"msg": "No data available for the selected time range"}), 404
            
        # Initialize statistics
        statistics = {
            'total_entries': len(network_data),
            'network_types': {},
            'operators': {},
            'frequency_bands': {},
            'network_type_stats': {},
            'device_stats': {}
        }
        
        # Calculate statistics
        for entry in network_data:
            # Network type statistics
            if entry.network_type not in statistics['network_types']:
                statistics['network_types'][entry.network_type] = 0
            statistics['network_types'][entry.network_type] += 1
            
            # Operator statistics
            if entry.operator not in statistics['operators']:
                statistics['operators'][entry.operator] = 0
            statistics['operators'][entry.operator] += 1
            
            # Network type detailed stats
            if entry.network_type not in statistics['network_type_stats']:
                statistics['network_type_stats'][entry.network_type] = {
                    'count': 0,
                    'total_signal_power': 0,
                    'total_sinr': 0
                }
            stats = statistics['network_type_stats'][entry.network_type]
            stats['count'] += 1
            stats['total_signal_power'] += entry.signal_power
            stats['total_sinr'] += entry.sinr
            
            # Device statistics
            if entry.device_id not in statistics['device_stats']:
                statistics['device_stats'][entry.device_id] = {
                    'count': 0,
                    'total_signal_power': 0,
                    'total_sinr': 0  # Added SINR tracking for devices
                }
            device_stats = statistics['device_stats'][entry.device_id]
            device_stats['count'] += 1
            device_stats['total_signal_power'] += entry.signal_power
            device_stats['total_sinr'] += entry.sinr  # Update device SINR total
        
        # Generate the text content
        text_content = f"Network Statistics Report\n"
        text_content += f"Generated for: {user_email}\n"
        text_content += f"Date Range: {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}\n\n"
        
        # Operator Statistics
        text_content += "Operator Connectivity Time:\n\n"
        for operator, count in statistics['operators'].items():
            percentage = (count / statistics['total_entries']) * 100
            text_content += f"{operator}: {percentage:.1f}%\n"
        text_content += "\n"
        
        # Network Type Statistics
        text_content += "Network Type Distribution:\n\n"
        for network_type, count in statistics['network_types'].items():
            percentage = (count / statistics['total_entries']) * 100
            text_content += f"{network_type}: {percentage:.1f}%\n"
        text_content += "\n"
        
        # Signal Power Statistics
        text_content += "Average Signal Power by Network Type:\n\n"
        for network_type, stats in statistics['network_type_stats'].items():
            avg_signal = stats['total_signal_power'] / stats['count']
            text_content += f"{network_type}: {avg_signal:.1f} dBm\n"
        text_content += "\n"
        
        # SINR Statistics
        text_content += "Average SINR by Network Type:\n\n"
        for network_type, stats in statistics['network_type_stats'].items():
            avg_sinr = stats['total_sinr'] / stats['count']
            text_content += f"{network_type}: {avg_sinr:.1f} dB\n"
        text_content += "\n"
        
        # Device Statistics
        text_content += "Device Statistics:\n\n"
        for device_id, stats in statistics['device_stats'].items():
            avg_signal = stats['total_signal_power'] / stats['count']
            avg_sinr = stats['total_sinr'] / stats['count']
            text_content += f"Device {device_id}:\n"
            text_content += f"• Signal Power: {avg_signal:.1f} dBm\n"
            text_content += f"• SINR: {avg_sinr:.1f} dB\n\n"
        
        # Create response with the text file
        from flask import make_response
        response = make_response(text_content)
        response.headers["Content-Disposition"] = f"attachment; filename=network_statistics_{start_date.strftime('%Y%m%d')}_{end_date.strftime('%Y%m%d')}.txt"
        response.headers["Content-type"] = "text/plain"
        
        return response
        
    except Exception as e:
        print(f"Error in download_statistics: {str(e)}")
        return jsonify({"msg": f"Server error: {str(e)}"}), 500

def log_event(message, error=False):
    """Stores logs and emits them in real-time."""
    log_type = "ERROR" if error else "INFO"
    log_entry = {"time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'), "type": log_type, "message": message}
    api_logs.append(log_entry)
    socketio.emit('log_update', log_entry)

# ============================ RUN FLASK SERVER ============================ #

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensures database tables are created
    
    # Print network interfaces to help with configuration
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    print(f"Server running on host: {hostname}")
    print(f"Host IP address: {ip_address}")
    print(f"Access URL: http://{ip_address}:9000")
    print(f"Use this IP in your Android app's NetworkManager.java")
    
    # Run the server on all interfaces
    socketio.run(app, debug=False, host='0.0.0.0', port=9000, allow_unsafe_werkzeug=True)

