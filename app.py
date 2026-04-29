import logging
import sqlite3
from functools import wraps
from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
import jwt
import datetime
from database import init_db, get_db_connection

app = Flask(__name__)
# Secret key for JWT
app.config['SECRET_KEY'] = 'super-secret-secureshield-key'

bcrypt = Bcrypt(app)

# Setup Defensive Logging (Task 6)
logger = logging.getLogger('security')
logger.setLevel(logging.WARNING)
file_handler = logging.FileHandler('security.log')
formatter = logging.Formatter('%(asctime)s - UNAUTHORIZED ATTEMPT (403) - %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# Initialize Database on startup
with app.app_context():
    init_db()

def token_required(f):
    """Task 3: Token Validation Decorator"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Check if Authorization header is present
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(" ")[1]
            else:
                token = auth_header
                
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
            
        try:
            # Check if token is blacklisted (Task 5)
            conn = get_db_connection()
            blacklist_entry = conn.execute('SELECT * FROM blacklist WHERE token = ?', (token,)).fetchone()
            conn.close()
            
            if blacklist_entry:
                return jsonify({'message': 'Token has been revoked/logged out. Please login again.'}), 401

            # Decode token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = {
                'username': data['username'],
                'role': data['role']
            }
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid! Signature validation failed.'}), 401
            
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/register', methods=['POST'])
def register():
    """Task 1: Secure Password Storage"""
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password') or not data.get('role'):
        return jsonify({'message': 'Missing fields: username, password, role are required'}), 400
        
    username = data.get('username')
    password = data.get('password')
    role = data.get('role')
    
    # Validation for role
    if role not in ['User', 'Admin']:
        return jsonify({'message': 'Role must be either "User" or "Admin"'}), 400
        
    # Salt and hash password using Bcrypt
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    
    try:
        conn = get_db_connection()
        conn.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                     (username, hashed_password, role))
        conn.commit()
        conn.close()
        return jsonify({'message': 'User created successfully!'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'message': 'Username already exists'}), 409

@app.route('/login', methods=['POST'])
def login():
    """Task 2: JWT Issuance"""
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Missing username or password'}), 400
        
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (data.get('username'),)).fetchone()
    conn.close()
    
    if not user:
        return jsonify({'message': 'Invalid username or password'}), 401
        
    # Verify password hash
    if bcrypt.check_password_hash(user['password_hash'], data.get('password')):
        # Generate JWT Token containing username and role
        token = jwt.encode({
            'username': user['username'],
            'role': user['role'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        return jsonify({'token': token})
        
    return jsonify({'message': 'Invalid username or password'}), 401

@app.route('/logout', methods=['POST'])
@token_required
def logout(current_user):
    """Task 5: Token Revocation (Blacklisting)"""
    auth_header = request.headers['Authorization']
    token = auth_header.split(" ")[1] if auth_header.startswith('Bearer ') else auth_header
    
    # Add token to blacklist
    conn = get_db_connection()
    try:
        conn.execute('INSERT INTO blacklist (token) VALUES (?)', (token,))
        conn.commit()
    except sqlite3.IntegrityError:
        pass # Token already blacklisted
    finally:
        conn.close()
    
    return jsonify({'message': 'Successfully logged out. Token revoked.'}), 200

@app.route('/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    """Task 4: Accessible by both User and Admin"""
    return jsonify({
        'message': f"Welcome back, {current_user['username']}!",
        'user_data': {
            'username': current_user['username'],
            'role': current_user['role']
        }
    })

@app.route('/user/<int:id>', methods=['DELETE'])
@token_required
def delete_user(current_user, id):
    """Task 4: Accessible ONLY by the Admin role"""
    if current_user['role'] != 'Admin':
        # Task 6: Defensive Logging
        logger.warning(f"User '{current_user['username']}' with role '{current_user['role']}' attempted to access DELETE /user/{id}")
        return jsonify({'message': 'Access Denied: Admins only. Forbidden.'}), 403
        
    # Admin deletion logic
    conn = get_db_connection()
    target_user = conn.execute('SELECT * FROM users WHERE id = ?', (id,)).fetchone()
    
    if not target_user:
        conn.close()
        return jsonify({'message': 'User not found!'}), 404
        
    if target_user['username'] == current_user['username']:
        conn.close()
        return jsonify({'message': 'Cannot delete your own admin account.'}), 400
        
    conn.execute('DELETE FROM users WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    
    return jsonify({'message': f"User with ID {id} has been deleted."}), 200

if __name__ == '__main__':
    app.run(debug=True, port=5000)
