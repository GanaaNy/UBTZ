from flask import Flask, request, jsonify
from flask_cors import CORS
import hashlib
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend requests

# Secret key for JWT tokens (in production, use environment variable)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'

# Mock user database (in production, use a real database)
# Format: username -> {'password_hash': ..., 'role': ..., 'name': ...}
USERS = {
    'admin': {
        'password_hash': hashlib.sha256('admin123'.encode()).hexdigest(),
        'role': 'admin',
        'name': 'Админ',
        'department': 'УБТЗ'
    },
    'master': {
        'password_hash': hashlib.sha256('master123'.encode()).hexdigest(),
        'role': 'master',
        'name': 'Мастер',
        'department': 'УБТЗ'
    },
    'accountant': {
        'password_hash': hashlib.sha256('accountant123'.encode()).hexdigest(),
        'role': 'accountant',
        'name': 'Нягтлан',
        'department': 'УБТЗ'
    }
}


def generate_token(username, user_data):
    """Generate JWT token for authenticated user"""
    payload = {
        'username': username,
        'role': user_data['role'],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')


@app.route('/api/login', methods=['POST'])
def login():
    """Handle user login"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'message': 'Мэдээлэл оруулаагүй байна'}), 400
        
        username = data.get('username', '').strip()
        password = data.get('password', '')
        remember_me = data.get('rememberMe', False)
        
        # Validate input
        if not username or not password:
            return jsonify({'message': 'Хэрэглэгчийн нэр болон нууц үг шаардлагатай'}), 400
        
        # Check if user exists
        if username not in USERS:
            return jsonify({'message': 'Хэрэглэгчийн нэр эсвэл нууц үг буруу байна'}), 401
        
        user = USERS[username]
        
        # Verify password
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if password_hash != user['password_hash']:
            return jsonify({'message': 'Хэрэглэгчийн нэр эсвэл нууц үг буруу байна'}), 401
        
        # Generate token
        token = generate_token(username, user)
        
        # Prepare user data (without password)
        user_data = {
            'username': username,
            'name': user['name'],
            'role': user['role'],
            'department': user['department']
        }
        
        return jsonify({
            'message': 'Амжилттай нэвтэрлээ',
            'token': token,
            'user': user_data,
            'redirect': '/dashboard.html'
        }), 200
        
    except Exception as e:
        print(f"Login error: {str(e)}")
        return jsonify({'message': 'Серверийн алдаа гарлаа'}), 500


@app.route('/api/verify', methods=['GET'])
def verify_token():
    """Verify JWT token"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    
    if not token:
        return jsonify({'valid': False}), 401
    
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        username = payload.get('username')
        
        if username in USERS:
            user = USERS[username]
            return jsonify({
                'valid': True,
                'user': {
                    'username': username,
                    'name': user['name'],
                    'role': user['role'],
                    'department': user['department']
                }
            }), 200
        else:
            return jsonify({'valid': False}), 401
            
    except jwt.ExpiredSignatureError:
        return jsonify({'valid': False, 'message': 'Токен хүчинтэй хугацаа дууссан'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'valid': False, 'message': 'Хүчингүй токен'}), 401


@app.route('/api/logout', methods=['POST'])
def logout():
    """Handle user logout"""
    return jsonify({'message': 'Амжилттай гарлаа'}), 200


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'ok'}), 200


if __name__ == '__main__':
    print("Starting login server...")
    print("Test users:")
    print("  - admin / admin123")
    print("  - master / master123")
    print("  - accountant / accountant123")
    app.run(debug=True, host='0.0.0.0', port=5000)

