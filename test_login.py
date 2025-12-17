import pytest
import json
import hashlib
import jwt
from datetime import datetime, timedelta
from login import app, USERS, generate_token


@pytest.fixture
def client():
    """Create a test client for the Flask application"""
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test-secret-key'
    with app.test_client() as client:
        yield client


@pytest.fixture
def valid_token():
    """Generate a valid JWT token for testing"""
    payload = {
        'username': 'admin',
        'role': 'admin',
        'exp': datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')


@pytest.fixture
def expired_token():
    """Generate an expired JWT token for testing"""
    payload = {
        'username': 'admin',
        'role': 'admin',
        'exp': datetime.utcnow() - timedelta(days=1)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')


class TestLoginEndpoint:
    """Test cases for /api/login endpoint"""
    
    def test_successful_login_admin(self, client):
        """Test successful login with admin credentials"""
        response = client.post(
            '/api/login',
            data=json.dumps({
                'username': 'admin',
                'password': 'admin123',
                'rememberMe': False
            }),
            content_type='application/json'
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['message'] == 'Амжилттай нэвтэрлээ'
        assert 'token' in data
        assert data['user']['username'] == 'admin'
        assert data['user']['role'] == 'admin'
        assert data['user']['name'] == 'Админ'
        assert data['redirect'] == '/dashboard.html'
        assert 'password' not in data['user']
    
    def test_successful_login_master(self, client):
        """Test successful login with master credentials"""
        response = client.post(
            '/api/login',
            data=json.dumps({
                'username': 'master',
                'password': 'master123',
                'rememberMe': True
            }),
            content_type='application/json'
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['message'] == 'Амжилттай нэвтэрлээ'
        assert 'token' in data
        assert data['user']['username'] == 'master'
        assert data['user']['role'] == 'master'
    
    def test_successful_login_accountant(self, client):
        """Test successful login with accountant credentials"""
        response = client.post(
            '/api/login',
            data=json.dumps({
                'username': 'accountant',
                'password': 'accountant123'
            }),
            content_type='application/json'
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['user']['role'] == 'accountant'
        assert data['user']['name'] == 'Нягтлан'
    
    def test_login_invalid_username(self, client):
        """Test login with non-existent username"""
        response = client.post(
            '/api/login',
            data=json.dumps({
                'username': 'nonexistent',
                'password': 'admin123'
            }),
            content_type='application/json'
        )
        
        assert response.status_code == 401
        data = json.loads(response.data)
        assert 'Хэрэглэгчийн нэр эсвэл нууц үг буруу байна' in data['message']
    
    def test_login_invalid_password(self, client):
        """Test login with incorrect password"""
        response = client.post(
            '/api/login',
            data=json.dumps({
                'username': 'admin',
                'password': 'wrongpassword'
            }),
            content_type='application/json'
        )
        
        assert response.status_code == 401
        data = json.loads(response.data)
        assert 'Хэрэглэгчийн нэр эсвэл нууц үг буруу байна' in data['message']
    
    def test_login_missing_username(self, client):
        """Test login without username"""
        response = client.post(
            '/api/login',
            data=json.dumps({
                'password': 'admin123'
            }),
            content_type='application/json'
        )
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'Хэрэглэгчийн нэр болон нууц үг шаардлагатай' in data['message']
    
    def test_login_missing_password(self, client):
        """Test login without password"""
        response = client.post(
            '/api/login',
            data=json.dumps({
                'username': 'admin'
            }),
            content_type='application/json'
        )
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'Хэрэглэгчийн нэр болон нууц үг шаардлагатай' in data['message']
    
    def test_login_empty_username(self, client):
        """Test login with empty username"""
        response = client.post(
            '/api/login',
            data=json.dumps({
                'username': '   ',
                'password': 'admin123'
            }),
            content_type='application/json'
        )
        
        assert response.status_code == 400
    
    def test_login_empty_password(self, client):
        """Test login with empty password"""
        response = client.post(
            '/api/login',
            data=json.dumps({
                'username': 'admin',
                'password': ''
            }),
            content_type='application/json'
        )
        
        assert response.status_code == 400
    
    def test_login_no_json_data(self, client):
        """Test login without JSON data"""
        response = client.post(
            '/api/login',
            content_type='application/json'
        )
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'Мэдээлэл оруулаагүй байна' in data['message']
    
    def test_login_username_whitespace_trimmed(self, client):
        """Test that username whitespace is trimmed"""
        response = client.post(
            '/api/login',
            data=json.dumps({
                'username': '  admin  ',
                'password': 'admin123'
            }),
            content_type='application/json'
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['user']['username'] == 'admin'
    
    def test_login_token_validity(self, client):
        """Test that generated token is valid and can be decoded"""
        response = client.post(
            '/api/login',
            data=json.dumps({
                'username': 'admin',
                'password': 'admin123'
            }),
            content_type='application/json'
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        token = data['token']
        
        # Verify token can be decoded
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        assert payload['username'] == 'admin'
        assert payload['role'] == 'admin'
        assert 'exp' in payload


class TestTokenVerification:
    """Test cases for /api/verify endpoint"""
    
    def test_verify_valid_token(self, client, valid_token):
        """Test verification of valid token"""
        response = client.get(
            '/api/verify',
            headers={'Authorization': f'Bearer {valid_token}'}
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['valid'] is True
        assert data['user']['username'] == 'admin'
        assert data['user']['role'] == 'admin'
        assert data['user']['name'] == 'Админ'
    
    def test_verify_token_without_bearer(self, client, valid_token):
        """Test verification with token but without Bearer prefix"""
        response = client.get(
            '/api/verify',
            headers={'Authorization': valid_token}
        )
        
        assert response.status_code == 401
    
    def test_verify_missing_token(self, client):
        """Test verification without token"""
        response = client.get('/api/verify')
        
        assert response.status_code == 401
        data = json.loads(response.data)
        assert data['valid'] is False
    
    def test_verify_expired_token(self, client, expired_token):
        """Test verification of expired token"""
        response = client.get(
            '/api/verify',
            headers={'Authorization': f'Bearer {expired_token}'}
        )
        
        assert response.status_code == 401
        data = json.loads(response.data)
        assert data['valid'] is False
        assert 'Токен хүчинтэй хугацаа дууссан' in data['message']
    
    def test_verify_invalid_token(self, client):
        """Test verification with invalid token"""
        response = client.get(
            '/api/verify',
            headers={'Authorization': 'Bearer invalid_token_12345'}
        )
        
        assert response.status_code == 401
        data = json.loads(response.data)
        assert data['valid'] is False
    
    def test_verify_token_wrong_secret(self, client):
        """Test verification with token signed with wrong secret"""
        wrong_secret_token = jwt.encode(
            {'username': 'admin', 'role': 'admin'},
            'wrong-secret',
            algorithm='HS256'
        )
        
        response = client.get(
            '/api/verify',
            headers={'Authorization': f'Bearer {wrong_secret_token}'}
        )
        
        assert response.status_code == 401
        data = json.loads(response.data)
        assert data['valid'] is False
    
    def test_verify_token_nonexistent_user(self, client):
        """Test verification with token for non-existent user"""
        token = jwt.encode(
            {
                'username': 'nonexistent',
                'role': 'admin',
                'exp': datetime.utcnow() + timedelta(days=7)
            },
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )
        
        response = client.get(
            '/api/verify',
            headers={'Authorization': f'Bearer {token}'}
        )
        
        assert response.status_code == 401
        data = json.loads(response.data)
        assert data['valid'] is False


class TestLogoutEndpoint:
    """Test cases for /api/logout endpoint"""
    
    def test_logout_success(self, client):
        """Test successful logout"""
        response = client.post('/api/logout')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['message'] == 'Амжилттай гарлаа'


class TestHealthCheck:
    """Test cases for /health endpoint"""
    
    def test_health_check(self, client):
        """Test health check endpoint"""
        response = client.get('/health')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'ok'


class TestTokenGeneration:
    """Test cases for generate_token function"""
    
    def test_generate_token_structure(self):
        """Test that generated token has correct structure"""
        user_data = USERS['admin']
        token = generate_token('admin', user_data)
        
        assert token is not None
        assert isinstance(token, str)
        
        # Decode and verify payload
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        assert payload['username'] == 'admin'
        assert payload['role'] == 'admin'
        assert 'exp' in payload
    
    def test_generate_token_expiration(self):
        """Test that token expiration is set correctly"""
        user_data = USERS['master']
        token = generate_token('master', user_data)
        
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        exp_time = datetime.fromtimestamp(payload['exp'])
        now = datetime.utcnow()
        
        # Token should expire approximately 7 days from now
        time_diff = exp_time - now
        assert 6.9 <= time_diff.days <= 7.1  # Allow small margin for execution time
    
    def test_generate_token_different_users(self):
        """Test token generation for different users"""
        admin_token = generate_token('admin', USERS['admin'])
        master_token = generate_token('master', USERS['master'])
        
        admin_payload = jwt.decode(admin_token, app.config['SECRET_KEY'], algorithms=['HS256'])
        master_payload = jwt.decode(master_token, app.config['SECRET_KEY'], algorithms=['HS256'])
        
        assert admin_payload['username'] == 'admin'
        assert admin_payload['role'] == 'admin'
        assert master_payload['username'] == 'master'
        assert master_payload['role'] == 'master'


class TestPasswordHashing:
    """Test cases for password hashing"""
    
    def test_password_hash_consistency(self):
        """Test that password hashing is consistent"""
        password = 'admin123'
        hash1 = hashlib.sha256(password.encode()).hexdigest()
        hash2 = hashlib.sha256(password.encode()).hexdigest()
        
        assert hash1 == hash2
        assert hash1 == USERS['admin']['password_hash']
    
    def test_password_hash_different_passwords(self):
        """Test that different passwords produce different hashes"""
        hash1 = hashlib.sha256('admin123'.encode()).hexdigest()
        hash2 = hashlib.sha256('master123'.encode()).hexdigest()
        
        assert hash1 != hash2


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

