import pytest
from fastapi.testclient import TestClient
import time

from app.main import app
from app.database import Base, get_db
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

SQLALCHEMY_DATABASE_URL = "sqlite:///./data/test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)

MAX_LOGIN_ATTEMPTS = 15


@pytest.fixture(scope="function")
def db_session():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    yield db
    db.close()


class TestPasswordStrength:
    
    def test_weak_passwords_rejected(self, db_session):
        weak_passwords = [
            ("short1!", "Too short"),
            ("nouppercase123!", "No uppercase"),
            ("NOLOWERCASE123!", "No lowercase"),
            ("NoDigits!", "No digits"),
            ("NoSpecial123", "No special characters"),
        ]
        
        for password, reason in weak_passwords:
            response = client.post(
                "/auth/register",
                json={
                    "username": f"test_{time.time()}",
                    "email": f"test_{time.time()}@example.com",
                    "password": password
                }
            )
            assert response.status_code == 400, f"Should reject weak password: {reason}"
    
    def test_strong_password_accepted(self, db_session):
        response = client.post(
            "/auth/register",
            json={
                "username": f"stronguser_{time.time()}",
                "email": f"strong_{time.time()}@example.com",
                "password": "StrongPass123!",
            }
        )
        assert response.status_code in [200, 201], "Should accept strong password"


class TestRateLimiting:
    
    def test_login_rate_limiting(self, db_session):
        for i in range(16):
            response = client.post(
                "/auth/login",
                json={
                    "username": "testuser",
                    "password": "wrongpassword"
                }
            )
            
            if i < 15:
                assert response.status_code in [401, 404], f"Attempt {i+1} should be processed"
            else:
                assert response.status_code == 429, f"Attempt {i+1} should be rate limited"


class TestAccountLockout:
    
    def test_lockout_after_failed_attempts(self, db_session):
        username = f"locktest_{time.time()}"
        password = "CorrectPass123!"
        
        response = client.post(
            "/auth/register",
            json={
                "username": username,
                "email": f"{username}@example.com",
                "password": password
            }
        )
        assert response.status_code in [200, 201], "User registration should succeed"
        
        for i in range(MAX_LOGIN_ATTEMPTS + 1):
            time.sleep(0.1)
            response = client.post(
                "/auth/login",
                json={
                    "username": username,
                    "password": "WrongPassword123!"
                }
            )
            
            if i < MAX_LOGIN_ATTEMPTS:
                assert response.status_code == 401, f"Attempt {i+1} should return 401"
            else:
                assert response.status_code == 429, f"Attempt {i+1} should be locked (429)"
        
        response = client.post(
            "/auth/login",
            json={
                "username": username,
                "password": password
            }
        )
        assert response.status_code == 429, "Should be locked even with correct password"


class TestCSRFProtection:
    
    def test_csrf_token_required(self, db_session):
        username = f"csrftest_{time.time()}"
        password = "TestPass123!"
        
        client.post(
            "/auth/register",
            json={
                "username": username,
                "email": f"{username}@example.com",
                "password": password
            }
        )
        
        login_response = client.post(
            "/auth/login",
            json={
                "username": username,
                "password": password
            }
        )
        
        csrf_token = login_response.json().get("csrf_token")
        
        assert csrf_token is not None, "CSRF token should be returned"
        
        response = client.post("/auth/logout")
        assert response.status_code == 403, "Should reject request without CSRF token"
    
    def test_csrf_token_accepted(self, db_session):
        username = f"csrftest2_{time.time()}"
        password = "TestPass123!"
        
        client.post(
            "/auth/register",
            json={
                "username": username,
                "email": f"{username}@example.com",
                "password": password
            }
        )
        
        login_response = client.post(
            "/auth/login",
            json={
                "username": username,
                "password": password
            }
        )
        
        csrf_token = login_response.json().get("csrf_token")
        
        response = client.post(
            "/auth/logout",
            headers={"X-CSRF-Token": csrf_token}
        )
        assert response.status_code == 200, "Should accept valid CSRF token"


class TestTokenRevocation:
    
    def test_token_revoked_on_logout(self, db_session):
        username = f"revoketest_{time.time()}"
        password = "TestPass123!"
        
        client.post(
            "/auth/register",
            json={
                "username": username,
                "email": f"{username}@example.com",
                "password": password
            }
        )
        
        login_response = client.post(
            "/auth/login",
            json={
                "username": username,
                "password": password
            }
        )
        
        csrf_token = login_response.json().get("csrf_token")
        
        response = client.get("/auth/protected")
        assert response.status_code == 200, "Should access protected route before logout"
        
        client.post(
            "/auth/logout",
            headers={"X-CSRF-Token": csrf_token}
        )
        
        response = client.get("/auth/protected")
        assert response.status_code == 401, "Should reject revoked token"


class TestCompleteAuthFlow:
    
    def test_full_authentication_flow(self, db_session):
        username = f"flowtest_{time.time()}"
        email = f"{username}@example.com"
        password = "FlowTest123!"
        
        response = client.post(
            "/auth/register",
            json={
                "username": username,
                "email": email,
                "password": password
            }
        )
        assert response.status_code in [200, 201]
        
        response = client.post(
            "/auth/login",
            json={
                "username": username,
                "password": password
            }
        )
        assert response.status_code == 200
        
        csrf_token = response.json().get("csrf_token")
        
        response = client.get("/auth/protected")
        assert response.status_code == 200
        
        response = client.post("/auth/refresh")
        assert response.status_code == 200
        
        response = client.get("/auth/protected")
        assert response.status_code == 200
        
        response = client.post(
            "/auth/logout",
            headers={"X-CSRF-Token": csrf_token}
        )
        assert response.status_code == 200
        
        response = client.get("/auth/protected")
        assert response.status_code == 401


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "not slow"])