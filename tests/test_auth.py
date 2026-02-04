"""
Security testing script for the authentication system.
Tests various securit features including rate limiting, account lockout,
CSRF protection and password strength validation.
"""

import requests
import time
from typing import Dict, Any

BASE_URL = "http://localhost:8000"
MAX_LOGIN_ATTEMPTS = 15

def test_password_strength():
    print("\n=== Testing Password Strength Validation ===")
    
    weak_passwords = [
        ("short1!", "Too short"),
        ("nouppercase123!", "No uppercase"),
        ("NOLOWERCASE123!", "No lowercase"),
        ("NoDigits!", "No digits"),
        ("NoSpecial123", "No special characters"),
    ]
    
    for password, reason in weak_passwords:
        response = requests.post(
            f"{BASE_URL}/auth/register",
            json={
                "username": f"test_{time.time()}",
                "email": f"test_{time.time()}@example.com",
                "password": password
            }
        )
        print(f"Testing weak password ({reason}): {response.status_code}")
        assert response.status_code == 400, f"Should reject weak password: {reason}"
        
    response = requests.post(
        f"{BASE_URL}/auth/register",
        json={
            "username": f"stronuser_{time.time()}",
            "email": f"string_{time.time()}@example.com",
            "password": "StrongPass123!",
        }
    )
    print(f"Testing strong password: {response.status_code}")
    assert response.status_code in [200, 201], "Should accept strong password"
    
    print("Password strength validation working correctly")
    
def test_rate_limiting():
    """Test rate limiting on login endpoint."""
    print("\n=== Testing Rate Limiting ===")
    
    for i in range(16):
        response = requests.post(
            f"{BASE_URL}/auth/login",
            json={
                "username": "testuser",
                "password": "wrongpassword"
            }
        )
        print(f"Login attempt {i+1}: {response.status_code}")
        
        if i < 15:
            assert response.status_code in [401, 404], f"Attempt {i+1} should be processed"
        else:
            assert response.status_code == 429, f"Attempt {i+1} should be rate limited"
    print("Rate limiting working correctly")
    
def test_account_lockout():
    """Test account lockout after failed login attempts."""
    print("\n === Testing Account Lockout ===")
    
    username = f"locktest_{time.time()}"
    password = f"CorrectPass123!"
    
    response = requests.post(
        f"{BASE_URL}/auth/register",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": password
        }
    )
    print(f"User registed: {response.status_code}")
    
    for i in range(MAX_LOGIN_ATTEMPTS + 1):
        time.sleep(0.1)
        response = requests.post(
            f"{BASE_URL}/auth/login",
            json={
                "username": username,
                "password": "WrongPassword123!"
            }
        )
        print(f"Failed attempt {i+1}: {response.status_code}")
        
        if i < MAX_LOGIN_ATTEMPTS:
            assert response.status_code == 401, f"Attempt {i+1} should return 401"
        else:
            assert response.status_code == 429, f"Attempt {i+1} should be locked (429)"
            
    response = requests.post(
        f"{BASE_URL}/auth/login",
        json={
            "username": username,
            "password": password
        }
    )
    print(f"Correct password while locked: {response.status_code}")
    assert response.status_code == 429, "Should be locked even with correct password"
    
    print("Account lockout working correctly")
    
def test_csrf_protection():
    """Test CSRF protection on logout endpoint."""
    print("\n === Testing CSRF Protection ===")
    
    username = f"csrftest_{time.time()}"
    password = "TestPass123!"
    
    requests.post(
        f"{BASE_URL}/auth/register",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": password
        }
    )
    
    login_response = requests.post(
        f"{BASE_URL}/auth/login",
        json={
            "username": username,
            "password": password
        }
    )
    
    cookies = login_response.cookies
    csrf_token = login_response.json().get("csrf_token")
    
    print(f"Login successful, CSRF token received: {bool(csrf_token)}")
    
    response = requests.post(
        f"{BASE_URL}/auth/logout",
        cookies=cookies
    )
    
    print(f"Logout with invalid CSRF token: {response.status_code}")
    assert response.status_code == 403, "Should reject invalid CSRF token"
    
    response = requests.post(
        f"{BASE_URL}/auth/logout",
        cookies=cookies,
        headers={"X-CSRF-Token": csrf_token}
    )
    print(f"Logout with valid CSRF token: {response.status_code}")
    assert response.status_code == 200, "Should accept valid CSRF token"
    
    print("CSRF protection working correctly")
    
def test_token_revocation():
    """Test token revocation on logout"""
    print("\n === Testing Token Revocation")
    
    username = f"revoketest_{time.time()}"
    password = "TestPass123!"
    
    requests.post(
        f"{BASE_URL}/auth/register",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": password
        }
    )
    
    login_response = requests.post(
        f"{BASE_URL}/auth/login",
        json={
            "username": username,
            "password": password
        }
    )
    
    cookies = login_response.cookies
    csrf_token = login_response.json().get("csrf_token")
    
    response = requests.get(
        f"{BASE_URL}/protected",
        cookies=cookies
    )
    print(f"Access protected route before logout: {response.status_code}")
    assert response.status_code == 200, "Should access protected route"
    
    requests.post(
        f"{BASE_URL}/auth/logout",
        cookies=cookies,
        headers={"X-CSRF-Token": csrf_token}
    )
    
    response = requests.get(
        f"{BASE_URL}/protected",
        cookies=cookies
    )
    
    print(f"Access protected route after logout: {response.status_code}")
    assert response.status_code == 401, "Should reject revoked token"
    
    print("Token revocation working correctly")
    
def test_complete_flow():
    """Test complete authentication flow."""
    print("\n=== Testing Complete Authentication Flow ===")
    
    username = f"flowtest_{time.time()}"
    email = f"{username}@example.com"
    password = "FlowTest123!"
    
    # 1. Register
    response = requests.post(
        f"{BASE_URL}/auth/register",
        json={
            "username": username,
            "email": email,
            "password": password
        }
    )
    print(f"1. Register: {response.status_code}")
    assert response.status_code in [200, 201]
    
    # 2. Login
    response = requests.post(
        f"{BASE_URL}/auth/login",
        json={
            "username": username,
            "password": password
        }
    )
    print(f"2. Login: {response.status_code}")
    assert response.status_code == 200
    
    cookies = response.cookies
    csrf_token = response.json().get("csrf_token")
    
    # 3. Access protected route
    response = requests.get(
        f"{BASE_URL}/protected",
        cookies=cookies
    )
    print(f"3. Access protected route: {response.status_code}")
    assert response.status_code == 200
    
    # 4. Refresh token
    response = requests.post(
        f"{BASE_URL}/auth/refresh",
        cookies=cookies
    )
    print(f"4. Refresh token: {response.status_code}")
    assert response.status_code == 200
    
    # Update cookies with new access token
    if response.cookies:
        cookies.update(response.cookies)
    
    # 5. Access protected route again
    response = requests.get(
        f"{BASE_URL}/protected",
        cookies=cookies
    )
    print(f"5. Access protected route after refresh: {response.status_code}")
    assert response.status_code == 200
    
    # 6. Logout
    response = requests.post(
        f"{BASE_URL}/auth/logout",
        cookies=cookies,
        headers={"X-CSRF-Token": csrf_token}
    )
    print(f"6. Logout: {response.status_code}")
    assert response.status_code == 200
    
    # 7. Try to access protected route after logout
    response = requests.get(
        f"{BASE_URL}/protected",
        cookies=cookies
    )
    print(f"7. Access protected route after logout: {response.status_code}")
    assert response.status_code == 401
    
    print("Complete authentication flow working correctly")
    
def main():
    """Run all security tests."""
    print("=" * 60)
    print("AUTHENTICATION SYSTEM SECURITY TESTS")
    print("=" * 60)
    print("\nMake sure the server is running at http://localhost:8000")
    print("Press Enter to continue or Ctrl+C to cancel...")
    input()
    
    try:
        test_password_strength()
        time.sleep(1)
        
        test_complete_flow()
        time.sleep(1)
        
        #test_rate_limiting()
        # test_account_lockout()
        print("\n Note: Skipping rate limiting and account lockout tests")
        print("Run them manually to avoid interference")
        
        test_csrf_protection()
        time.sleep(1)
        
        test_token_revocation()
        
        print("\n" + "=" * 60)
        print("ALL TESTS PASSED")
        print("=" * 60)
    except AssertionError as e:
        print(f"\nTEST FAILED: {e}")
        return 1
    except requests.exceptions.ConnectionError:
        print("\nERROR: Cannot connect to server. Make sure it's running at http://localhost:8000")
        return 1
    except Exception as e:
        print(f"\nUNEXPECTED ERROR: {e}")
        return 1
    return 0

if __name__ == "__main__":
    exit(main())