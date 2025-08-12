"""
Tests for API endpoints.
"""
import pytest
from fastapi.testclient import TestClient
from moto import mock_aws

@mock_aws
class TestAPIEndpoints:
    """Test cases for API endpoints."""
    
    def test_health_check(self, test_app):
        """Test health check endpoint."""
        response = test_app.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "healthy", "service": "auth-api"}
    
    def test_register_endpoint(self, test_app, test_user_data):
        """Test user registration endpoint."""
        response = test_app.post("/api/auth/register", json=test_user_data)
        
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert "Registration successful" in data["message"]
        assert data["data"]["email"] == test_user_data["email"]
    
    def test_register_invalid_data(self, test_app):
        """Test registration with invalid data."""
        invalid_data = {
            "email": "invalid-email",
            "password": "short",
            "full_name": ""
        }
        
        response = test_app.post("/api/auth/register", json=invalid_data)
        assert response.status_code == 422  # Validation error
    
    def test_register_duplicate_email(self, test_app, test_user_data):
        """Test registration with duplicate email."""
        # Register first user
        response = test_app.post("/api/auth/register", json=test_user_data)
        assert response.status_code == 200
        
        # Try to register with same email
        response = test_app.post("/api/auth/register", json=test_user_data)
        assert response.status_code == 400
        assert "already exists" in response.json()["detail"]
    
    def test_login_unconfirmed_user(self, test_app, test_user_data):
        """Test login with unconfirmed user."""
        # Register user
        register_response = test_app.post("/api/auth/register", json=test_user_data)
        assert register_response.status_code == 200
        
        # Try to login without confirming email
        login_data = {
            "email": test_user_data["email"],
            "password": test_user_data["password"]
        }
        
        login_response = test_app.post("/api/auth/login", json=login_data)
        assert login_response.status_code == 401
        assert "not verified" in login_response.json()["detail"]
    
    def test_forgot_password_endpoint(self, test_app, test_user_data):
        """Test forgot password endpoint."""
        # Register user first
        test_app.post("/api/auth/register", json=test_user_data)
        
        # Request password reset
        reset_data = {"email": test_user_data["email"]}
        response = test_app.post("/api/auth/forgot-password", json=reset_data)
        
        assert response.status_code == 200
        assert "reset code has been sent" in response.json()["message"]
    
    def test_forgot_password_nonexistent_user(self, test_app):
        """Test forgot password for non-existent user."""
        reset_data = {"email": "nonexistent@example.com"}
        response = test_app.post("/api/auth/forgot-password", json=reset_data)
        
        # Should return success for security (don't reveal if user exists)
        assert response.status_code == 200
        assert "reset code has been sent" in response.json()["message"]
    
    def test_protected_endpoint_without_auth(self, test_app):
        """Test accessing protected endpoint without authentication."""
        response = test_app.get("/api/user/profile")
        assert response.status_code == 403  # Forbidden (no auth header)
    
    def test_protected_endpoint_with_invalid_token(self, test_app):
        """Test accessing protected endpoint with invalid token."""
        headers = {"Authorization": "Bearer invalid-token"}
        response = test_app.get("/api/user/profile", headers=headers)
        assert response.status_code == 401  # Unauthorized