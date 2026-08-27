#!/usr/bin/env python3
"""
Regression tests for PyJWT 2.13 compatibility in auth.py.
Tests token creation, valid verification, invalid signatures, expired tokens, and missing/invalid secrets.

These are unit tests that verify the auth.py module directly without requiring a running container.
"""

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

# Add deploy/docker to path for imports
DEPLOY_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, DEPLOY_DIR)


class TestPyJWTMigration(unittest.TestCase):
    """Test that auth.py works correctly with PyJWT 2.x API."""

    def setUp(self):
        """Set up test environment with a known secret."""
        # Use a test secret that meets the 32-character minimum
        self.test_secret = "test_secret_key_that_is_long_enough_32"
        # Patch the secret resolution to use our test secret
        self.secret_patcher = patch.dict(os.environ, {"SECRET_KEY": self.test_secret})
        self.secret_patcher.start()
        # Reload auth module to pick up the patched environment
        if 'auth' in sys.modules:
            del sys.modules['auth']
        from auth import create_access_token, verify_token, SECRET_KEY
        self.create_access_token = create_access_token
        self.verify_token = verify_token
        self.SECRET_KEY = SECRET_KEY

    def tearDown(self):
        """Clean up patches."""
        self.secret_patcher.stop()
        if 'auth' in sys.modules:
            del sys.modules['auth']

    # ========================================================================
    # Token Creation Tests
    # ========================================================================

    def test_token_creation_basic(self):
        """Test that create_access_token produces a valid JWT token."""
        token = self.create_access_token({"sub": "testuser"})
        self.assertIsInstance(token, str)
        self.assertTrue(len(token) > 0)
        # JWT tokens have three parts separated by dots
        self.assertEqual(len(token.split('.')), 3)

    def test_token_creation_with_custom_expiry(self):
        """Test token creation with custom expiration delta."""
        custom_delta = timedelta(minutes=30)
        token = self.create_access_token({"sub": "testuser"}, expires_delta=custom_delta)
        self.assertIsInstance(token, str)
        self.assertEqual(len(token.split('.')), 3)

    def test_token_creation_contains_claims(self):
        """Test that created token contains expected claims."""
        token = self.create_access_token({"sub": "testuser", "role": "admin"})
        # Decode without verification to check claims
        import jwt
        decoded = jwt.decode(
            token, 
            self.SECRET_KEY, 
            algorithms=["HS256"],
            options={"verify_exp": False}
        )
        self.assertEqual(decoded["sub"], "testuser")
        self.assertEqual(decoded["role"], "admin")
        self.assertIn("exp", decoded)

    # ========================================================================
    # Valid Verification Tests
    # ========================================================================

    def test_valid_verification(self):
        """Test that valid tokens are accepted."""
        token = self.create_access_token({"sub": "testuser"})
        # Create mock credentials
        mock_credentials = MagicMock()
        mock_credentials.credentials = token
        
        result = self.verify_token(mock_credentials)
        self.assertEqual(result["sub"], "testuser")

    def test_valid_verification_with_extra_claims(self):
        """Test that tokens with extra claims are accepted."""
        token = self.create_access_token({
            "sub": "testuser",
            "email": "test@example.com",
            "roles": ["user", "admin"]
        })
        mock_credentials = MagicMock()
        mock_credentials.credentials = token
        
        result = self.verify_token(mock_credentials)
        self.assertEqual(result["sub"], "testuser")
        self.assertEqual(result["email"], "test@example.com")
        self.assertEqual(result["roles"], ["user", "admin"])

    # ========================================================================
    # Invalid Signature Tests
    # ========================================================================

    def test_invalid_signature_rejected(self):
        """Test that tokens signed with wrong secret are rejected."""
        token = self.create_access_token({"sub": "testuser"})
        # Create a token with a different secret
        import jwt
        wrong_token = jwt.encode({"sub": "testuser"}, "wrong_secret_key_that_is_long_32", algorithm="HS256")
        
        mock_credentials = MagicMock()
        mock_credentials.credentials = wrong_token
        
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as context:
            self.verify_token(mock_credentials)
        self.assertEqual(context.exception.status_code, 401)

    def test_tampered_token_rejected(self):
        """Test that tampered tokens are rejected."""
        import jwt
        # Create a valid token
        token = self.create_access_token({"sub": "testuser"})
        # Tamper with it
        parts = token.split('.')
        # Flip a character in the payload (base64 part)
        tampered = parts[0] + '.tampered.' + parts[2]
        
        mock_credentials = MagicMock()
        mock_credentials.credentials = tampered
        
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as context:
            self.verify_token(mock_credentials)
        self.assertEqual(context.exception.status_code, 401)

    # ========================================================================
    # Expired Token Tests
    # ========================================================================

    def test_expired_token_rejected(self):
        """Test that expired tokens are rejected."""
        import jwt
        # Create a token that's already expired
        expired_payload = {
            "sub": "testuser",
            "exp": datetime.now(timezone.utc) - timedelta(minutes=1)
        }
        token = jwt.encode(expired_payload, self.SECRET_KEY, algorithm="HS256")
        
        mock_credentials = MagicMock()
        mock_credentials.credentials = token
        
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as context:
            self.verify_token(mock_credentials)
        self.assertEqual(context.exception.status_code, 401)

    def test_expired_token_error_message(self):
        """Test that expired tokens return appropriate error message."""
        import jwt
        expired_payload = {
            "sub": "testuser",
            "exp": datetime.now(timezone.utc) - timedelta(minutes=1)
        }
        token = jwt.encode(expired_payload, self.SECRET_KEY, algorithm="HS256")
        
        mock_credentials = MagicMock()
        mock_credentials.credentials = token
        
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as context:
            self.verify_token(mock_credentials)
        # Should have specific message about expiration
        self.assertIn("expired", str(context.exception.detail).lower())

    # ========================================================================
    # Missing/Invalid Secrets Tests
    # ========================================================================

    def test_missing_token_rejected(self):
        """Test that missing token is rejected."""
        mock_credentials = MagicMock()
        mock_credentials.credentials = None
        
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as context:
            self.verify_token(mock_credentials)
        self.assertEqual(context.exception.status_code, 401)
        self.assertIn("No token provided", context.exception.detail)

    def test_empty_token_rejected(self):
        """Test that empty token is rejected."""
        mock_credentials = MagicMock()
        mock_credentials.credentials = ""
        
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as context:
            self.verify_token(mock_credentials)
        self.assertEqual(context.exception.status_code, 401)

    def test_invalid_token_format_rejected(self):
        """Test that malformed tokens are rejected."""
        mock_credentials = MagicMock()
        mock_credentials.credentials = "not-a-valid-jwt-token"
        
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as context:
            self.verify_token(mock_credentials)
        self.assertEqual(context.exception.status_code, 401)


class TestSecretKeyValidation(unittest.TestCase):
    """Test secret key validation and security."""

    def test_weak_secret_validation_in_source(self):
        """Test that weak secrets validation exists in auth.py."""
        # Read the source and verify the validation logic exists
        with open(os.path.join(DEPLOY_DIR, "auth.py")) as f:
            source = f.read()
        
        # Verify weak secrets validation exists
        self.assertIn("_WEAK_SECRETS", source)
        self.assertIn("mysecret", source)
        self.assertIn("secret", source)
        
        # Verify length validation exists
        self.assertIn("len(key) < 32", source)

    def test_short_secret_rejected_by_validation(self):
        """Test that short secrets are rejected by validation logic in source."""
        # Verify the validation exists in source code
        with open(os.path.join(DEPLOY_DIR, "auth.py")) as f:
            source = f.read()
        
        # The source should contain the short key rejection
        self.assertIn("len(key) < 32", source)
        
        # Also test directly with a fresh import in a subprocess
        # to ensure the validation actually runs
        import subprocess
        result = subprocess.run(
            [sys.executable, "-c", 
             "import os; os.environ['SECRET_KEY'] = 'shortkey'; "
             "exec(open('auth.py').read())"],
            cwd=DEPLOY_DIR,
            capture_output=True,
            text=True
        )
        self.assertIn("32", result.stderr)

    def test_valid_secret_accepted(self):
        """Test that valid secrets are accepted."""
        with patch.dict(os.environ, {"SECRET_KEY": "valid_secret_key_that_is_long_enough"}):
            from auth import _resolve_secret_key
            key = _resolve_secret_key()
            self.assertEqual(key, "valid_secret_key_that_is_long_enough")


if __name__ == "__main__":
    print("=" * 70)
    print("PyJWT 2.13 Auth Regression Tests")
    print("=" * 70)
    print()
    unittest.main(verbosity=2)
