
import unittest
import json
from protected_routes import app, jwt_required
from flask import Flask

# Load the test JWTs
with open("test_jwts.txt") as f:
    lines = f.readlines()
    creator_token = lines[0].split(": ", 1)[1].strip()
    admin_token = lines[1].split(": ", 1)[1].strip()

class AuthMiddlewareTestCase(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_creator_access_memory(self):
        response = self.client.get(
            "/memory/abc123",
            headers={"Authorization": f"Bearer {creator_token}"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("Access granted to loop_id: abc123", response.get_data(as_text=True))

    def test_admin_denied_memory(self):
        response = self.client.get(
            "/memory/abc123",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        self.assertEqual(response.status_code, 403)

    def test_admin_access_stats(self):
        response = self.client.get(
            "/admin/stats",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("Admin access granted to stats", response.get_data(as_text=True))

    def test_creator_denied_stats(self):
        response = self.client.get(
            "/admin/stats",
            headers={"Authorization": f"Bearer {creator_token}"}
        )
        self.assertEqual(response.status_code, 403)

    def test_missing_token(self):
        response = self.client.get("/memory/abc123")
        self.assertEqual(response.status_code, 401)

if __name__ == '__main__':
    unittest.main()
    def test_expired_token(self):
        # Token with expired 'exp' claim
        expired_token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiZXhwaXJlZF91c2VyIiwicm9sZSI6ImNyZWF0b3IiLCJleHAiOjE2MDAwMDAwMDB9.xZKyG4gOa7GRZZmj2Hzj7vEvvGjR9DlK9KbXhnSxyT8"
        response = self.app.get('/memory/test-loop', headers={'Authorization': expired_token})
        self.assertEqual(response.status_code, 401)

    def test_malformed_token(self):
        # Totally malformed token
        malformed_token = "Bearer this.is.not.a.valid.jwt"
        response = self.app.get('/memory/test-loop', headers={'Authorization': malformed_token})
        self.assertEqual(response.status_code, 401)

    def test_missing_bearer_prefix(self):
        # Valid token but no Bearer prefix
        valid_token_no_prefix = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiY3JlYXRvcl8xMjMiLCJyb2xlIjoiY3JlYXRvciIsImV4cCI6MjYwMDAwMDAwMH0.NhQz5dhjN1-WpNkzguWjZkDIDeLnSsnxu7V58l4GC9M"
        response = self.app.get('/memory/test-loop', headers={'Authorization': valid_token_no_prefix})
        self.assertEqual(response.status_code, 401)

    def test_invalid_role_token(self):
        # Token with undefined role
        undefined_role_token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiZ3Vlc3QiLCJyb2xlIjoiZ3Vlc3QiLCJleHAiOjI2MDAwMDAwMDB9.XGpdd3q_WGl7VQK9tL08Q5bnRQzcvkhuWhJZo5shljY"
        response = self.app.get('/memory/test-loop', headers={'Authorization': undefined_role_token})
        self.assertEqual(response.status_code, 403)

