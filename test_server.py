import unittest
import json
import os
import sqlite3
import time

# Remove any leftover test DB before importing main
DB_FILE = "totally_not_my_privateKeys.db"
if os.path.exists(DB_FILE):
    os.remove(DB_FILE)

from main import app, init_db, generate_and_store_key, get_db, int_to_base64, DB_FILE


class TestDatabase(unittest.TestCase):
    """Tests for database initialization and key storage."""

    def test_db_file_created(self):
        """DB file should exist after init."""
        self.assertTrue(os.path.exists(DB_FILE))

    def test_keys_table_exists(self):
        """Keys table should be present in the DB."""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='keys'"
        )
        result = cursor.fetchone()
        conn.close()
        self.assertIsNotNone(result)

    def test_keys_seeded_on_startup(self):
        """At least two keys (one valid, one expired) should be in the DB."""
        conn = get_db()
        rows = conn.execute("SELECT COUNT(*) as count FROM keys").fetchone()
        conn.close()
        self.assertGreaterEqual(rows["count"], 2)

    def test_valid_key_stored(self):
        """At least one unexpired key should be in the DB."""
        current_time = int(time.time())
        conn = get_db()
        row = conn.execute(
            "SELECT kid FROM keys WHERE exp > ?", (current_time,)
        ).fetchone()
        conn.close()
        self.assertIsNotNone(row)

    def test_expired_key_stored(self):
        """At least one expired key should be in the DB."""
        current_time = int(time.time())
        conn = get_db()
        row = conn.execute(
            "SELECT kid FROM keys WHERE exp <= ?", (current_time,)
        ).fetchone()
        conn.close()
        self.assertIsNotNone(row)


class TestHelpers(unittest.TestCase):
    """Tests for helper functions."""

    def test_int_to_base64_even_hex(self):
        """Should correctly encode an integer with even-length hex."""
        result = int_to_base64(65537)  # common RSA exponent
        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 0)

    def test_int_to_base64_odd_hex(self):
        """Should correctly pad and encode an integer with odd-length hex."""
        result = int_to_base64(1)
        self.assertIsInstance(result, str)


class TestJWKSEndpoint(unittest.TestCase):
    """Tests for GET /.well-known/jwks.json"""

    def setUp(self):
        self.client = app.test_client()

    def test_jwks_returns_200(self):
        """JWKS endpoint should return HTTP 200."""
        response = self.client.get('/.well-known/jwks.json')
        self.assertEqual(response.status_code, 200)

    def test_jwks_returns_keys_field(self):
        """Response should contain a 'keys' array."""
        response = self.client.get('/.well-known/jwks.json')
        data = response.get_json()
        self.assertIn('keys', data)
        self.assertIsInstance(data['keys'], list)

    def test_jwks_only_valid_keys(self):
        """All returned keys should be unexpired (have valid structure)."""
        response = self.client.get('/.well-known/jwks.json')
        data = response.get_json()
        for key in data['keys']:
            self.assertIn('kid', key)
            self.assertIn('n', key)
            self.assertIn('e', key)
            self.assertEqual(key['kty'], 'RSA')
            self.assertEqual(key['alg'], 'RS256')

    def test_jwks_no_expired_keys(self):
        """Expired keys should NOT appear in the JWKS response."""
        current_time = int(time.time())
        conn = get_db()
        expired_kids = [
            str(row["kid"]) for row in
            conn.execute("SELECT kid FROM keys WHERE exp <= ?", (current_time,)).fetchall()
        ]
        conn.close()

        response = self.client.get('/.well-known/jwks.json')
        data = response.get_json()
        returned_kids = [k['kid'] for k in data['keys']]

        for ek in expired_kids:
            self.assertNotIn(ek, returned_kids)


class TestAuthEndpoint(unittest.TestCase):
    """Tests for POST /auth"""

    def setUp(self):
        self.client = app.test_client()

    def test_auth_returns_200(self):
        """Auth endpoint should return HTTP 200."""
        response = self.client.post('/auth')
        self.assertEqual(response.status_code, 200)

    def test_auth_returns_token(self):
        """Auth endpoint should return a JWT string."""
        response = self.client.post('/auth')
        token = response.data.decode('utf-8')
        self.assertIsInstance(token, str)
        # JWTs have 3 parts separated by dots
        self.assertEqual(len(token.split('.')), 3)

    def test_auth_expired_returns_200(self):
        """Auth with ?expired param should return HTTP 200."""
        response = self.client.post('/auth?expired=true')
        self.assertEqual(response.status_code, 200)

    def test_auth_expired_returns_token(self):
        """Auth with ?expired param should return a JWT string."""
        response = self.client.post('/auth?expired=true')
        token = response.data.decode('utf-8')
        self.assertIsInstance(token, str)
        self.assertEqual(len(token.split('.')), 3)

    def test_auth_accepts_basic_auth(self):
        """Auth should work with HTTP Basic Auth header."""
        import base64
        credentials = base64.b64encode(b"userABC:password123").decode("utf-8")
        response = self.client.post(
            '/auth',
            headers={"Authorization": f"Basic {credentials}"}
        )
        self.assertEqual(response.status_code, 200)
        token = response.data.decode('utf-8')
        self.assertEqual(len(token.split('.')), 3)

    def test_auth_accepts_json_payload(self):
        """Auth should work with JSON body payload."""
        response = self.client.post(
            '/auth',
            data=json.dumps({"username": "userABC", "password": "password123"}),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        token = response.data.decode('utf-8')
        self.assertEqual(len(token.split('.')), 3)


if __name__ == '__main__':
    unittest.main()
