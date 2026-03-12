import time
import base64
import sqlite3
import os
from flask import Flask, request, jsonify
import jwt  # PyJWT
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# Database file name (required by assignment)
# Use absolute path based on script location so gradebot always finds it
DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "totally_not_my_privateKeys.db")


# ── Database Setup ────────────────────────────────────────────────────────────

def get_db():
    """Opens a connection to the SQLite database."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row  # allows column access by name
    return conn


def init_db():
    """Creates the keys table if it doesn't already exist."""
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    """)
    conn.commit()
    conn.close()


# ── Key Generation ────────────────────────────────────────────────────────────

def generate_and_store_key(expired=False):
    """
    Generates an RSA private key and stores it in the database as a PEM string.
    If expired=True, sets expiry to 1 hour ago. Otherwise, 1 hour from now.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Serialize the private key to PEM format (string) for SQLite storage
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    # Set expiry timestamp
    exp = int(time.time()) - 3600 if expired else int(time.time()) + 3600

    # Use parameterized query to prevent SQL injection
    conn = get_db()
    conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem, exp))
    conn.commit()
    conn.close()


# ── Helper ────────────────────────────────────────────────────────────────────

def int_to_base64(value):
    """Converts an RSA key integer component to a Base64URL string."""
    value_hex = format(value, 'x')
    if len(value_hex) % 2 != 0:
        value_hex = '0' + value_hex
    return base64.urlsafe_b64encode(bytes.fromhex(value_hex)).rstrip(b'=').decode('utf-8')


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    """Returns all valid (non-expired) public keys in JWKS format."""
    current_time = int(time.time())
    valid_keys = []

    # Parameterized query: only fetch unexpired keys
    conn = get_db()
    rows = conn.execute(
        "SELECT kid, key FROM keys WHERE exp > ?", (current_time,)
    ).fetchall()
    conn.close()

    for row in rows:
        # Deserialize PEM string back into a private key object
        private_key = serialization.load_pem_private_key(
            row["key"].encode("utf-8"),
            password=None,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        numbers = public_key.public_numbers()

        valid_keys.append({
            "alg": "RS256",
            "kty": "RSA",
            "use": "sig",
            "kid": str(row["kid"]),
            "n": int_to_base64(numbers.n),
            "e": int_to_base64(numbers.e),
        })

    return jsonify(keys=valid_keys)


@app.route('/auth', methods=['POST'])
def auth():
    """
    Issues a signed JWT.
    - No query param  → signs with a valid (unexpired) key
    - ?expired=true   → signs with an expired key
    """
    is_expired = 'expired' in request.args
    current_time = int(time.time())

    conn = get_db()

    # Parameterized query: select key based on expiry requirement
    if is_expired:
        row = conn.execute(
            "SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1", (current_time,)
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1", (current_time,)
        ).fetchone()

    conn.close()

    if row is None:
        return jsonify({"error": "No suitable key found"}), 500

    # Deserialize PEM string back into a private key object
    private_key = serialization.load_pem_private_key(
        row["key"].encode("utf-8"),
        password=None,
        backend=default_backend()
    )

    # Re-serialize PEM for PyJWT signing
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Build JWT payload
    payload = {
        "sub": "userABC",
        "username": "userABC",
        "exp": row["exp"]
    }

    token = jwt.encode(
        payload,
        pem,
        algorithm="RS256",
        headers={"kid": str(row["kid"])}
    )

    # Return the raw JWT string (not JSON-wrapped) so gradebot can decode it
    from flask import make_response
    response = make_response(token)
    response.headers['Content-Type'] = 'application/jwt'
    return response


# ── Startup ───────────────────────────────────────────────────────────────────

# Initialize DB and seed keys when the module is loaded
init_db()
generate_and_store_key(expired=False)  # valid key: expires in 1 hour
generate_and_store_key(expired=True)   # expired key: expired 1 hour ago

if __name__ == '__main__':
    app.run(port=8080)
