"""
Flask Test Server for HMAC Authentication

This server demonstrates how to use the byteforge-hmac library to protect
API endpoints with HMAC-SHA256 authentication. It includes:
- Timestamp validation (300 second tolerance)
- Replay attack protection via nonce tracking
- HMAC-SHA256 signature verification

Test this server using test_client.py or any HTTP client that can generate
proper HMAC signatures.
"""

import sys
sys.path.insert(0, 'src')

from flask import Flask, request, jsonify
from byteforge_hmac import (
    HMACAuthenticator,
    DictSecretProvider,
    AuthHeaderParser
)

app = Flask(__name__)

# Test client credentials (client_id: secret_key)
# In production, these would come from a database or secret management service
TEST_CLIENTS = {
    'test_client_1': 'secret_key_123',
    'test_client_2': 'another_secret_456'
}

# Initialize HMAC authenticator with dictionary-based secret provider
# Timestamp tolerance of 300 seconds (5 minutes) allows for clock drift
secret_provider = DictSecretProvider(TEST_CLIENTS)
authenticator = HMACAuthenticator(
    secret_provider=secret_provider,
    timestamp_tolerance=300
)


@app.route('/api/data', methods=['GET'])
def get_data():
    """
    GET endpoint requiring HMAC authentication

    Returns a list of items if authentication succeeds.
    """
    # Parse the Authorization header
    # Expected format: HMAC client_id="xxx",timestamp="xxx",nonce="xxx",signature="xxx"
    auth_header = request.headers.get('Authorization', '')
    auth_request = AuthHeaderParser.parse(auth_header)

    if not auth_request:
        return jsonify({'error': 'Unauthorized'}), 401

    # Extract request details needed for signature verification
    method = request.method
    path = request.path
    body = request.get_data(as_text=True) or ''

    # Perform HMAC authentication
    # This validates: timestamp freshness, nonce uniqueness, and HMAC signature
    if not authenticator.authenticate(auth_request, method, path, body):
        return jsonify({'error': 'Authentication failed'}), 403

    # Authentication successful - return protected data
    return jsonify({
        'status': 'success',
        'message': 'GET request authenticated successfully',
        'data': {
            'items': ['item1', 'item2', 'item3']
        }
    }), 200


@app.route('/api/data', methods=['POST'])
def post_data():
    """
    POST endpoint requiring HMAC authentication

    Accepts JSON data and echoes it back if authentication succeeds.
    The request body is included in the HMAC signature calculation.
    """
    # Parse the Authorization header
    auth_header = request.headers.get('Authorization', '')
    auth_request = AuthHeaderParser.parse(auth_header)

    if not auth_request:
        return jsonify({'error': 'Unauthorized'}), 401

    # Extract request details needed for signature verification
    # IMPORTANT: For POST requests, the body must be read as text for signature verification
    method = request.method
    path = request.path
    body = request.get_data(as_text=True) or ''

    # Perform HMAC authentication
    # The signature is calculated over: method + path + timestamp + nonce + body
    if not authenticator.authenticate(auth_request, method, path, body):
        return jsonify({'error': 'Authentication failed'}), 403

    # Authentication successful - process the request
    # Now we can safely parse the JSON body
    data = request.get_json(silent=True) or {}

    return jsonify({
        'status': 'success',
        'message': 'POST request authenticated successfully',
        'received': data
    }), 200


@app.route('/')
def index():
    """
    Server information endpoint (unauthenticated)

    Returns server details, available endpoints, and authentication format.
    """
    return jsonify({
        'name': 'HMAC Authentication Test Server',
        'version': '0.1.0',
        'endpoints': {
            'GET /api/data': 'Requires HMAC authentication',
            'POST /api/data': 'Requires HMAC authentication'
        },
        'test_clients': list(TEST_CLIENTS.keys()),
        'auth_format': 'HMAC client_id="xxx",timestamp="xxx",nonce="xxx",signature="xxx"'
    })


if __name__ == '__main__':
    # Display server startup information
    print("\n" + "="*60)
    print("HMAC Authentication Test Server")
    print("="*60)
    print("\nTest Clients (client_id: secret_key):")
    for client_id, secret in TEST_CLIENTS.items():
        print(f"  - {client_id}: {secret}")
    print("\nEndpoints:")
    print("  GET  /           - Server info (unauthenticated)")
    print("  GET  /api/data   - Protected endpoint (requires HMAC auth)")
    print("  POST /api/data   - Protected endpoint (requires HMAC auth)")
    print("\nAuthentication:")
    print("  - Timestamp tolerance: 300 seconds")
    print("  - Replay protection: Enabled (nonce tracking)")
    print("  - Signature algorithm: HMAC-SHA256")
    print("\n" + "="*60 + "\n")

    # Start Flask development server on port 5001
    # Note: Port 5000 conflicts with macOS AirPlay service
    app.run(debug=True, port=5001)
