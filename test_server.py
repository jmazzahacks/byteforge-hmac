"""
Minimal Flask test server for HMAC authentication
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

# Test client credentials
TEST_CLIENTS = {
    'test_client_1': 'secret_key_123',
    'test_client_2': 'another_secret_456'
}

# Initialize HMAC authenticator
secret_provider = DictSecretProvider(TEST_CLIENTS)
authenticator = HMACAuthenticator(
    secret_provider=secret_provider,
    timestamp_tolerance=300
)




@app.route('/api/data', methods=['GET'])
def get_data():
    """GET endpoint requiring HMAC authentication"""
    # Parse the Authorization header
    auth_header = request.headers.get('Authorization', '')
    auth_request = AuthHeaderParser.parse(auth_header)

    if not auth_request:
        return jsonify({'error': 'Unauthorized'}), 401

    # Get request details
    method = request.method
    path = request.path
    body = request.get_data(as_text=True) or ''

    # Authenticate
    if not authenticator.authenticate(auth_request, method, path, body):
        return jsonify({'error': 'Authentication failed'}), 403

    return jsonify({
        'status': 'success',
        'message': 'GET request authenticated successfully',
        'data': {
            'items': ['item1', 'item2', 'item3']
        }
    }), 200


@app.route('/api/data', methods=['POST'])
def post_data():
    """POST endpoint requiring HMAC authentication"""
    # Parse the Authorization header
    auth_header = request.headers.get('Authorization', '')
    auth_request = AuthHeaderParser.parse(auth_header)

    if not auth_request:
        return jsonify({'error': 'Unauthorized'}), 401

    # Get request details
    method = request.method
    path = request.path
    body = request.get_data(as_text=True) or ''

    # Authenticate
    if not authenticator.authenticate(auth_request, method, path, body):
        return jsonify({'error': 'Authentication failed'}), 403

    # Get the request body
    data = request.get_json(silent=True) or {}

    return jsonify({
        'status': 'success',
        'message': 'POST request authenticated successfully',
        'received': data
    }), 200


@app.route('/')
def index():
    """Info page about the test server"""
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
    print("\n" + "="*60)
    print("HMAC Authentication Test Server")
    print("="*60)
    print("\nTest Clients:")
    for client_id, secret in TEST_CLIENTS.items():
        print(f"  - {client_id}: {secret}")
    print("\nEndpoints:")
    print("  GET  /           - Server info")
    print("  GET  /api/data   - Protected endpoint")
    print("  POST /api/data   - Protected endpoint")
    print("\n" + "="*60 + "\n")

    app.run(debug=True, port=5001)
