"""
Test client for HMAC authenticated requests
"""

import sys
sys.path.insert(0, 'src')

import time
import hashlib
import hmac
import uuid
import requests
import json


class HMACClient:
    """Simple HMAC client for testing"""

    def __init__(self, client_id: str, secret_key: str, base_url: str = 'http://localhost:5001'):
        self.client_id = client_id
        self.secret_key = secret_key
        self.base_url = base_url

    def _generate_signature(self, method: str, path: str, timestamp: str, nonce: str, body: str = '') -> str:
        """Generate HMAC-SHA256 signature"""
        message = f"{method}\n{path}\n{timestamp}\n{nonce}\n{body}"
        signature = hmac.new(
            self.secret_key.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        return signature

    def _create_auth_header(self, method: str, path: str, body: str = '') -> str:
        """Create Authorization header"""
        timestamp = str(int(time.time()))
        nonce = str(uuid.uuid4())
        signature = self._generate_signature(method, path, timestamp, nonce, body)

        auth_header = f'HMAC client_id="{self.client_id}",timestamp="{timestamp}",nonce="{nonce}",signature="{signature}"'
        return auth_header

    def get(self, path: str) -> requests.Response:
        """Make authenticated GET request"""
        headers = {
            'Authorization': self._create_auth_header('GET', path)
        }
        url = f"{self.base_url}{path}"
        return requests.get(url, headers=headers)

    def post(self, path: str, data: dict = None) -> requests.Response:
        """Make authenticated POST request"""
        body = json.dumps(data) if data else ''
        headers = {
            'Authorization': self._create_auth_header('POST', path, body),
            'Content-Type': 'application/json'
        }
        url = f"{self.base_url}{path}"
        return requests.post(url, headers=headers, data=body)


def main():
    """Test the HMAC authentication"""
    print("\n" + "="*60)
    print("HMAC Client Test")
    print("="*60 + "\n")

    # Create client
    client = HMACClient(
        client_id='test_client_1',
        secret_key='secret_key_123'
    )

    # Test GET request
    print("Testing GET /api/data...")
    response = client.get('/api/data')
    print(f"Status: {response.status_code}")
    try:
        print(f"Response: {json.dumps(response.json(), indent=2)}\n")
    except Exception as e:
        print(f"Response (text): {response.text}\n")
        print(f"Error: {e}\n")

    # Test POST request
    print("Testing POST /api/data...")
    test_data = {
        'name': 'Test Item',
        'value': 42,
        'timestamp': int(time.time())
    }
    response = client.post('/api/data', test_data)
    print(f"Status: {response.status_code}")
    try:
        print(f"Response: {json.dumps(response.json(), indent=2)}\n")
    except Exception as e:
        print(f"Response (text): {response.text}\n")
        print(f"Error: {e}\n")

    # Test invalid signature
    print("Testing with invalid client...")
    bad_client = HMACClient(
        client_id='test_client_1',
        secret_key='wrong_secret'
    )
    response = bad_client.get('/api/data')
    print(f"Status: {response.status_code}")
    try:
        print(f"Response: {json.dumps(response.json(), indent=2)}\n")
    except Exception as e:
        print(f"Response (text): {response.text}\n")
        print(f"Error: {e}\n")

    print("="*60)


if __name__ == '__main__':
    main()
