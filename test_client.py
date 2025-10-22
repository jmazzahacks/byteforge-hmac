"""
Test Client for HMAC Authentication

Demonstrates usage of the HMACClient library for making authenticated requests
to the test server.
"""

import sys
sys.path.insert(0, 'src')

import time
import json
from byteforge_hmac import HMACClient


def main():
    """Test the HMAC authentication library"""
    print("\n" + "="*60)
    print("HMAC Client Library Test")
    print("="*60 + "\n")

    # Initialize client with credentials
    # The client automatically handles signature generation, timestamps, and nonces
    client = HMACClient(
        client_id='test_client_1',
        secret_key='secret_key_123',
        base_url='http://localhost:5001'
    )

    # Test 1: Authenticated GET request
    print("Test 1: GET /api/data (valid credentials)")
    print("-" * 60)
    response = client.get('/api/data')
    print(f"Status: {response.status_code}")
    try:
        print(f"Response: {json.dumps(response.json(), indent=2)}\n")
    except Exception as e:
        print(f"Response (text): {response.text}")
        print(f"Error: {e}\n")

    # Test 2: Authenticated POST request with JSON data
    print("Test 2: POST /api/data (valid credentials)")
    print("-" * 60)
    test_data = {
        'name': 'Test Item',
        'value': 42,
        'timestamp': int(time.time())
    }
    response = client.post('/api/data', data=test_data)
    print(f"Status: {response.status_code}")
    try:
        print(f"Response: {json.dumps(response.json(), indent=2)}\n")
    except Exception as e:
        print(f"Response (text): {response.text}")
        print(f"Error: {e}\n")

    # Test 3: Invalid credentials should fail authentication
    print("Test 3: GET /api/data (invalid credentials)")
    print("-" * 60)
    bad_client = HMACClient(
        client_id='test_client_1',
        secret_key='wrong_secret',
        base_url='http://localhost:5001'
    )
    response = bad_client.get('/api/data')
    print(f"Status: {response.status_code}")
    try:
        print(f"Response: {json.dumps(response.json(), indent=2)}\n")
    except Exception as e:
        print(f"Response (text): {response.text}")
        print(f"Error: {e}\n")

    print("="*60)
    print("All tests completed!")
    print("="*60)


if __name__ == '__main__':
    main()
