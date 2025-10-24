# byteforge-hmac

A Python library for HMAC-based HTTP request authentication with built-in timestamp validation and replay attack protection.

## Features

- **HMAC-SHA256 Signature Verification** - Cryptographically secure request authentication
- **Timestamp Validation** - Configurable tolerance window to prevent stale requests
- **Replay Attack Protection** - Nonce tracking to prevent request replay
- **Server & Client Components** - Complete solution for both sides of authentication
- **Flexible Secret Management** - Pluggable secret provider architecture
- **Framework Agnostic** - Works with Flask, Django, FastAPI, or any Python web framework

## Installation

```bash
pip install byteforge-hmac
```

For development with Flask examples:
```bash
pip install byteforge-hmac[dev]
```

## Quick Start

### Server-Side: Protecting API Endpoints

```python
from flask import Flask, request, jsonify
from byteforge_hmac import (
    HMACAuthenticator,
    DictSecretProvider,
    AuthHeaderParser
)

app = Flask(__name__)

# Initialize with your client secrets
# In production, use a database or secret management service
secrets = {
    'client_123': 'secret_key_abc',
    'client_456': 'secret_key_xyz'
}

secret_provider = DictSecretProvider(secrets)
authenticator = HMACAuthenticator(
    secret_provider=secret_provider,
    timestamp_tolerance=300  # 5 minutes
)

@app.route('/api/protected', methods=['GET', 'POST'])
def protected_endpoint():
    # Parse the Authorization header
    auth_header = request.headers.get('Authorization', '')
    auth_request = AuthHeaderParser.parse(auth_header)

    if not auth_request:
        return jsonify({'error': 'Unauthorized'}), 401

    # Extract request details
    method = request.method
    path = request.path
    body = request.get_data(as_text=True) or ''

    # Authenticate the request
    if not authenticator.authenticate(auth_request, method, path, body):
        return jsonify({'error': 'Authentication failed'}), 403

    # Request is authenticated - proceed with business logic
    return jsonify({'status': 'success', 'data': 'Protected resource'})
```

### Client-Side: Making Authenticated Requests

```python
from byteforge_hmac import HMACClient

# Initialize the client
client = HMACClient(
    client_id='client_123',
    secret_key='secret_key_abc',
    base_url='https://api.example.com'
)

# Make authenticated GET request
response = client.get('/api/protected')
print(response.json())

# Make authenticated POST request with data
data = {'name': 'example', 'value': 42}
response = client.post('/api/protected', data=data)
print(response.json())

# Other HTTP methods are also supported
response = client.put('/api/resource', data={'update': 'value'})
response = client.delete('/api/resource')
```

## How It Works

### Authentication Flow

1. **Client generates a signature**:
   - Creates a Unix timestamp
   - Generates a unique nonce (UUID)
   - Computes HMAC-SHA256 signature over: `{method}\n{path}\n{timestamp}\n{nonce}\n{body}`
   - Sends request with Authorization header

2. **Server validates the request**:
   - **Timestamp Check**: Ensures request is within tolerance window (prevents stale requests)
   - **Replay Check**: Verifies nonce hasn't been seen before (prevents replay attacks)
   - **Signature Verification**: Recomputes signature and compares using constant-time comparison

### Authorization Header Format

```
Authorization: HMAC client_id="client_123",timestamp="1234567890",nonce="uuid-string",signature="hex-signature"
```

### Signature Calculation

The HMAC-SHA256 signature is calculated over the following message format:

```
{HTTP_METHOD}\n{PATH}\n{TIMESTAMP}\n{NONCE}\n{BODY}
```

Example for `POST /api/data` with body `{"key":"value"}`:
```
POST\n/api/data\n1234567890\nuuid-here\n{"key":"value"}
```

## Server-Side Usage

### Custom Secret Provider

Implement your own secret provider to integrate with databases or secret management services:

```python
from byteforge_hmac import SecretProvider
from typing import Optional

class DatabaseSecretProvider(SecretProvider):
    def __init__(self, db_connection):
        self.db = db_connection

    def get_secret(self, client_id: str) -> Optional[str]:
        # Query your database
        result = self.db.query(
            "SELECT secret_key FROM clients WHERE client_id = %s",
            (client_id,)
        )
        return result[0] if result else None

# Use it with the authenticator
secret_provider = DatabaseSecretProvider(db_connection)
authenticator = HMACAuthenticator(secret_provider=secret_provider)
```

### Configuration Options

```python
authenticator = HMACAuthenticator(
    secret_provider=secret_provider,
    timestamp_tolerance=300,  # Time tolerance in seconds (default: 300)
    nonce_storage={}         # Optional: provide your own dict-like storage
)
```

### Persistent Nonce Storage

⚠️ **Required for Production:** For production environments with multiple server instances or concurrent request handling, you **MUST** use a thread-safe shared storage backend.

**Redis provides atomic operations** that prevent the race condition in the default dict storage:

```python
import redis

class RedisNonceStorage:
    """Thread-safe nonce storage using Redis"""

    def __init__(self, redis_client):
        self.redis = redis_client

    def __contains__(self, key):
        return self.redis.exists(key)

    def __setitem__(self, key, value):
        # Store with expiration matching timestamp tolerance
        # Redis operations are atomic, preventing race conditions
        self.redis.setex(key, 300, value)

    def __getitem__(self, key):
        result = self.redis.get(key)
        return int(result) if result else None

    def items(self):
        # Not needed for ReplayProtector cleanup logic with Redis
        # Redis handles expiration automatically
        return []

redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)
nonce_storage = RedisNonceStorage(redis_client)

authenticator = HMACAuthenticator(
    secret_provider=secret_provider,
    nonce_storage=nonce_storage
)
```

**Note:** Redis's atomic operations ensure that checking and storing a nonce happens atomically, preventing the race condition present in the default dict storage.

### Framework Integration Examples

#### Django

```python
from django.http import JsonResponse
from byteforge_hmac import HMACAuthenticator, AuthHeaderParser

def protected_view(request):
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    auth_request = AuthHeaderParser.parse(auth_header)

    if not auth_request:
        return JsonResponse({'error': 'Unauthorized'}, status=401)

    method = request.method
    path = request.path
    body = request.body.decode('utf-8') if request.body else ''

    if not authenticator.authenticate(auth_request, method, path, body):
        return JsonResponse({'error': 'Authentication failed'}, status=403)

    return JsonResponse({'status': 'success'})
```

#### FastAPI

```python
from fastapi import FastAPI, Request, HTTPException, Depends
from byteforge_hmac import HMACAuthenticator, AuthHeaderParser

app = FastAPI()

async def verify_hmac(request: Request):
    auth_header = request.headers.get('authorization', '')
    auth_request = AuthHeaderParser.parse(auth_header)

    if not auth_request:
        raise HTTPException(status_code=401, detail="Unauthorized")

    # Read body
    body = await request.body()
    body_str = body.decode('utf-8') if body else ''

    if not authenticator.authenticate(
        auth_request,
        request.method,
        request.url.path,
        body_str
    ):
        raise HTTPException(status_code=403, detail="Authentication failed")

    return auth_request

@app.post("/api/protected")
async def protected_endpoint(auth_request = Depends(verify_hmac)):
    return {"status": "success", "client_id": auth_request.client_id}
```

## Client-Side Usage

### Basic Client Usage

```python
from byteforge_hmac import HMACClient

client = HMACClient(
    client_id='your_client_id',
    secret_key='your_secret_key',
    base_url='https://api.example.com'
)

# GET request
response = client.get('/api/users')

# POST request with JSON data
response = client.post('/api/users', data={'name': 'John', 'email': 'john@example.com'})

# PUT request
response = client.put('/api/users/123', data={'name': 'Jane'})

# DELETE request
response = client.delete('/api/users/123')
```

### Advanced Client Usage

```python
# Pass additional requests library arguments
response = client.get(
    '/api/data',
    params={'page': 1, 'limit': 10},
    timeout=30
)

# Custom headers (Authorization header is automatically added)
response = client.post(
    '/api/data',
    data={'key': 'value'},
    headers={'X-Custom-Header': 'custom-value'}
)

# Using the generic request method
response = client.request(
    'PATCH',
    '/api/resource',
    data={'field': 'updated'}
)
```

### Manual Signature Generation

If you need to generate signatures manually without using `HMACClient`:

```python
import hmac
import hashlib
import time
import uuid

def generate_hmac_signature(secret_key, method, path, timestamp, nonce, body=''):
    message = f"{method}\n{path}\n{timestamp}\n{nonce}\n{body}"
    signature = hmac.new(
        secret_key.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    return signature

# Generate components
timestamp = str(int(time.time()))
nonce = str(uuid.uuid4())
signature = generate_hmac_signature(
    'your_secret_key',
    'GET',
    '/api/data',
    timestamp,
    nonce
)

# Create Authorization header
auth_header = f'HMAC client_id="your_client",timestamp="{timestamp}",nonce="{nonce}",signature="{signature}"'
```

## Security Considerations

### Timestamp Tolerance

The `timestamp_tolerance` parameter defines how old a request can be before it's rejected. Consider:

- **Shorter tolerance** (e.g., 60 seconds): More secure but requires tighter clock synchronization
- **Longer tolerance** (e.g., 300 seconds): More forgiving of clock drift but larger replay window
- Default is 300 seconds (5 minutes)

### Nonce Storage

⚠️ **CRITICAL: Thread Safety Warning**

The default in-memory dictionary storage is **NOT thread-safe** and has a race condition vulnerability. In multi-threaded or multi-process environments (most production web servers), the same nonce can be accepted multiple times, bypassing replay protection.

**Production Deployment Requirements:**

- **❌ NEVER use default dict storage in production** with concurrent request handling
- **✅ ALWAYS use thread-safe external storage** (Redis, Memcached, etc.) for production
- **✅ Implement proper locking** if using custom storage backends

**Storage Options:**

- **In-memory storage** (default dict): **ONLY for single-threaded development/testing**
- **Redis/Memcached**: **Required for production** with multiple workers/threads
- **Database with row locking**: Possible but may have performance implications
- Nonces should be stored for at least `timestamp_tolerance` duration

**Example Production Setup with Redis:**

See the "Persistent Nonce Storage" section above for Redis implementation with proper atomic operations.

### Secret Key Management

- **Never hardcode secrets** in your application code
- Use environment variables or secret management services (AWS Secrets Manager, HashiCorp Vault, etc.)
- Rotate keys periodically
- Use cryptographically strong random keys (at least 32 bytes of entropy)

### TLS/SSL Encryption

⚠️ **IMPORTANT: This library does NOT provide encryption**

HMAC authentication provides:
- ✅ Request authentication (proves who sent it)
- ✅ Request integrity (detects tampering)
- ❌ **NO encryption** of request/response data

**Production Deployment Requirements:**

Your application **MUST** be deployed behind a TLS-enabled reverse proxy (nginx, Apache, AWS ALB, etc.) to ensure:
- Request/response confidentiality
- Protection against man-in-the-middle attacks
- Server authentication

**Recommended Architecture:**

```
Internet → [Nginx with TLS] → [Your Python App with HMAC Auth]
```

**Example nginx configuration:**

```nginx
server {
    listen 443 ssl http2;
    server_name api.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:5001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Without TLS, request bodies and secrets are transmitted in plaintext over the network.

## Testing

Run the included test server and client:

```bash
# Terminal 1: Start the test server
python test_server.py

# Terminal 2: Run the test client
python test_client.py
```

The test server runs on `http://localhost:5001` with these test credentials:
- Client ID: `test_client_1`, Secret: `secret_key_123`
- Client ID: `test_client_2`, Secret: `another_secret_456`

## API Reference

### Server Components

#### `HMACAuthenticator`
Main authenticator class that coordinates all validation steps.

```python
HMACAuthenticator(
    secret_provider: SecretProvider,
    timestamp_tolerance: int = 300,
    nonce_storage: Optional[Dict[str, int]] = None
)
```

**Methods:**
- `authenticate(auth_request, method, path, body='') -> bool`: Perform complete authentication

#### `AuthHeaderParser`
Parses HMAC authorization headers.

**Methods:**
- `parse(auth_header: str) -> Optional[AuthRequest]`: Parse Authorization header

#### `SecretProvider`
Abstract base class for retrieving client secrets.

**Methods:**
- `get_secret(client_id: str) -> Optional[str]`: Get secret for a client

#### `DictSecretProvider`
Dictionary-based secret provider for testing/simple use cases.

```python
DictSecretProvider(secrets: Dict[str, str])
```

### Client Components

#### `HMACClient`
Client for making HMAC-authenticated HTTP requests.

```python
HMACClient(
    client_id: str,
    secret_key: str,
    base_url: str = 'http://localhost:5001'
)
```

**Methods:**
- `get(path, **kwargs) -> requests.Response`
- `post(path, data=None, **kwargs) -> requests.Response`
- `put(path, data=None, **kwargs) -> requests.Response`
- `delete(path, **kwargs) -> requests.Response`
- `request(method, path, data=None, **kwargs) -> requests.Response`

### Models

#### `AuthRequest`
Data model for parsed authentication requests.

**Attributes:**
- `client_id: str`
- `timestamp: str`
- `nonce: str`
- `signature: str`

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License

## Author

Jason Byteforge (@jmazzahacks)
