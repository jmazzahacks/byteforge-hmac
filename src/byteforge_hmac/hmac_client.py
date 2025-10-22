"""
HMAC Client for Making Authenticated Requests

This module provides a client for making HTTP requests authenticated with HMAC-SHA256
signatures. It handles signature generation, timestamp creation, and nonce generation.
"""

import time
import hashlib
import hmac
import uuid
import json
from typing import Optional, Dict, Any


class HMACClient:
    """
    Client for making HMAC-authenticated HTTP requests

    This client automatically generates HMAC signatures for HTTP requests using:
    - Current Unix timestamp
    - Random UUID nonce
    - HMAC-SHA256 signature algorithm

    The signature is calculated over the message format:
    {method}\n{path}\n{timestamp}\n{nonce}\n{body}
    """

    def __init__(self, client_id: str, secret_key: str, base_url: str = 'http://localhost:5001'):
        """
        Initialize HMAC client

        Args:
            client_id: Client identifier
            secret_key: Secret key for HMAC signature generation
            base_url: Base URL for requests (default: http://localhost:5001)
        """
        self.client_id = client_id
        self.secret_key = secret_key
        self.base_url = base_url

    def _generate_signature(self, method: str, path: str, timestamp: str, nonce: str, body: str = '') -> str:
        """
        Generate HMAC-SHA256 signature

        Args:
            method: HTTP method (GET, POST, etc.)
            path: Request path
            timestamp: Unix timestamp as string
            nonce: Unique nonce
            body: Request body (optional)

        Returns:
            Hexadecimal HMAC-SHA256 signature
        """
        # Create message in the format expected by the server
        message = f"{method}\n{path}\n{timestamp}\n{nonce}\n{body}"

        # Generate HMAC-SHA256 signature
        signature = hmac.new(
            self.secret_key.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        return signature

    def _create_auth_header(self, method: str, path: str, body: str = '') -> str:
        """
        Create Authorization header with HMAC signature

        Args:
            method: HTTP method
            path: Request path
            body: Request body (optional)

        Returns:
            Authorization header value in format:
            HMAC client_id="xxx",timestamp="xxx",nonce="xxx",signature="xxx"
        """
        # Generate timestamp and nonce
        timestamp = str(int(time.time()))
        nonce = str(uuid.uuid4())

        # Generate signature
        signature = self._generate_signature(method, path, timestamp, nonce, body)

        # Format Authorization header
        auth_header = (
            f'HMAC client_id="{self.client_id}",'
            f'timestamp="{timestamp}",'
            f'nonce="{nonce}",'
            f'signature="{signature}"'
        )

        return auth_header

    def request(self, method: str, path: str, data: Optional[Dict[str, Any]] = None, **kwargs) -> 'requests.Response':
        """
        Make an authenticated HTTP request

        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            path: Request path
            data: Request data (will be JSON encoded if provided)
            **kwargs: Additional arguments to pass to requests.request()

        Returns:
            Response object from requests library

        Note:
            Requires the 'requests' library to be installed
        """
        import requests

        # Prepare request body
        body = json.dumps(data) if data else ''

        # Create headers
        headers = kwargs.pop('headers', {})
        headers['Authorization'] = self._create_auth_header(method, path, body)

        if data:
            headers['Content-Type'] = 'application/json'

        # Make request
        url = f"{self.base_url}{path}"
        return requests.request(method, url, headers=headers, data=body, **kwargs)

    def get(self, path: str, **kwargs) -> 'requests.Response':
        """
        Make authenticated GET request

        Args:
            path: Request path
            **kwargs: Additional arguments to pass to requests.get()

        Returns:
            Response object
        """
        return self.request('GET', path, **kwargs)

    def post(self, path: str, data: Optional[Dict[str, Any]] = None, **kwargs) -> 'requests.Response':
        """
        Make authenticated POST request

        Args:
            path: Request path
            data: Request data (will be JSON encoded)
            **kwargs: Additional arguments to pass to requests.post()

        Returns:
            Response object
        """
        return self.request('POST', path, data=data, **kwargs)

    def put(self, path: str, data: Optional[Dict[str, Any]] = None, **kwargs) -> 'requests.Response':
        """
        Make authenticated PUT request

        Args:
            path: Request path
            data: Request data (will be JSON encoded)
            **kwargs: Additional arguments to pass to requests.put()

        Returns:
            Response object
        """
        return self.request('PUT', path, data=data, **kwargs)

    def delete(self, path: str, **kwargs) -> 'requests.Response':
        """
        Make authenticated DELETE request

        Args:
            path: Request path
            **kwargs: Additional arguments to pass to requests.delete()

        Returns:
            Response object
        """
        return self.request('DELETE', path, **kwargs)
