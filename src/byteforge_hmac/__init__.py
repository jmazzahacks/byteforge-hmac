"""
HMAC Authentication Library

Server-side components:
- HMACAuthenticator: Main authenticator for validating requests
- AuthHeaderParser: Parse HMAC authorization headers
- SecretProvider: Abstract base for secret retrieval
- DictSecretProvider: In-memory secret storage

Client-side components:
- HMACClient: Client for making authenticated requests

Validators:
- HMACValidator: HMAC signature verification
- TimestampValidator: Timestamp freshness validation
- ReplayProtector: Nonce-based replay attack prevention

Models:
- AuthRequest: Authentication request data model
"""

from .secret_provider import SecretProvider
from .dict_secret_provider import DictSecretProvider
from .hmac_validator import HMACValidator
from .timestamp_validator import TimestampValidator
from .replay_protector import ReplayProtector
from .hmac_authenticator import HMACAuthenticator
from .auth_request import AuthRequest
from .auth_header_parser import AuthHeaderParser
from .hmac_client import HMACClient

__all__ = [
    # Server-side
    'HMACAuthenticator',
    'AuthHeaderParser',
    'SecretProvider',
    'DictSecretProvider',
    # Client-side
    'HMACClient',
    # Validators
    'HMACValidator',
    'TimestampValidator',
    'ReplayProtector',
    # Models
    'AuthRequest',
]
__version__ = '0.1.2'
