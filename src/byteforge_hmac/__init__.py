"""
HMAC Authentication Library
"""

from .secret_provider import SecretProvider
from .dict_secret_provider import DictSecretProvider
from .hmac_validator import HMACValidator
from .timestamp_validator import TimestampValidator
from .replay_protector import ReplayProtector
from .hmac_authenticator import HMACAuthenticator
from .auth_request import AuthRequest
from .auth_header_parser import AuthHeaderParser

__all__ = [
    'SecretProvider',
    'DictSecretProvider',
    'HMACValidator',
    'TimestampValidator',
    'ReplayProtector',
    'HMACAuthenticator',
    'AuthRequest',
    'AuthHeaderParser',
]
__version__ = '0.1.0'
