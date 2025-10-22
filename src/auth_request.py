"""
Authentication Request Model
"""

from dataclasses import dataclass


@dataclass
class AuthRequest:
    """Represents a parsed HMAC authentication request"""

    client_id: str
    timestamp: str
    nonce: str
    signature: str
