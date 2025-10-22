"""
HMAC Authorization Header Parser
"""

import logging
from typing import Optional
from .auth_request import AuthRequest

logger = logging.getLogger(__name__)


class AuthHeaderParser:
    """Parses HMAC authorization headers"""

    @staticmethod
    def parse(auth_header: str) -> Optional[AuthRequest]:
        """
        Parse HMAC authorization header

        Expected format: HMAC client_id="xxx",timestamp="xxx",nonce="xxx",signature="xxx"

        Args:
            auth_header: The Authorization header value

        Returns:
            AuthRequest object if valid, None otherwise
        """
        if not auth_header.startswith('HMAC '):
            logger.warning("Authorization header does not start with 'HMAC '")
            return None

        try:
            # Remove 'HMAC ' prefix and parse key=value pairs
            auth_parts = auth_header[5:].split(',')
            auth_dict = {}

            for part in auth_parts:
                key, value = part.strip().split('=', 1)
                auth_dict[key] = value.strip('"')

            # Validate all required fields are present
            required_fields = ['client_id', 'timestamp', 'nonce', 'signature']
            if not all(field in auth_dict for field in required_fields):
                missing = [f for f in required_fields if f not in auth_dict]
                logger.warning(f"Missing required auth parameters: {missing}")
                return None

            # Create and return AuthRequest object
            return AuthRequest(
                client_id=auth_dict['client_id'],
                timestamp=auth_dict['timestamp'],
                nonce=auth_dict['nonce'],
                signature=auth_dict['signature']
            )

        except (ValueError, KeyError) as e:
            logger.error(f"Error parsing auth header: {e}")
            return None
