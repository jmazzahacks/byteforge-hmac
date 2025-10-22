"""
HMAC Signature Validator
"""

import hashlib
import hmac
import logging
from .secret_provider import SecretProvider

logger = logging.getLogger(__name__)


class HMACValidator:
    """Validates HMAC signatures for authentication requests"""

    def __init__(self, secret_provider: SecretProvider):
        """
        Initialize HMAC validator

        Args:
            secret_provider: Provider for retrieving client secrets
        """
        self.secret_provider = secret_provider

    def verify_signature(
        self,
        client_id: str,
        timestamp: str,
        nonce: str,
        signature: str,
        method: str,
        path: str,
        body: str = ''
    ) -> bool:
        """
        Verify HMAC-SHA256 signature

        Args:
            client_id: Client identifier
            timestamp: Request timestamp
            nonce: Unique request nonce
            signature: HMAC signature to verify
            method: HTTP method (GET, POST, etc.)
            path: Request path
            body: Request body (optional)

        Returns:
            True if signature is valid, False otherwise
        """
        # Get client secret
        client_secret = self.secret_provider.get_secret(client_id)
        if not client_secret:
            logger.warning(f"Unknown client_id: {client_id}")
            return False

        # Create message to sign
        message = f"{method}\n{path}\n{timestamp}\n{nonce}\n{body}"

        # Calculate expected signature
        expected_signature = hmac.new(
            client_secret.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        # Constant-time comparison
        return hmac.compare_digest(signature, expected_signature)
