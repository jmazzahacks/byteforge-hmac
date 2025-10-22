"""
Complete HMAC Authentication System
"""

import logging
from typing import Dict, Optional
from .secret_provider import SecretProvider
from .hmac_validator import HMACValidator
from .timestamp_validator import TimestampValidator
from .replay_protector import ReplayProtector
from .auth_request import AuthRequest

logger = logging.getLogger(__name__)


class HMACAuthenticator:
    """
    Complete HMAC authentication system combining signature verification,
    timestamp validation, and replay protection
    """

    def __init__(
        self,
        secret_provider: SecretProvider,
        timestamp_tolerance: int = 300,
        nonce_storage: Optional[Dict[str, int]] = None
    ):
        """
        Initialize HMAC authenticator

        Args:
            secret_provider: Provider for retrieving client secrets
            timestamp_tolerance: Maximum time difference in seconds (default: 300)
            nonce_storage: Dictionary for nonce storage (creates new if None)
        """
        self.hmac_validator = HMACValidator(secret_provider)
        self.timestamp_validator = TimestampValidator(timestamp_tolerance)
        self.replay_protector = ReplayProtector(
            nonce_storage if nonce_storage is not None else {}
        )
        self.timestamp_tolerance = timestamp_tolerance

    def authenticate(
        self,
        auth_request: AuthRequest,
        method: str,
        path: str,
        body: str = ''
    ) -> bool:
        """
        Perform complete authentication check

        Args:
            auth_request: Parsed authentication request containing client_id, timestamp, nonce, signature
            method: HTTP method
            path: Request path
            body: Request body (optional)

        Returns:
            True if authentication succeeds, False otherwise
        """
        # Validate timestamp
        if not self.timestamp_validator.validate(auth_request.timestamp):
            return False

        # Check for replay
        if not self.replay_protector.check_and_store(
            auth_request.client_id,
            auth_request.nonce,
            auth_request.timestamp,
            self.timestamp_tolerance
        ):
            return False

        # Verify signature
        if not self.hmac_validator.verify_signature(
            auth_request.client_id,
            auth_request.timestamp,
            auth_request.nonce,
            auth_request.signature,
            method,
            path,
            body
        ):
            logger.warning(f"Invalid signature for client {auth_request.client_id}")
            return False

        logger.info(f"Successfully authenticated client {auth_request.client_id} for {method} {path}")
        return True
