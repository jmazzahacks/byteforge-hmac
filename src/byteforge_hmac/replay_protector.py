"""
Replay Attack Protector
"""

import time
import logging
from typing import Dict

logger = logging.getLogger(__name__)


class ReplayProtector:
    """Protects against replay attacks using nonce tracking"""

    def __init__(self, storage: Dict[str, int]):
        """
        Initialize replay protector

        Args:
            storage: Dictionary for storing seen nonces (nonce_key -> timestamp)
        """
        self.storage = storage

    def check_and_store(
        self,
        client_id: str,
        nonce: str,
        timestamp: str,
        tolerance_seconds: int = 300
    ) -> bool:
        """
        Check if nonce has been seen and store it if not

        Args:
            client_id: Client identifier
            nonce: Unique request nonce
            timestamp: Request timestamp
            tolerance_seconds: How long to keep nonces (default: 300)

        Returns:
            True if nonce is new (not a replay), False if replay detected
        """
        # Clean up old nonces
        current_time = int(time.time())
        cutoff_time = current_time - tolerance_seconds

        # Remove old entries
        self.storage = {k: v for k, v in self.storage.items() if v > cutoff_time}

        # Check if we've seen this nonce
        nonce_key = f"{client_id}:{nonce}"
        if nonce_key in self.storage:
            logger.warning(f"Replay detected for client {client_id}, nonce {nonce}")
            return False

        # Store the nonce with its timestamp
        self.storage[nonce_key] = int(timestamp)
        return True
