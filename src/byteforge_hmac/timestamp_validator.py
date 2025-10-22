"""
Timestamp Validator
"""

import time
import logging

logger = logging.getLogger(__name__)


class TimestampValidator:
    """Validates request timestamps to prevent replay attacks"""

    def __init__(self, tolerance_seconds: int = 300):
        """
        Initialize timestamp validator

        Args:
            tolerance_seconds: Maximum allowed time difference in seconds (default: 300)
        """
        self.tolerance_seconds = tolerance_seconds

    def validate(self, timestamp: str) -> bool:
        """
        Validate that timestamp is within acceptable tolerance

        Args:
            timestamp: Unix timestamp as string

        Returns:
            True if timestamp is valid, False otherwise
        """
        try:
            request_time = int(timestamp)
            current_time = int(time.time())

            time_diff = abs(current_time - request_time)

            if time_diff > self.tolerance_seconds:
                logger.warning(f"Timestamp outside tolerance: {time_diff} seconds")
                return False

            return True
        except (ValueError, TypeError):
            logger.error(f"Invalid timestamp: {timestamp}")
            return False
