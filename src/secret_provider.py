"""
Secret Provider Abstract Base Class
"""

from abc import ABC, abstractmethod
from typing import Optional


class SecretProvider(ABC):
    """Abstract base class for providing client secrets"""

    @abstractmethod
    def get_secret(self, client_id: str) -> Optional[str]:
        """
        Get the secret key for a given client ID

        Args:
            client_id: Client identifier

        Returns:
            Secret key if client exists, None otherwise
        """
        pass
