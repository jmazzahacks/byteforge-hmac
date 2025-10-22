"""
Dictionary-based Secret Provider Implementation
"""

from typing import Dict, Optional
from .secret_provider import SecretProvider


class DictSecretProvider(SecretProvider):
    """Dictionary-based secret provider implementation"""

    def __init__(self, secrets: Dict[str, str]):
        """
        Initialize with a dictionary of client secrets

        Args:
            secrets: Dictionary mapping client_id to secret_key
        """
        self.secrets = secrets

    def get_secret(self, client_id: str) -> Optional[str]:
        """
        Get secret from dictionary

        Args:
            client_id: Client identifier

        Returns:
            Secret key if found, None otherwise
        """
        return self.secrets.get(client_id)
