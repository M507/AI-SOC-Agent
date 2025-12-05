"""
Trello client for creating tasks and recommendations.
"""

from __future__ import annotations

from typing import Dict, Any, Optional

from ....core.config import SamiConfig
from ....core.errors import IntegrationError
from ....core.logging import get_logger
from .trello_http import TrelloHttpClient


logger = get_logger("sami.integrations.trello.client")


class TrelloClient:
    """
    Client for interacting with Trello API to create tasks and recommendations.
    """

    def __init__(self, http_client: TrelloHttpClient, fine_tuning_board_id: str, engineering_board_id: str) -> None:
        """
        Initialize Trello client.
        
        Args:
            http_client: HTTP client for Trello API
            fine_tuning_board_id: Trello board ID for fine-tuning recommendations
            engineering_board_id: Trello board ID for engineering/visibility recommendations
        """
        self._http = http_client
        self.fine_tuning_board_id = fine_tuning_board_id
        self.engineering_board_id = engineering_board_id

    @classmethod
    def from_config(cls, config: SamiConfig) -> "TrelloClient":
        """
        Factory to construct a client from ``SamiConfig``.
        
        Args:
            config: SamiConfig instance with Trello configuration
        
        Returns:
            TrelloClient instance
        
        Raises:
            IntegrationError: If Trello configuration is not set
        """
        if not config.eng or not config.eng.trello:
            raise IntegrationError("Trello configuration is not set in SamiConfig")

        trello_config = config.eng.trello
        http_client = TrelloHttpClient(
            api_key=trello_config.api_key,
            api_token=trello_config.api_token,
            timeout_seconds=trello_config.timeout_seconds,
            verify_ssl=trello_config.verify_ssl,
        )
        
        return cls(
            http_client=http_client,
            fine_tuning_board_id=trello_config.fine_tuning_board_id,
            engineering_board_id=trello_config.engineering_board_id,
        )

    def create_fine_tuning_recommendation(
        self,
        title: str,
        description: str,
        list_name: Optional[str] = None,
        labels: Optional[list[str]] = None,
    ) -> Dict[str, Any]:
        """
        Create a fine-tuning recommendation card on the fine-tuning board.
        
        Args:
            title: Card title
            description: Card description
            list_name: Optional list name (defaults to first list on board)
            labels: Optional list of label names to add to the card
        
        Returns:
            Dictionary with card information
        """
        logger.info(f"Creating fine-tuning recommendation: {title}")
        
        # Get lists on the board
        lists = self._http.get(f"/1/boards/{self.fine_tuning_board_id}/lists")
        
        # Find the target list
        target_list_id = None
        if list_name:
            for list_item in lists:
                if list_item.get("name") == list_name:
                    target_list_id = list_item.get("id")
                    break
            if not target_list_id:
                raise IntegrationError(f"List '{list_name}' not found on fine-tuning board")
        else:
            # Use the first list if no list_name specified
            if not lists:
                raise IntegrationError("No lists found on fine-tuning board")
            target_list_id = lists[0].get("id")
        
        # Create the card
        card_data = {
            "name": title,
            "desc": description,
            "idList": target_list_id,
        }
        
        card = self._http.post("/1/cards", json_data=card_data)
        
        # Add labels if provided
        if labels:
            board_labels = self._http.get(f"/1/boards/{self.fine_tuning_board_id}/labels")
            label_map = {label.get("name"): label.get("id") for label in board_labels if label.get("name")}
            
            for label_name in labels:
                if label_name in label_map:
                    # Trello API uses POST /1/cards/{id}/idLabels with value parameter
                    self._http.post(f"/1/cards/{card['id']}/idLabels", params={"value": label_map[label_name]})
                else:
                    logger.warning(f"Label '{label_name}' not found on board, skipping")
        
        logger.info(f"Created fine-tuning recommendation card: {card.get('id')}")
        return card

    def create_visibility_recommendation(
        self,
        title: str,
        description: str,
        list_name: Optional[str] = None,
        labels: Optional[list[str]] = None,
    ) -> Dict[str, Any]:
        """
        Create a visibility/engineering recommendation card on the engineering board.
        
        Args:
            title: Card title
            description: Card description
            list_name: Optional list name (defaults to first list on board)
            labels: Optional list of label names to add to the card
        
        Returns:
            Dictionary with card information
        """
        logger.info(f"Creating visibility recommendation: {title}")
        
        # Get lists on the board
        lists = self._http.get(f"/1/boards/{self.engineering_board_id}/lists")
        
        # Find the target list
        target_list_id = None
        if list_name:
            for list_item in lists:
                if list_item.get("name") == list_name:
                    target_list_id = list_item.get("id")
                    break
            if not target_list_id:
                raise IntegrationError(f"List '{list_name}' not found on engineering board")
        else:
            # Use the first list if no list_name specified
            if not lists:
                raise IntegrationError("No lists found on engineering board")
            target_list_id = lists[0].get("id")
        
        # Create the card
        card_data = {
            "name": title,
            "desc": description,
            "idList": target_list_id,
        }
        
        card = self._http.post("/1/cards", json_data=card_data)
        
        # Add labels if provided
        if labels:
            board_labels = self._http.get(f"/1/boards/{self.engineering_board_id}/labels")
            label_map = {label.get("name"): label.get("id") for label in board_labels if label.get("name")}
            
            for label_name in labels:
                if label_name in label_map:
                    # Trello API uses POST /1/cards/{id}/idLabels with value parameter
                    self._http.post(f"/1/cards/{card['id']}/idLabels", params={"value": label_map[label_name]})
                else:
                    logger.warning(f"Label '{label_name}' not found on board, skipping")
        
        logger.info(f"Created visibility recommendation card: {card.get('id')}")
        return card

    def ping(self) -> bool:
        """
        Check if Trello API is reachable.
        
        Returns:
            True if API is reachable, False otherwise
        """
        try:
            # Try to get boards for the authenticated user
            self._http.get("/1/members/me/boards", params={"limit": 1})
            return True
        except IntegrationError:
            logger.exception("Trello ping failed")
            return False

