"""Analyst approval queue for AI-suggested SOC actions.

The AI files a request instead of executing irreversible work. The Requests
view lets an analyst approve, deny, or answer a question. Handlers then run
against the originating Elastic cluster (or record that an API is still needed).
"""

from .catalog import ACTION_CATALOG, get_action_spec, list_action_specs
from .models import ApprovalRequest, RequestStatus
from .service import ApprovalQueue, get_queue, init_queue

__all__ = [
    "ACTION_CATALOG",
    "ApprovalQueue",
    "ApprovalRequest",
    "RequestStatus",
    "get_action_spec",
    "get_queue",
    "init_queue",
    "list_action_specs",
]
