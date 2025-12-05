"""
Generic, vendor-neutral APIs for SamiGPT.

This package defines interfaces and DTOs for:
- Case management (`case_management.py`)
- SIEM (`siem.py`)
- EDR (`edr.py`)

The orchestrator and LLM tools depend only on these modules, never on
vendor-specific integrations.
"""


