"""
Runbook Manager for reading and parsing investigation runbooks.
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional

from ..core.errors import IntegrationError


class RunbookManager:
    """Manages runbook discovery and parsing."""
    
    def __init__(self, runbooks_dir: Optional[str] = None):
        """
        Initialize runbook manager.
        
        Args:
            runbooks_dir: Path to runbooks directory.
        """
        if runbooks_dir is None:
            # Default to run_books/ relative to project root
            project_root = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
            runbooks_dir = os.path.join(project_root, "run_books")
        
        self.runbooks_dir = runbooks_dir
    
    def find_runbook(self, runbook_name: str, soc_tier: Optional[str] = None) -> Optional[str]:
        """
        Find runbook file by name.
        
        Args:
            runbook_name: Name of runbook (e.g., "initial_alert_triage" or "soc1/triage/initial_alert_triage")
            soc_tier: Optional SOC tier to limit search
        
        Returns:
            Path to runbook file, or None if not found
        """
        # If runbook_name already includes path, use it directly
        if "/" in runbook_name or runbook_name.startswith("soc"):
            # Try as-is first
            runbook_path = os.path.join(self.runbooks_dir, f"{runbook_name}.md")
            if os.path.exists(runbook_path):
                return runbook_path
            
            # Try without .md extension
            runbook_path = os.path.join(self.runbooks_dir, runbook_name)
            if os.path.exists(runbook_path):
                return runbook_path
        
        # Search for runbook
        for root, dirs, files in os.walk(self.runbooks_dir):
            # Filter by soc_tier if provided
            if soc_tier and f"/{soc_tier}/" not in root:
                continue
            
            for file in files:
                if file.endswith(".md"):
                    # Check if filename matches (without extension)
                    if file[:-3] == runbook_name or file[:-3].endswith(f"/{runbook_name}"):
                        return os.path.join(root, file)
                    
                    # Check if filename contains runbook_name
                    if runbook_name in file[:-3]:
                        return os.path.join(root, file)
        
        return None
    
    def list_runbooks(
        self,
        soc_tier: Optional[str] = None,
        category: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        List available runbooks.
        
        Args:
            soc_tier: Filter by SOC tier (soc1, soc2, soc3)
            category: Filter by category (triage, investigation, response, forensics, correlation)
        
        Returns:
            List of runbook metadata dictionaries
        """
        runbooks = []
        
        if not os.path.exists(self.runbooks_dir):
            return runbooks
        
        for root, dirs, files in os.walk(self.runbooks_dir):
            # Filter by soc_tier
            if soc_tier and f"/{soc_tier}/" not in root:
                continue
            
            # Filter by category
            if category:
                if f"/{category}/" not in root:
                    continue
            
            for file in files:
                if file.endswith(".md") and file not in [
                    "README.md",
                    "index.md",
                    "SOC_TIER_ORGANIZATION_PLAN.md",
                    "IMPLEMENTATION_SUMMARY.md",
                    "RUNBOOK_INTEGRATION_PROPOSAL.md",
                    "AGENT_PROFILES_IMPLEMENTATION.md",
                    "guidelines.md",  # SOC tier guidelines are not executable runbooks
                ]:
                    runbook_path = os.path.join(root, file)
                    runbook_meta = self.parse_runbook_metadata(runbook_path)
                    
                    # Get relative path from runbooks_dir
                    rel_path = os.path.relpath(runbook_path, self.runbooks_dir)
                    runbook_name = rel_path[:-3]  # Remove .md extension
                    
                    runbooks.append({
                        "name": runbook_name,
                        "path": runbook_path,
                        "soc_tier": runbook_meta.get("soc_tier"),
                        "category": runbook_meta.get("category"),
                        "objective": runbook_meta.get("objective", "")[:200],
                        "description": runbook_meta.get("description", "")[:200]
                    })
        
        return runbooks
    
    def read_runbook(self, runbook_path: str) -> str:
        """
        Read runbook content from file.
        
        Args:
            runbook_path: Path to runbook file
        
        Returns:
            Runbook content as string
        """
        if not os.path.exists(runbook_path):
            raise IntegrationError(f"Runbook not found: {runbook_path}")
        
        with open(runbook_path, "r", encoding="utf-8") as f:
            return f.read()
    
    def parse_runbook_metadata(self, runbook_path: str, content: Optional[str] = None) -> Dict[str, Any]:
        """
        Parse metadata from runbook markdown.
        
        Args:
            runbook_path: Path to runbook file
            content: Optional runbook content (if already loaded)
        
        Returns:
            Dictionary with parsed metadata
        """
        if content is None:
            content = self.read_runbook(runbook_path)
        
        metadata = {}
        
        # Extract SOC tier from path
        if "/soc1/" in runbook_path:
            metadata["soc_tier"] = "soc1"
        elif "/soc2/" in runbook_path:
            metadata["soc_tier"] = "soc2"
        elif "/soc3/" in runbook_path:
            metadata["soc_tier"] = "soc3"
        
        # Extract category from path
        if "/triage/" in runbook_path:
            metadata["category"] = "triage"
        elif "/investigation/" in runbook_path:
            metadata["category"] = "investigation"
        elif "/response/" in runbook_path:
            metadata["category"] = "response"
        elif "/forensics/" in runbook_path:
            metadata["category"] = "forensics"
        elif "/correlation/" in runbook_path:
            metadata["category"] = "correlation"
        elif "/enrichment/" in runbook_path:
            metadata["category"] = "enrichment"
        elif "/remediation/" in runbook_path:
            metadata["category"] = "remediation"
        elif "/cases/" in runbook_path:
            # Case-specific runbooks are sub-runbooks
            metadata["category"] = "cases"
        
        # Extract objective
        obj_match = re.search(r"## Objective\s*\n\s*\n(.*?)(?=\n##|\Z)", content, re.DOTALL | re.IGNORECASE)
        if obj_match:
            metadata["objective"] = obj_match.group(1).strip()
        
        # Extract scope
        scope_match = re.search(r"## Scope\s*\n\s*\n(.*?)(?=\n##|\Z)", content, re.DOTALL | re.IGNORECASE)
        if scope_match:
            metadata["scope"] = scope_match.group(1).strip()
        
        # Extract tools
        tools_match = re.search(r"## Tools\s*\n\s*\n(.*?)(?=\n##|\Z)", content, re.DOTALL | re.IGNORECASE)
        if tools_match:
            tools_text = tools_match.group(1)
            # Extract tool names (look for backtick-wrapped tool names)
            tool_names = re.findall(r"`([a-z_]+)`", tools_text, re.IGNORECASE)
            metadata["tools"] = list(set(tool_names))  # Remove duplicates
        
        # Extract inputs
        inputs_match = re.search(r"## Inputs\s*\n\s*\n(.*?)(?=\n##|\Z)", content, re.DOTALL | re.IGNORECASE)
        if inputs_match:
            inputs_text = inputs_match.group(1)
            # Extract input variables
            input_vars = re.findall(r"\$\{([A-Z_]+)\}", inputs_text)
            metadata["inputs"] = list(set(input_vars))
        
        # Extract workflow steps count
        steps_match = re.search(r"## Workflow Steps", content, re.IGNORECASE)
        if steps_match:
            # Count numbered steps
            step_count = len(re.findall(r"^\d+\.\s+\*\*", content, re.MULTILINE))
            metadata["step_count"] = step_count
        
        return metadata
    
    def extract_workflow_steps(self, content: str) -> List[Dict[str, Any]]:
        """
        Extract workflow steps from runbook content.
        
        Args:
            content: Runbook content
        
        Returns:
            List of workflow step dictionaries
        """
        steps = []
        
        # Find workflow steps section
        steps_section_match = re.search(
            r"## Workflow Steps.*?\n(.*?)(?=\n```|\n##|\Z)",
            content,
            re.DOTALL | re.IGNORECASE
        )
        
        if not steps_section_match:
            return steps
        
        steps_text = steps_section_match.group(1)
        
        # Extract numbered steps
        step_pattern = r"(\d+)\.\s+\*\*(.*?)\*\*:(.*?)(?=\d+\.\s+\*\*|\Z)"
        step_matches = re.finditer(step_pattern, steps_text, re.DOTALL)
        
        for match in step_matches:
            step_num = int(match.group(1))
            step_title = match.group(2).strip()
            step_content = match.group(3).strip()
            
            steps.append({
                "step_number": step_num,
                "title": step_title,
                "content": step_content
            })
        
        return steps

