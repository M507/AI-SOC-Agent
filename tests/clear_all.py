#!/usr/bin/env python3
"""
Master utility script to clear all test data.

WARNING: This is a destructive operation that will:
- Delete the last 24 hours of data from Elasticsearch indices
- Delete ALL cases in IRIS
- Delete ALL recommendation tasks in ClickUp

Use with extreme caution!

This script executes:
1. tests/integrations/siem/clear_last_24_hours.py
2. tests/integrations/case_management/iris/delete_all_cases.py
3. tests/integrations/eng/clickup/clear_recommendation_tasks.py

Usage:
    python tests/clear_all.py --yes
    python tests/clear_all.py --no-siem
    python tests/clear_all.py --yes --no-siem
    
Options:
    --yes       Skip confirmation prompts for all scripts (use with caution!)
    --no-siem   Skip SIEM cleanup (do not execute Elasticsearch clearing)
"""

import argparse
import logging
import os
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, project_root)


def setup_logging(log_dir: Path) -> logging.Logger:
    """
    Set up logging to both file and console.
    
    Args:
        log_dir: Directory to write log files
        
    Returns:
        Configured logger instance
    """
    # Create log directory if it doesn't exist
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Create log filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"clear_all_{timestamp}.log"
    
    # Configure logging
    logger = logging.getLogger("clear_all")
    logger.setLevel(logging.DEBUG)
    
    # Remove existing handlers
    logger.handlers = []
    
    # File handler (DEBUG level)
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    
    # Console handler (INFO level)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter('%(levelname)s - %(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    logger.info(f"Logging to: {log_file}")
    return logger


def parse_output_for_failures(output: str) -> tuple[bool, str]:
    """
    Parse script output to detect failures even if exit code is 0.
    
    Args:
        output: The stdout output from the script
        
    Returns:
        Tuple of (has_failures: bool, failure_message: str)
    """
    if not output:
        return False, ""
    
    # Look for failure indicators in the output
    output_lower = output.lower()
    
    # Check for "Failed: X" where X > 0
    failed_match = re.search(r'failed:\s*(\d+)', output_lower)
    if failed_match:
        failed_count = int(failed_match.group(1))
        if failed_count > 0:
            # Extract the failure details
            failure_lines = []
            for line in output.split('\n'):
                if '✗' in line or 'failed' in line.lower() or 'error' in line.lower():
                    failure_lines.append(line.strip())
            failure_msg = '\n'.join(failure_lines[:5])  # Limit to first 5 failure lines
            return True, failure_msg
    
    # Check for "Successfully deleted: 0" when there are items to delete
    # This indicates nothing was actually deleted
    if 'successfully deleted: 0' in output_lower:
        # Check if there were items to delete
        total_match = re.search(r'total (?:cases|tasks|index patterns):\s*(\d+)', output_lower)
        if total_match:
            total = int(total_match.group(1))
            if total > 0:
                return True, "No items were successfully deleted despite having items to delete"
    
    return False, ""


def run_script(script_path: str, skip_confirmation: bool, logger: logging.Logger) -> tuple[bool, str]:
    """
    Run a Python script and capture its output.
    
    Args:
        script_path: Path to the script to run
        skip_confirmation: Whether to pass --yes flag
        logger: Logger instance
        
    Returns:
        Tuple of (success: bool, output: str)
    """
    script_name = os.path.basename(script_path)
    logger.info(f"Running script: {script_name}")
    logger.debug(f"Full path: {script_path}")
    
    # Build command
    cmd = [sys.executable, script_path]
    if skip_confirmation:
        cmd.append("--yes")
        logger.debug("Adding --yes flag to skip confirmation")
    
    try:
        # Run the script and capture output
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=project_root,
            timeout=300,  # 5 minute timeout per script
        )
        
        # Extract actual errors from stderr (filter out warnings)
        actual_errors = []
        if result.stderr:
            stderr_lines = result.stderr.split('\n')
            for line in stderr_lines:
                line_lower = line.lower()
                # Skip warnings and urllib3 messages
                if any(skip in line_lower for skip in ['warning', 'urllib3', 'notopenssl', 'insecurerequest']):
                    continue
                # Keep actual error messages
                if 'error' in line_lower or 'failed' in line_lower or 'exception' in line_lower:
                    actual_errors.append(line.strip())
        
        # Combine stdout and actual errors
        combined_output = result.stdout
        if actual_errors:
            combined_output += '\n' + '\n'.join(actual_errors)
        
        # Log the output
        if result.stdout:
            logger.debug(f"STDOUT from {script_name}:\n{result.stdout}")
        if result.stderr:
            logger.debug(f"STDERR from {script_name}:\n{result.stderr}")
        
        # Check exit code first
        if result.returncode != 0:
            logger.error(f"✗ Script {script_name} failed with return code {result.returncode}")
            # Use actual errors if available, otherwise fall back to full stderr
            if actual_errors:
                error_output = '\n'.join(actual_errors)
            else:
                error_output = result.stderr or result.stdout or "No error output"
            logger.error(f"Error output:\n{error_output}")
            return False, error_output
        
        # Exit code is 0 - script completed successfully
        # Even if some items failed to delete, the script did its job of attempting to clear everything
        # and logging errors, so we consider it successful
        logger.info(f"✓ Successfully executed {script_name}")
        
        # Log warnings if there were any failures in the output (for informational purposes)
        has_failures, failure_msg = parse_output_for_failures(result.stdout)
        if has_failures:
            logger.warning(f"Note: {script_name} completed but some items failed to process.")
            logger.debug(f"Failure details:\n{failure_msg}")
        
        return True, result.stdout
            
    except subprocess.TimeoutExpired:
        logger.error(f"✗ Script {script_name} timed out after 5 minutes")
        return False, "Script execution timed out"
    except Exception as e:
        logger.error(f"✗ Failed to execute {script_name}: {e}", exc_info=True)
        return False, str(e)


def clear_all(skip_confirmation: bool = False, skip_siem: bool = False):
    """
    Execute all clearing scripts in sequence.
    
    Args:
        skip_confirmation: Whether to skip confirmation prompts
        skip_siem: Whether to skip SIEM cleanup
    """
    # Set up logging
    log_dir = Path(project_root) / "tests" / "logs"
    logger = setup_logging(log_dir)
    
    logger.info("=" * 70)
    logger.info("Master Clear All Utility")
    logger.info("=" * 70)
    logger.info("")
    
    # Define scripts to run in order
    all_scripts = [
        {
            "path": "tests/integrations/siem/clear_last_24_hours.py",
            "name": "Clear Elasticsearch (last 24 hours)",
            "description": "Deletes the last 24 hours of data from Elasticsearch indices"
        },
        {
            "path": "tests/integrations/case_management/iris/delete_all_cases.py",
            "name": "Delete IRIS Cases",
            "description": "Deletes all cases in IRIS"
        },
        {
            "path": "tests/integrations/eng/clickup/clear_recommendation_tasks.py",
            "name": "Clear ClickUp Recommendations",
            "description": "Deletes all recommendation tasks in ClickUp"
        }
    ]
    
    # Filter out SIEM script if --no-siem flag is set
    scripts = [s for s in all_scripts if not (skip_siem and "siem" in s["path"].lower())]
    
    if skip_siem:
        logger.info("SIEM cleanup is disabled (--no-siem flag provided)")
        logger.info("")
    
    # Show what will be executed
    logger.info("The following operations will be executed:")
    for i, script in enumerate(scripts, 1):
        logger.info(f"  {i}. {script['name']}: {script['description']}")
    
    # Confirm execution
    if not skip_confirmation:
        logger.info("")
        logger.info("WARNING: This will execute all destructive operations listed above!")
        response = input("Are you sure you want to continue? (yes/no): ")
        
        if response.lower() not in ("yes", "y"):
            logger.info("Operation cancelled.")
            return
    else:
        logger.info("")
        logger.info("Skipping confirmation (--yes flag provided)")
    
    # Execute each script
    logger.info("")
    logger.info("=" * 70)
    logger.info("Executing Scripts")
    logger.info("=" * 70)
    
    results = []
    for script in scripts:
        logger.info("")
        script_path = os.path.join(project_root, script["path"])
        
        if not os.path.exists(script_path):
            logger.error(f"Script not found: {script_path}")
            results.append({
                "name": script["name"],
                "success": False,
                "error": "Script file not found"
            })
            continue
        
        success, output = run_script(script_path, skip_confirmation, logger)
        results.append({
            "name": script["name"],
            "success": success,
            "output": output
        })
    
    # Summary
    logger.info("")
    logger.info("=" * 70)
    logger.info("Execution Summary")
    logger.info("=" * 70)
    
    total = len(scripts)
    successful = sum(1 for r in results if r["success"])
    failed = total - successful
    
    logger.info(f"Total scripts: {total}")
    logger.info(f"Successfully executed: {successful}")
    logger.info(f"Failed: {failed}")
    logger.info("")
    
    logger.info("Details:")
    for result in results:
        if result["success"]:
            logger.info(f"  ✓ {result['name']}: Success")
        else:
            logger.info(f"  ✗ {result['name']}: Failed")
            error = result.get("error") or result.get("output", "Unknown error")
            # Show first few lines of error output
            if error and len(error) > 200:
                error_lines = error.split('\n')[:3]
                error = '\n'.join(error_lines) + '...'
            logger.error(f"    Error: {error}")
    
    logger.info("=" * 70)
    
    if failed > 0:
        logger.warning(f"Some scripts failed. Check the log file for details.")
        sys.exit(1)
    else:
        logger.info("All scripts executed successfully!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Clear all test data (Elasticsearch, IRIS, ClickUp)"
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip confirmation prompts for all scripts (use with caution!)"
    )
    parser.add_argument(
        "--no-siem",
        action="store_true",
        help="Skip SIEM cleanup (do not execute Elasticsearch clearing)"
    )
    args = parser.parse_args()
    
    clear_all(skip_confirmation=args.yes, skip_siem=args.no_siem)

