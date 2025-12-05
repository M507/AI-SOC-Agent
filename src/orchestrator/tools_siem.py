"""
LLM-callable tools for SIEM operations.

These functions wrap the generic SIEMClient interface and provide
LLM-friendly error handling and return values.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from ..api.siem import SIEMClient
from ..core.errors import IntegrationError


def search_security_events(
    query: str,
    limit: int = 100,
    client: SIEMClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Search security events across all environments.

    Tool schema:
    - name: search_security_events
    - description: Search security events and logs across all environments
      using a query string. Returns matching events with details.
    - parameters:
      - query (str, required): Search query (vendor-specific query language).
      - limit (int, optional): Maximum number of events to return (default: 100).

    Args:
        query: Search query string.
        limit: Maximum number of events to return.
        client: The SIEM client.

    Returns:
        Dictionary containing search results with events.

    Raises:
        IntegrationError: If search fails.
    """
    if client is None:
        raise IntegrationError("SIEM client not provided")

    try:
        result = client.search_security_events(query=query, limit=limit)

        return {
            "success": True,
            "query": result.query,
            "total_count": result.total_count,
            "returned_count": len(result.events),
            "events": [
                {
                    "id": event.id,
                    "timestamp": event.timestamp.isoformat(),
                    "source_type": event.source_type.value,
                    "message": event.message,
                    "host": event.host,
                    "username": event.username,
                    "ip": event.ip,
                    "process_name": event.process_name,
                    "file_hash": event.file_hash,
                }
                for event in result.events
            ],
        }
    except Exception as e:
        raise IntegrationError(f"Failed to search security events: {str(e)}") from e


def get_file_report(
    file_hash: str,
    client: SIEMClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Get a report about a file by its hash.

    Tool schema:
    - name: get_file_report
    - description: Retrieve an aggregated report about a file identified by
      its hash, including when it was first/last seen, detection count, and
      affected hosts.
    - parameters:
      - file_hash (str, required): The file hash (MD5, SHA256, etc.).

    Args:
        file_hash: The file hash.
        client: The SIEM client.

    Returns:
        Dictionary containing file report details.

    Raises:
        IntegrationError: If retrieving report fails.
    """
    if client is None:
        raise IntegrationError("SIEM client not provided")

    try:
        report = client.get_file_report(file_hash)

        return {
            "success": True,
            "file_hash": report.file_hash,
            "first_seen": report.first_seen.isoformat() if report.first_seen else None,
            "last_seen": report.last_seen.isoformat() if report.last_seen else None,
            "detection_count": report.detection_count,
            "affected_hosts": report.affected_hosts or [],
        }
    except Exception as e:
        raise IntegrationError(f"Failed to get file report for {file_hash}: {str(e)}") from e


def get_file_behavior_summary(
    file_hash: str,
    client: SIEMClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Get a behavior summary for a file.

    Tool schema:
    - name: get_file_behavior_summary
    - description: Retrieve a high-level behavior summary for a file,
      including process trees, network activity, and persistence mechanisms.
    - parameters:
      - file_hash (str, required): The file hash.

    Args:
        file_hash: The file hash.
        client: The SIEM client.

    Returns:
        Dictionary containing behavior summary.

    Raises:
        IntegrationError: If retrieving summary fails.
    """
    if client is None:
        raise IntegrationError("SIEM client not provided")

    try:
        summary = client.get_file_behavior_summary(file_hash)

        return {
            "success": True,
            "file_hash": summary.file_hash,
            "process_trees": summary.process_trees or [],
            "network_activity": summary.network_activity or [],
            "persistence_mechanisms": summary.persistence_mechanisms or [],
            "notes": summary.notes,
        }
    except Exception as e:
        raise IntegrationError(
            f"Failed to get file behavior summary for {file_hash}: {str(e)}"
        ) from e


def get_entities_related_to_file(
    file_hash: str,
    client: SIEMClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Get entities related to a file.

    Tool schema:
    - name: get_entities_related_to_file
    - description: Retrieve entities related to a file hash, such as hosts
      where it was seen, users who executed it, related processes, and alerts.
    - parameters:
      - file_hash (str, required): The file hash.

    Args:
        file_hash: The file hash.
        client: The SIEM client.

    Returns:
        Dictionary containing related entities.

    Raises:
        IntegrationError: If retrieving entities fails.
    """
    if client is None:
        raise IntegrationError("SIEM client not provided")

    try:
        entities = client.get_entities_related_to_file(file_hash)

        return {
            "success": True,
            "indicator": entities.indicator,
            "hosts": entities.hosts or [],
            "users": entities.users or [],
            "processes": entities.processes or [],
            "alerts": entities.alerts or [],
        }
    except Exception as e:
        raise IntegrationError(
            f"Failed to get entities related to file {file_hash}: {str(e)}"
        ) from e


def get_ip_address_report(
    ip: str,
    client: SIEMClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Get a report about an IP address.

    Tool schema:
    - name: get_ip_address_report
    - description: Retrieve an aggregated report about an IP address,
      including reputation, geolocation, and related alerts.
    - parameters:
      - ip (str, required): The IP address.

    Args:
        ip: The IP address.
        client: The SIEM client.

    Returns:
        Dictionary containing IP report details.

    Raises:
        IntegrationError: If retrieving report fails.
    """
    if client is None:
        raise IntegrationError("SIEM client not provided")

    try:
        report = client.get_ip_address_report(ip)

        return {
            "success": True,
            "ip": report.ip,
            "reputation": report.reputation,
            "geo": report.geo or {},
            "related_alerts": report.related_alerts or [],
        }
    except Exception as e:
        raise IntegrationError(f"Failed to get IP address report for {ip}: {str(e)}") from e


def search_user_activity(
    username: str,
    limit: int = 100,
    client: SIEMClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Search for user activity in security logs.

    Tool schema:
    - name: search_user_activity
    - description: Search for security events related to a specific user,
      including authentication events, file access, and other activities.
    - parameters:
      - username (str, required): The username to search for.
      - limit (int, optional): Maximum number of events to return (default: 100).

    Args:
        username: The username.
        limit: Maximum number of events.
        client: The SIEM client.

    Returns:
        Dictionary containing user activity events.

    Raises:
        IntegrationError: If search fails.
    """
    if client is None:
        raise IntegrationError("SIEM client not provided")

    try:
        result = client.search_user_activity(username=username, limit=limit)

        return {
            "success": True,
            "username": username,
            "total_count": result.total_count,
            "returned_count": len(result.events),
            "events": [
                {
                    "id": event.id,
                    "timestamp": event.timestamp.isoformat(),
                    "source_type": event.source_type.value,
                    "message": event.message,
                    "host": event.host,
                    "username": event.username,
                    "ip": event.ip,
                    "process_name": event.process_name,
                    "file_hash": event.file_hash,
                }
                for event in result.events
            ],
        }
    except Exception as e:
        raise IntegrationError(f"Failed to search user activity for {username}: {str(e)}") from e


def pivot_on_indicator(
    indicator: str,
    limit: int = 200,
    client: SIEMClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Pivot on an indicator of compromise (IOC).

    Tool schema:
    - name: pivot_on_indicator
    - description: Given an IOC (file hash, IP address, domain, etc.),
      search for all related security events across environments for
      further investigation.
    - parameters:
      - indicator (str, required): The IOC (hash, IP, domain, etc.).
      - limit (int, optional): Maximum number of events to return (default: 200).

    Args:
        indicator: The IOC value.
        limit: Maximum number of events.
        client: The SIEM client.

    Returns:
        Dictionary containing related events.

    Raises:
        IntegrationError: If pivot search fails.
    """
    if client is None:
        raise IntegrationError("SIEM client not provided")

    try:
        result = client.pivot_on_indicator(indicator=indicator, limit=limit)

        return {
            "success": True,
            "indicator": indicator,
            "query": result.query,
            "total_count": result.total_count,
            "returned_count": len(result.events),
            "events": [
                {
                    "id": event.id,
                    "timestamp": event.timestamp.isoformat(),
                    "source_type": event.source_type.value,
                    "message": event.message,
                    "host": event.host,
                    "username": event.username,
                    "ip": event.ip,
                    "process_name": event.process_name,
                    "file_hash": event.file_hash,
                }
                for event in result.events
            ],
        }
    except Exception as e:
        raise IntegrationError(f"Failed to pivot on indicator {indicator}: {str(e)}") from e


def get_recent_alerts(
    hours_back: int = 1,
    max_alerts: int = 100,
    status_filter: Optional[str] = None,
    severity: Optional[str] = None,
    hostname: Optional[str] = None,
    client: SIEMClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Summarize and smart-group recent alerts from the SIEM.

    Tool schema:
    - name: get_recent_alerts
    - description: Get recent SIEM alerts (last N hours) and group similar
      alerts together to help the AI decide what to investigate first.
      **CRITICAL: Automatically excludes alerts that have already been investigated**
      (alerts with signal.ai.verdict field) to prevent duplicate work. SOC1 should
      never re-investigate alerts that have already been triaged.
    - parameters:
      - hours_back (int, optional): How many hours to look back (default: 1)
      - max_alerts (int, optional): Maximum number of alerts to retrieve (default: 100)
      - status_filter (str, optional): Filter by status (implementation-specific)
      - severity (str, optional): Filter by severity (low, medium, high, critical)
      - hostname (str, optional): Filter alerts by hostname (matches host.name field)

    **Important:** This tool automatically filters out alerts that have a `verdict` field
    (signal.ai.verdict in Elasticsearch). Alerts with verdicts have already been investigated
    and should not be re-triaged by SOC1. This prevents duplicate work and ensures SOC1 only
    processes new, uninvestigated alerts.

    The tool groups alerts by a composite of title, severity, status, rule ID,
    and alert type/category. For each group it returns:
      - a stable group_id
      - title and primary_severity
      - count of alerts in the group
      - list of alert_ids in the group
      - statuses and severities seen in the group
      - earliest_created_at and latest_created_at
      - up to 3 example_alerts with key fields (id, title, severity, status, timestamps).
    """
    if client is None:
        raise IntegrationError("SIEM client not provided")

    if not hasattr(client, "get_security_alerts"):
        raise IntegrationError("SIEM client does not support get_security_alerts")

    try:
        alerts = client.get_security_alerts(
            hours_back=hours_back,
            max_alerts=max_alerts,
            status_filter=status_filter,
            severity=severity,
            hostname=hostname,
        )
    except Exception as e:
        raise IntegrationError(f"Failed to get recent alerts: {str(e)}") from e

    if not isinstance(alerts, list):
        raise IntegrationError(
            "SIEM client get_security_alerts returned unexpected type "
            f"{type(alerts).__name__}, expected list"
        )

    def _severity_rank(value: Optional[str]) -> int:
        mapping = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        if value is None:
            return 0
        return mapping.get(str(value).lower(), 0)

    # First, filter out investigated alerts and limit to max_alerts uninvestigated alerts.
    # While doing this, also track the single oldest uninvestigated alert so we can
    # expose it as a suggested starting point for triage.
    uninvestigated_alerts = []
    suggested_alert = None
    suggested_alert_created_at = None

    for alert in alerts:
        if not isinstance(alert, dict):
            continue

        # CRITICAL: Skip alerts that have already been investigated (have verdict field)
        # The verdict field comes from signal.ai.verdict in Elasticsearch and indicates the alert has already been triaged
        # SOC1 should never re-investigate alerts that have already been processed
        # Check both direct verdict field and signal.ai.verdict path for compatibility
        verdict = alert.get("verdict") or alert.get("signal", {}).get("ai", {}).get("verdict")
        if verdict:
            continue  # Skip this alert - it has already been investigated (has signal.ai.verdict)

        # Limit to max_alerts uninvestigated alerts
        if len(uninvestigated_alerts) >= max_alerts:
            break

        uninvestigated_alerts.append(alert)

        # Track the oldest uninvestigated alert based on created_at / @timestamp
        created_at_value = alert.get("created_at") or alert.get("@timestamp")
        if created_at_value is not None and (
            suggested_alert_created_at is None or created_at_value < suggested_alert_created_at
        ):
            suggested_alert = alert
            suggested_alert_created_at = created_at_value

    # If no uninvestigated alerts, return early with a clear message
    if not uninvestigated_alerts:
        return {
            "success": True,
            "hours_back": hours_back,
            "max_alerts": max_alerts,
            "status_filter": status_filter,
            "severity": severity,
            "hostname": hostname,
            "total_alerts": len(alerts),
            "uninvestigated_alerts": 0,
            "group_count": 0,
            "groups": [],
            "message": "No recent security alerts to investigate. All alerts in the specified timeframe have already been investigated (have verdict field).",
            "suggested_alert_to_triage": None,
        }

    groups: Dict[str, Dict[str, Any]] = {}

    for alert in uninvestigated_alerts:
        alert_id = alert.get("id")
        
        # Skip alerts without a title or name
        title = alert.get("title") or alert.get("name")
        if not title or not title.strip():
            continue
        
        severity_value = (alert.get("severity") or "unknown").lower()
        status_value = (alert.get("status") or "unknown").lower()

        rule_id = alert.get("rule_id") or alert.get("detection_rule_id")
        rule = alert.get("rule")
        if isinstance(rule, dict):
            rule_id = rule_id or rule.get("id")

        alert_type = (
            alert.get("type")
            or alert.get("category")
            or (rule.get("name") if isinstance(rule, dict) else None)
        )

        key_parts = [
            title.strip().lower(),
            severity_value,
            status_value,
        ]
        if rule_id:
            key_parts.append(f"rule:{rule_id}")
        if alert_type:
            key_parts.append(f"type:{str(alert_type).lower()}")

        group_key = "|".join(key_parts)
        group = groups.get(group_key)
        if group is None:
            group = {
                "group_key": group_key,
                "title": title,
                "primary_severity": severity_value,
                "primary_status": status_value,
                "rule_id": rule_id,
                "alert_type": alert_type,
                "count": 0,
                "alert_ids": [],
                "statuses": set(),
                "severities": set(),
                "earliest_created_at": None,
                "latest_created_at": None,
                "example_alerts": [],
            }
            groups[group_key] = group

        group["count"] += 1
        if alert_id is not None:
            group["alert_ids"].append(alert_id)

        group["statuses"].add(status_value)
        group["severities"].add(severity_value)

        created_at = alert.get("created_at") or alert.get("@timestamp")
        if created_at is not None:
            earliest = group["earliest_created_at"]
            latest = group["latest_created_at"]
            if earliest is None or created_at < earliest:
                group["earliest_created_at"] = created_at
            if latest is None or created_at > latest:
                group["latest_created_at"] = created_at

        if _severity_rank(severity_value) > _severity_rank(group.get("primary_severity")):
            group["primary_severity"] = severity_value

        examples = group["example_alerts"]
        if len(examples) < 3:
            examples.append(
                {
                    "id": alert_id,
                    "title": title,
                    "severity": severity_value,
                    "status": status_value,
                    "created_at": created_at,
                    "source": alert.get("source"),
                    "rule_id": rule_id,
                    "type": alert_type,
                    "description": alert.get("description"),
                }
            )

    grouped_list = []
    for idx, group in enumerate(groups.values(), start=1):
        # Sort example_alerts within each group from oldest to most recent
        example_alerts_sorted = sorted(
            group["example_alerts"],
            key=lambda a: a.get("created_at") or "",
        )

        grouped_list.append(
            {
                "group_id": f"alert_group_{idx}",
                "title": group["title"],
                "primary_severity": group["primary_severity"],
                "primary_status": group["primary_status"],
                "rule_id": group["rule_id"],
                "alert_type": group["alert_type"],
                "count": group["count"],
                "alert_ids": group["alert_ids"],
                "statuses": sorted(s for s in group["statuses"] if s),
                "severities": sorted(s for s in group["severities"] if s),
                "earliest_created_at": group["earliest_created_at"],
                "latest_created_at": group["latest_created_at"],
                "example_alerts": example_alerts_sorted,
            }
        )

    # Sort groups from oldest to most recent based on their earliest_created_at.
    # If timestamps are missing, they will naturally fall to the start of the list.
    grouped_list.sort(
        key=lambda g: g.get("earliest_created_at") or "",
    )

    # Build a compact "suggested alert to triage" view based on the oldest uninvestigated alert
    suggested_alert_view = None
    if suggested_alert is not None:
        suggested_title = suggested_alert.get("title") or suggested_alert.get("name")
        suggested_severity = (suggested_alert.get("severity") or "unknown").lower()
        suggested_status = (suggested_alert.get("status") or "unknown").lower()
        suggested_rule_id = (
            suggested_alert.get("rule_id")
            or suggested_alert.get("detection_rule_id")
        )
        suggested_alert_view = {
            "id": suggested_alert.get("id"),
            "title": suggested_title,
            "severity": suggested_severity,
            "status": suggested_status,
            "created_at": suggested_alert_created_at,
            "rule_id": suggested_rule_id,
            "source": suggested_alert.get("source"),
            "type": suggested_alert.get("type")
            or suggested_alert.get("category"),
            "description": suggested_alert.get("description"),
        }

    return {
        "success": True,
        "hours_back": hours_back,
        "max_alerts": max_alerts,
        "status_filter": status_filter,
        "severity": severity,
        "hostname": hostname,
        "total_alerts": len(alerts),
        "uninvestigated_alerts": len(uninvestigated_alerts),
        "group_count": len(grouped_list),
        "groups": grouped_list,
        "suggested_alert_to_triage": suggested_alert_view,
    }


def get_security_alerts(
    hours_back: int = 24,
    max_alerts: int = 10,
    status_filter: Optional[str] = None,
    severity: Optional[str] = None,
    client: SIEMClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Get security alerts from the SIEM platform.
    
    Tool schema:
    - name: get_security_alerts
    - description: Get security alerts directly from the SIEM platform
    - parameters:
      - hours_back (int, optional): How many hours to look back (default: 24)
      - max_alerts (int, optional): Maximum number of alerts to return (default: 10)
      - status_filter (str, optional): Filter by status
      - severity (str, optional): Filter by severity (low, medium, high, critical)
    """
    if client is None:
        raise IntegrationError("SIEM client not provided")
    
    # Check if client has this method
    if not hasattr(client, "get_security_alerts"):
        raise IntegrationError("SIEM client does not support get_security_alerts")
    
    try:
        alerts = client.get_security_alerts(
            hours_back=hours_back,
            max_alerts=max_alerts,
            status_filter=status_filter,
            severity=severity,
        )
        
        return {
            "success": True,
            "count": len(alerts),
            "alerts": alerts,
        }
    except Exception as e:
        raise IntegrationError(f"Failed to get security alerts: {str(e)}") from e


def get_security_alert_by_id(
    alert_id: str,
    include_detections: bool = True,
    client: SIEMClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Get detailed information about a specific security alert.
    
    Tool schema:
    - name: get_security_alert_by_id
    - description: Get detailed information about a specific security alert by its ID
    - parameters:
      - alert_id (str, required): The ID of the alert
      - include_detections (bool, optional): Whether to include detection details (default: true)
    """
    if client is None:
        raise IntegrationError("SIEM client not provided")
    
    if not hasattr(client, "get_security_alert_by_id"):
        raise IntegrationError("SIEM client does not support get_security_alert_by_id")
    
    try:
        alert = client.get_security_alert_by_id(
            alert_id=alert_id,
            include_detections=include_detections,
        )
        
        return {
            "success": True,
            "alert": alert,
        }
    except Exception as e:
        raise IntegrationError(f"Failed to get security alert: {str(e)}") from e


def get_siem_event_by_id(
    event_id: str,
    client: SIEMClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Get detailed information about a specific security event by its ID.
    
    Tool schema:
    - name: get_siem_event_by_id
    - description: Retrieve a specific security event by its unique identifier (event ID).
      This tool allows you to get the exact event details when you know the event ID.
    - parameters:
      - event_id (str, required): The unique identifier of the event to retrieve
    """
    if client is None:
        raise IntegrationError("SIEM client not provided")
    
    if not hasattr(client, "get_siem_event_by_id"):
        raise IntegrationError("SIEM client does not support get_siem_event_by_id")
    
    try:
        event = client.get_siem_event_by_id(event_id=event_id)
        
        return {
            "success": True,
            "event": {
                "id": event.id,
                "timestamp": event.timestamp.isoformat(),
                "source_type": event.source_type.value,
                "message": event.message,
                "host": event.host,
                "username": event.username,
                "ip": event.ip,
                "process_name": event.process_name,
                "file_hash": event.file_hash,
                "raw": event.raw,
            },
        }
    except Exception as e:
        raise IntegrationError(f"Failed to get event by ID: {str(e)}") from e


def lookup_entity(
    entity_value: str,
    entity_type: Optional[str] = None,
    hours_back: int = 24,
    client: SIEMClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Look up an entity for enrichment.
    
    Tool schema:
    - name: lookup_entity
    - description: Look up an entity (IP address, domain, hash, user, etc.) in the SIEM for enrichment
    - parameters:
      - entity_value (str, required): Value to look up
      - entity_type (str, optional): Type of entity (ip, domain, hash, user, etc.)
      - hours_back (int, optional): How many hours of historical data (default: 24)
    """
    if client is None:
        raise IntegrationError("SIEM client not provided")
    
    if not hasattr(client, "lookup_entity"):
        raise IntegrationError("SIEM client does not support lookup_entity")
    
    try:
        result = client.lookup_entity(
            entity_value=entity_value,
            entity_type=entity_type,
            hours_back=hours_back,
        )
        
        return {
            "success": True,
            **result,
        }
    except Exception as e:
        raise IntegrationError(f"Failed to lookup entity: {str(e)}") from e


def get_ioc_matches(
    hours_back: int = 24,
    max_matches: int = 20,
    ioc_type: Optional[str] = None,
    severity: Optional[str] = None,
    client: SIEMClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Get Indicators of Compromise (IoC) matches.
    
    Tool schema:
    - name: get_ioc_matches
    - description: Get Indicators of Compromise (IoC) matches from the SIEM
    - parameters:
      - hours_back (int, optional): How many hours back to look (default: 24)
      - max_matches (int, optional): Maximum number of matches (default: 20)
      - ioc_type (str, optional): Filter by IoC type (ip, domain, hash, url, etc.)
      - severity (str, optional): Filter by severity level
    """
    if client is None:
        raise IntegrationError("SIEM client not provided")
    
    if not hasattr(client, "get_ioc_matches"):
        raise IntegrationError("SIEM client does not support get_ioc_matches")
    
    try:
        matches = client.get_ioc_matches(
            hours_back=hours_back,
            max_matches=max_matches,
            ioc_type=ioc_type,
            severity=severity,
        )
        
        return {
            "success": True,
            "count": len(matches),
            "matches": matches,
        }
    except Exception as e:
        raise IntegrationError(f"Failed to get IoC matches: {str(e)}") from e


def get_threat_intel(
    query: str,
    context: Optional[Dict[str, Any]] = None,
    client: SIEMClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Get threat intelligence answers.
    
    Tool schema:
    - name: get_threat_intel
    - description: Get answers to security questions using integrated threat intelligence
    - parameters:
      - query (str, required): The security or threat intelligence question
      - context (object, optional): Additional context (indicators, events, etc.)
    """
    if client is None:
        raise IntegrationError("SIEM client not provided")
    
    if not hasattr(client, "get_threat_intel"):
        raise IntegrationError("SIEM client does not support get_threat_intel")
    
    try:
        result = client.get_threat_intel(
            query=query,
            context=context,
        )
        
        return {
            "success": True,
            **result,
        }
    except Exception as e:
        raise IntegrationError(f"Failed to get threat intelligence: {str(e)}") from e


def list_security_rules(
    enabled_only: bool = False,
    limit: int = 100,
    client: SIEMClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    List security detection rules.
    
    Tool schema:
    - name: list_security_rules
    - description: List all security detection rules configured in the SIEM platform
    - parameters:
      - enabled_only (bool, optional): Only return enabled rules (default: false)
      - limit (int, optional): Maximum number of rules (default: 100)
    """
    if client is None:
        raise IntegrationError("SIEM client not provided")
    
    if not hasattr(client, "list_security_rules"):
        raise IntegrationError("SIEM client does not support list_security_rules")
    
    try:
        rules = client.list_security_rules(
            enabled_only=enabled_only,
            limit=limit,
        )
        
        return {
            "success": True,
            "count": len(rules),
            "rules": rules,
        }
    except Exception as e:
        raise IntegrationError(f"Failed to list security rules: {str(e)}") from e


def search_security_rules(
    query: str,
    category: Optional[str] = None,
    enabled_only: bool = False,
    client: SIEMClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Search for security detection rules.
    
    Tool schema:
    - name: search_security_rules
    - description: Search for security detection rules by name, description, or other criteria
    - parameters:
      - query (str, required): Search query (supports regex patterns)
      - category (str, optional): Filter by rule category
      - enabled_only (bool, optional): Only search enabled rules (default: false)
    """
    if client is None:
        raise IntegrationError("SIEM client not provided")
    
    if not hasattr(client, "search_security_rules"):
        raise IntegrationError("SIEM client does not support search_security_rules")
    
    try:
        rules = client.search_security_rules(
            query=query,
            category=category,
            enabled_only=enabled_only,
        )
        
        return {
            "success": True,
            "count": len(rules),
            "rules": rules,
        }
    except Exception as e:
        raise IntegrationError(f"Failed to search security rules: {str(e)}") from e


def get_rule_detections(
    rule_id: str,
    alert_state: Optional[str] = None,
    hours_back: int = 24,
    limit: int = 50,
    client: SIEMClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Get historical detections from a specific rule.
    
    Tool schema:
    - name: get_rule_detections
    - description: Retrieve historical detections generated by a specific security detection rule
    - parameters:
      - rule_id (str, required): Unique ID of the rule
      - alert_state (str, optional): Filter by alert state
      - hours_back (int, optional): How many hours back (default: 24)
      - limit (int, optional): Maximum number of detections (default: 50)
    """
    if client is None:
        raise IntegrationError("SIEM client not provided")
    
    if not hasattr(client, "get_rule_detections"):
        raise IntegrationError("SIEM client does not support get_rule_detections")
    
    try:
        detections = client.get_rule_detections(
            rule_id=rule_id,
            alert_state=alert_state,
            hours_back=hours_back,
            limit=limit,
        )
        
        return {
            "success": True,
            "rule_id": rule_id,
            "count": len(detections),
            "detections": detections,
        }
    except Exception as e:
        raise IntegrationError(f"Failed to get rule detections: {str(e)}") from e


def list_rule_errors(
    rule_id: str,
    hours_back: int = 24,
    client: SIEMClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    List execution errors for a specific rule.
    
    Tool schema:
    - name: list_rule_errors
    - description: List execution errors for a specific security detection rule
    - parameters:
      - rule_id (str, required): Unique ID of the rule
      - hours_back (int, optional): How many hours back to look (default: 24)
    """
    if client is None:
        raise IntegrationError("SIEM client not provided")
    
    if not hasattr(client, "list_rule_errors"):
        raise IntegrationError("SIEM client does not support list_rule_errors")
    
    try:
        errors = client.list_rule_errors(
            rule_id=rule_id,
            hours_back=hours_back,
        )
        
        return {
            "success": True,
            "rule_id": rule_id,
            "error_count": len(errors),
            "errors": errors,
        }
    except Exception as e:
        raise IntegrationError(f"Failed to list rule errors: {str(e)}") from e


def close_alert(
    alert_id: str,
    reason: Optional[str] = None,
    comment: Optional[str] = None,
    client: SIEMClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Close an alert in the SIEM, typically used for false positives.
    
    Tool schema:
    - name: close_alert
    - description: Close a security alert in the SIEM platform. Use this when an alert
      has been determined to be a false positive or benign true positive during triage.
    - parameters:
      - alert_id (str, required): The ID of the alert to close
      - reason (str, optional): Reason for closing (e.g., "false_positive", "benign_true_positive")
      - comment (str, optional): Comment explaining why the alert is being closed
    
    Args:
        alert_id: The ID of the alert to close.
        reason: Optional reason for closing.
        comment: Optional comment explaining why the alert is being closed.
        client: The SIEM client.
    
    Returns:
        Dictionary containing success status and alert details.
    
    Raises:
        IntegrationError: If closing the alert fails.
    """
    if client is None:
        raise IntegrationError("SIEM client not provided")
    
    if not hasattr(client, "close_alert"):
        raise IntegrationError("SIEM client does not support close_alert")
    
    try:
        result = client.close_alert(
            alert_id=alert_id,
            reason=reason,
            comment=comment,
        )
        
        return {
            "success": True,
            "alert_id": result.get("alert_id"),
            "status": result.get("status"),
            "reason": result.get("reason"),
            "comment": result.get("comment"),
            "alert": result.get("alert"),
        }
    except Exception as e:
        raise IntegrationError(f"Failed to close alert {alert_id}: {str(e)}") from e


def update_alert_verdict(
    alert_id: str,
    verdict: str,
    comment: Optional[str] = None,
    client: SIEMClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Update the verdict for an alert in the SIEM.
    
    Tool schema:
    - name: update_alert_verdict
    - description: Update the verdict for a security alert. Use this to set or update the verdict
      field (e.g., "in-progress", "false_positive", "benign_true_positive", "true_positive", "uncertain").
      This is the preferred method for setting verdicts as it clearly indicates the intent to
      update the verdict rather than close the alert.
    - parameters:
      - alert_id (str, required): The ID of the alert to update
      - verdict (str, required): The verdict value. Valid values: "in-progress", "false_positive",
        "benign_true_positive", "true_positive", "uncertain"
      - comment (str, optional): Optional comment explaining the verdict
    
    Args:
        alert_id: The ID of the alert to update.
        verdict: The verdict value to set. Valid values: "in-progress", "false_positive",
            "benign_true_positive", "true_positive", "uncertain".
        comment: Optional comment explaining the verdict.
        client: The SIEM client.
    
    Returns:
        Dictionary containing success status, alert_id, verdict, and updated alert details.
    
    Raises:
        IntegrationError: If updating the verdict fails.
    """
    if client is None:
        raise IntegrationError("SIEM client not provided")
    
    if not hasattr(client, "update_alert_verdict"):
        raise IntegrationError("SIEM client does not support update_alert_verdict")
    
    try:
        result = client.update_alert_verdict(
            alert_id=alert_id,
            verdict=verdict,
            comment=comment,
        )
        
        return {
            "success": True,
            "alert_id": result.get("alert_id"),
            "verdict": result.get("verdict"),
            "comment": result.get("comment"),
            "alert": result.get("alert"),
        }
    except Exception as e:
        raise IntegrationError(f"Failed to update alert verdict for {alert_id}: {str(e)}") from e


def tag_alert(
    alert_id: str,
    tag: str,
    client: SIEMClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Tag an alert with a classification tag (FP, TP, or NMI).
    
    Tool schema:
    - name: tag_alert
    - description: Tag a security alert in the SIEM platform with a classification.
      Use this to mark alerts as FP (False Positive), TP (True Positive), or NMI (Need More Investigation).
    - parameters:
      - alert_id (str, required): The ID of the alert to tag
      - tag (str, required): The tag to apply. Must be one of: "FP" (False Positive), 
        "TP" (True Positive), or "NMI" (Need More Investigation)
    
    Args:
        alert_id: The ID of the alert to tag.
        tag: The tag to apply. Must be one of: "FP", "TP", or "NMI".
        client: The SIEM client.
    
    Returns:
        Dictionary containing success status and alert details with updated tags.
    
    Raises:
        IntegrationError: If tagging the alert fails.
    """
    # Validate tag value first before checking client
    valid_tags = {"FP", "TP", "NMI"}
    tag_upper = tag.upper()
    if tag_upper not in valid_tags:
        raise IntegrationError(
            f"Invalid tag '{tag}'. Must be one of: FP (False Positive), "
            f"TP (True Positive), or NMI (Need More Investigation)"
        )
    
    if client is None:
        raise IntegrationError("SIEM client not provided")
    
    if not hasattr(client, "tag_alert"):
        raise IntegrationError("SIEM client does not support tag_alert")
    
    try:
        result = client.tag_alert(
            alert_id=alert_id,
            tag=tag_upper,
        )
        
        return {
            "success": True,
            "alert_id": result.get("alert_id"),
            "tag": result.get("tag"),
            "tags": result.get("tags", []),
            "alert": result.get("alert"),
        }
    except Exception as e:
        raise IntegrationError(f"Failed to tag alert {alert_id}: {str(e)}") from e


def add_alert_note(
    alert_id: str,
    note: str,
    client: SIEMClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Add a note/comment to an alert in the SIEM.
    
    Tool schema:
    - name: add_alert_note
    - description: Add a note or comment to a security alert in the SIEM platform.
      Use this to document investigation findings, recommendations for detection rule improvements,
      case numbers, or other relevant information about the alert.
    - parameters:
      - alert_id (str, required): The ID of the alert to add a note to
      - note (str, required): The note/comment text to add
    
    Args:
        alert_id: The ID of the alert to add a note to.
        note: The note/comment text to add.
        client: The SIEM client.
    
    Returns:
        Dictionary containing success status and alert details with the note.
    
    Raises:
        IntegrationError: If adding the note fails.
    """
    if client is None:
        raise IntegrationError("SIEM client not provided")
    
    if not hasattr(client, "add_alert_note"):
        raise IntegrationError("SIEM client does not support add_alert_note")
    
    try:
        result = client.add_alert_note(
            alert_id=alert_id,
            note=note,
        )
        
        return {
            "success": True,
            "alert_id": result.get("alert_id"),
            "note": result.get("note"),
            "alert": result.get("alert"),
        }
    except Exception as e:
        raise IntegrationError(f"Failed to add note to alert {alert_id}: {str(e)}") from e


def search_kql_query(
    kql_query: str,
    limit: int = 500,
    hours_back: Optional[int] = None,
    client: SIEMClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Execute a KQL (Kusto Query Language) or advanced query for deeper investigations.
    
    Tool schema:
    - name: search_kql_query
    - description: Execute a KQL (Kusto Query Language) or advanced query for deeper investigations.
      This tool allows for complex queries including advanced filtering, aggregations, time-based
      analysis, cross-index searches, and complex joins. Supports both KQL syntax and vendor-specific
      query DSL (e.g., Elasticsearch Query DSL).
    - parameters:
      - kql_query (str, required): KQL query string or advanced query DSL (JSON for Elasticsearch)
      - limit (int, optional): Maximum number of events to return (default: 500)
      - hours_back (int, optional): Optional time window in hours to limit the search
    
    Args:
        kql_query: KQL query string or advanced query DSL.
        limit: Maximum number of events to return.
        hours_back: Optional time window in hours.
        client: The SIEM client.
    
    Returns:
        Dictionary containing search results with events.
    
    Raises:
        IntegrationError: If search fails.
    """
    if client is None:
        raise IntegrationError("SIEM client not provided")
    
    if not hasattr(client, "search_kql_query"):
        raise IntegrationError("SIEM client does not support search_kql_query")
    
    try:
        result = client.search_kql_query(
            kql_query=kql_query,
            limit=limit,
            hours_back=hours_back,
        )
        
        return {
            "success": True,
            "query": result.query,
            "total_count": result.total_count,
            "returned_count": len(result.events),
            "events": [
                {
                    "id": event.id,
                    "timestamp": event.timestamp.isoformat(),
                    "source_type": event.source_type.value,
                    "message": event.message,
                    "host": event.host,
                    "username": event.username,
                    "ip": event.ip,
                    "process_name": event.process_name,
                    "file_hash": event.file_hash,
                }
                for event in result.events
            ],
        }
    except Exception as e:
        raise IntegrationError(f"Failed to execute KQL query: {str(e)}") from e


def get_network_events(
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    port: Optional[int] = None,
    protocol: Optional[str] = None,
    hours_back: int = 24,
    limit: int = 100,
    event_type: Optional[str] = None,
    client: SIEMClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Retrieve network traffic events (firewall, netflow, proxy logs) with structured fields.
    
    Tool schema:
    - name: get_network_events
    - description: Retrieve network traffic events (firewall, netflow, proxy logs) with structured
      fields for analysis. Returns network events with source/destination IPs, ports, protocols,
      bytes, packets, and connection duration.
    - parameters:
      - source_ip (str, optional): Source IP address
      - destination_ip (str, optional): Destination IP address
      - port (int, optional): Port number
      - protocol (str, optional): Protocol (tcp, udp, icmp, etc.)
      - hours_back (int, optional): Time window (default: 24)
      - limit (int, optional): Max results (default: 100)
      - event_type (str, optional): Filter by event type ("firewall", "netflow", "proxy", "all")
    
    Args:
        source_ip: Source IP address.
        destination_ip: Destination IP address.
        port: Port number.
        protocol: Protocol (tcp, udp, icmp, etc.).
        hours_back: Time window in hours.
        limit: Maximum number of events to return.
        event_type: Filter by event type.
        client: The SIEM client.
    
    Returns:
        Dictionary containing network events with structured fields.
    
    Raises:
        IntegrationError: If retrieval fails.
    """
    if client is None:
        raise IntegrationError("SIEM client not provided")
    
    if not hasattr(client, "get_network_events"):
        raise IntegrationError("SIEM client does not support get_network_events")
    
    try:
        result = client.get_network_events(
            source_ip=source_ip,
            destination_ip=destination_ip,
            port=port,
            protocol=protocol,
            hours_back=hours_back,
            limit=limit,
            event_type=event_type,
        )
        
        # Result is a dictionary with events array
        events = result.get("events", [])
        return {
            "success": True,
            "total_count": result.get("total_count", len(events)),
            "returned_count": len(events),
            "events": events,
        }
    except Exception as e:
        raise IntegrationError(f"Failed to get network events: {str(e)}") from e


def get_dns_events(
    domain: Optional[str] = None,
    ip_address: Optional[str] = None,
    resolved_ip: Optional[str] = None,
    query_type: Optional[str] = None,
    hours_back: int = 24,
    limit: int = 100,
    client: SIEMClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Retrieve DNS query and response events with structured fields.
    
    Tool schema:
    - name: get_dns_events
    - description: Retrieve DNS query and response events with structured fields for analysis.
      Returns DNS events with domain, query type, resolved IP, source IP, and response codes.
    - parameters:
      - domain (str, optional): Domain name queried
      - ip_address (str, optional): IP that made the query
      - resolved_ip (str, optional): Resolved IP address
      - query_type (str, optional): DNS query type (A, AAAA, MX, TXT, etc.)
      - hours_back (int, optional): Time window (default: 24)
      - limit (int, optional): Max results (default: 100)
    
    Args:
        domain: Domain name queried.
        ip_address: IP that made the query.
        resolved_ip: Resolved IP address.
        query_type: DNS query type (A, AAAA, MX, TXT, etc.).
        hours_back: Time window in hours.
        limit: Maximum number of events to return.
        client: The SIEM client.
    
    Returns:
        Dictionary containing DNS events with structured fields.
    
    Raises:
        IntegrationError: If retrieval fails.
    """
    if client is None:
        raise IntegrationError("SIEM client not provided")
    
    if not hasattr(client, "get_dns_events"):
        raise IntegrationError("SIEM client does not support get_dns_events")
    
    try:
        result = client.get_dns_events(
            domain=domain,
            ip_address=ip_address,
            resolved_ip=resolved_ip,
            query_type=query_type,
            hours_back=hours_back,
            limit=limit,
        )
        
        # Result is a dictionary with events array
        events = result.get("events", [])
        return {
            "success": True,
            "total_count": result.get("total_count", len(events)),
            "returned_count": len(events),
            "events": events,
        }
    except Exception as e:
        raise IntegrationError(f"Failed to get DNS events: {str(e)}") from e


def get_alerts_by_entity(
    entity_value: str,
    entity_type: Optional[str] = None,
    hours_back: int = 24,
    limit: int = 50,
    severity: Optional[str] = None,
    client: SIEMClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Retrieve alerts filtered by specific entity (IP, user, host, domain, hash) for correlation analysis.
    
    Tool schema:
    - name: get_alerts_by_entity
    - description: Retrieve alerts filtered by specific entity (IP, user, host, domain, hash) for
      correlation analysis. Returns alerts that contain the specified entity.
    - parameters:
      - entity_value (str, required): Entity value (IP, user, hostname, domain, hash)
      - entity_type (str, optional): Entity type (auto-detected if not provided: "ip", "user", "host", "domain", "hash")
      - hours_back (int, optional): Lookback period (default: 24)
      - limit (int, optional): Max results (default: 50)
      - severity (str, optional): Filter by severity ("low", "medium", "high", "critical")
    
    Args:
        entity_value: Entity value (IP, user, hostname, domain, hash).
        entity_type: Entity type (auto-detected if not provided).
        hours_back: Lookback period in hours.
        limit: Maximum number of alerts to return.
        severity: Filter by severity level.
        client: The SIEM client.
    
    Returns:
        Dictionary containing alerts related to the entity.
    
    Raises:
        IntegrationError: If retrieval fails.
    """
    if client is None:
        raise IntegrationError("SIEM client not provided")
    
    if not hasattr(client, "get_alerts_by_entity"):
        raise IntegrationError("SIEM client does not support get_alerts_by_entity")
    
    try:
        result = client.get_alerts_by_entity(
            entity_value=entity_value,
            entity_type=entity_type,
            hours_back=hours_back,
            limit=limit,
            severity=severity,
        )
        
        return {
            "success": True,
            "entity_value": result.get("entity_value"),
            "entity_type": result.get("entity_type"),
            "total_count": result.get("total_count", 0),
            "returned_count": result.get("returned_count", 0),
            "alerts": result.get("alerts", []),
        }
    except Exception as e:
        raise IntegrationError(f"Failed to get alerts by entity: {str(e)}") from e


def get_all_uncertain_alerts_for_host(
    hostname: str,
    hours_back: int = 7 * 24,  # Default 7 days
    limit: int = 100,
    client: SIEMClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Retrieve all alerts with verdict="uncertain" for a specific host.
    
    Tool schema:
    - name: get_all_uncertain_alerts_for_host
    - description: Retrieve all alerts with verdict="uncertain" for a specific host.
      This is useful for pattern analysis when investigating uncertain alerts to determine
      if multiple uncertain alerts on the same host indicate a broader issue requiring
      case creation and escalation.
    - parameters:
      - hostname (str, required): The hostname to search for
      - hours_back (int, optional): How many hours to look back (default: 168 = 7 days)
      - limit (int, optional): Maximum number of alerts to return (default: 100)
    
    Args:
        hostname: The hostname to search for.
        hours_back: How many hours to look back (default: 168 = 7 days).
        limit: Maximum number of alerts to return.
        client: The SIEM client.
    
    Returns:
        Dictionary containing uncertain alerts for the host.
    
    Raises:
        IntegrationError: If retrieval fails.
    """
    if client is None:
        raise IntegrationError("SIEM client not provided")
    
    if not hasattr(client, "get_all_uncertain_alerts_for_host"):
        raise IntegrationError("SIEM client does not support get_all_uncertain_alerts_for_host")
    
    try:
        result = client.get_all_uncertain_alerts_for_host(
            hostname=hostname,
            hours_back=hours_back,
            limit=limit,
        )
        
        return {
            "success": True,
            "hostname": result.get("hostname"),
            "hours_back": result.get("hours_back"),
            "total_count": result.get("total_count", 0),
            "returned_count": result.get("returned_count", 0),
            "alerts": result.get("alerts", []),
        }
    except Exception as e:
        raise IntegrationError(f"Failed to get uncertain alerts for host: {str(e)}") from e


def get_alerts_by_time_window(
    start_time: str,
    end_time: str,
    limit: int = 100,
    severity: Optional[str] = None,
    alert_type: Optional[str] = None,
    client: SIEMClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Retrieve alerts within a specific time window for temporal correlation.
    
    Tool schema:
    - name: get_alerts_by_time_window
    - description: Retrieve alerts within a specific time window for temporal correlation.
      Returns alerts that occurred between start_time and end_time.
    - parameters:
      - start_time (str, required): Start time (ISO format)
      - end_time (str, required): End time (ISO format)
      - limit (int, optional): Max results (default: 100)
      - severity (str, optional): Filter by severity
      - alert_type (str, optional): Filter by alert type
    
    Args:
        start_time: Start time in ISO format.
        end_time: End time in ISO format.
        limit: Maximum number of alerts to return.
        severity: Filter by severity level.
        alert_type: Filter by alert type.
        client: The SIEM client.
    
    Returns:
        Dictionary containing alerts in the time window.
    
    Raises:
        IntegrationError: If retrieval fails.
    """
    if client is None:
        raise IntegrationError("SIEM client not provided")
    
    if not hasattr(client, "get_alerts_by_time_window"):
        raise IntegrationError("SIEM client does not support get_alerts_by_time_window")
    
    try:
        result = client.get_alerts_by_time_window(
            start_time=start_time,
            end_time=end_time,
            limit=limit,
            severity=severity,
            alert_type=alert_type,
        )
        
        return {
            "success": True,
            "total_count": result.get("total_count", 0),
            "returned_count": result.get("returned_count", 0),
            "alerts": result.get("alerts", []),
        }
    except Exception as e:
        raise IntegrationError(f"Failed to get alerts by time window: {str(e)}") from e


def get_email_events(
    sender_email: Optional[str] = None,
    recipient_email: Optional[str] = None,
    subject: Optional[str] = None,
    email_id: Optional[str] = None,
    hours_back: int = 24,
    limit: int = 100,
    event_type: Optional[str] = None,
    client: SIEMClient = None,  # type: ignore
) -> Dict[str, Any]:
    """
    Retrieve email security events with structured fields for phishing analysis.
    
    Tool schema:
    - name: get_email_events
    - description: Retrieve email security events with structured fields for phishing analysis.
      Returns email events with sender, recipient, subject, headers, authentication, URLs, and attachments.
    - parameters:
      - sender_email (str, optional): Sender email address
      - recipient_email (str, optional): Recipient email address
      - subject (str, optional): Email subject (partial match)
      - email_id (str, optional): Email message ID
      - hours_back (int, optional): Time window (default: 24)
      - limit (int, optional): Max results (default: 100)
      - event_type (str, optional): Filter by event type ("delivered", "blocked", "quarantined", "all")
    
    Args:
        sender_email: Sender email address.
        recipient_email: Recipient email address.
        subject: Email subject (partial match).
        email_id: Email message ID.
        hours_back: Time window in hours.
        limit: Maximum number of events to return.
        event_type: Filter by event type.
        client: The SIEM client.
    
    Returns:
        Dictionary containing email events with structured fields.
    
    Raises:
        IntegrationError: If retrieval fails.
    """
    if client is None:
        raise IntegrationError("SIEM client not provided")
    
    if not hasattr(client, "get_email_events"):
        raise IntegrationError("SIEM client does not support get_email_events")
    
    try:
        result = client.get_email_events(
            sender_email=sender_email,
            recipient_email=recipient_email,
            subject=subject,
            email_id=email_id,
            hours_back=hours_back,
            limit=limit,
            event_type=event_type,
        )
        
        return {
            "success": True,
            "total_count": result.get("total_count", 0),
            "returned_count": result.get("returned_count", 0),
            "events": result.get("events", []),
        }
    except Exception as e:
        raise IntegrationError(f"Failed to get email events: {str(e)}") from e


