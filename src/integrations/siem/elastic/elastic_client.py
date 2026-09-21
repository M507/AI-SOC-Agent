"""
Elasticsearch/Elastic SIEM implementation of the generic ``SIEMClient`` interface.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

from ....api.siem import (
    FileBehaviorSummary,
    FileReport,
    IpAddressReport,
    QueryResult,
    RelatedEntities,
    SIEMClient,
    SiemEvent,
    Severity,
    SourceType,
)
from ....core.config import SamiConfig
from ....core.errors import IntegrationError
from ....core.logging import get_logger
from .elastic_http import ElasticHttpClient


logger = get_logger("sami.integrations.elastic.client")

# Elastic Security workflow statuses (kibana.alert.workflow_status / signal.status).
_ALERT_STATUS_ALIASES = {
    "akn": "acknowledged",
    "ack": "acknowledged",
    "acked": "acknowledged",
    "acknowledge": "acknowledged",
    "in_progress": "in-progress",
    "inprogress": "in-progress",
}

# Statuses that imply historical review — include already-triaged (verdicted) alerts.
_HISTORICAL_STATUSES = frozenset({"closed", "acknowledged"})

_ALERT_INDEX_PATTERNS = [
    "alerts-*,.siem-signals-*,logs-endpoint.alerts-*",
    "alerts-*",
    "_all",
]

_AGENT_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.I,
)


class ElasticSIEMClient:
    """
    SIEM client backed by Elasticsearch/Elastic SIEM.
    
    This implementation uses Elasticsearch query DSL for searching security events.
    """

    def __init__(
        self,
        http_client: ElasticHttpClient,
        kibana_http: Optional[ElasticHttpClient] = None,
    ) -> None:
        self._http = http_client
        self._kibana_http = kibana_http

    @classmethod
    def from_config(cls, config: SamiConfig) -> "ElasticSIEMClient":
        """
        Factory to construct a client from ``SamiConfig``.
        """
        if not config.elastic:
            raise IntegrationError("Elastic configuration is not set in SamiConfig")

        return cls.from_settings(
            base_url=config.elastic.base_url,
            api_key=config.elastic.api_key,
            username=config.elastic.username,
            password=config.elastic.password,
            timeout_seconds=config.elastic.timeout_seconds,
            verify_ssl=config.elastic.verify_ssl,
        )

    @classmethod
    def from_settings(
        cls,
        *,
        base_url: str,
        api_key: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout_seconds: int = 30,
        verify_ssl: bool = True,
        kibana_url: Optional[str] = None,
    ) -> "ElasticSIEMClient":
        """Build a client from explicit cluster credentials."""
        http_client = ElasticHttpClient(
            base_url=base_url,
            api_key=api_key,
            username=username,
            password=password,
            timeout_seconds=timeout_seconds,
            verify_ssl=verify_ssl,
        )
        kibana_http = None
        resolved_kibana = (kibana_url or "").strip().rstrip("/")
        if resolved_kibana and resolved_kibana != base_url.rstrip("/"):
            kibana_http = ElasticHttpClient(
                base_url=resolved_kibana,
                api_key=api_key,
                username=username,
                password=password,
                timeout_seconds=timeout_seconds,
                verify_ssl=verify_ssl,
            )
        return cls(http_client=http_client, kibana_http=kibana_http)

    def search_security_events(
        self,
        query: str,
        limit: int = 100,
    ) -> QueryResult:
        """
        Search security events/logs using Elasticsearch query DSL.
        
        The query can be:
        - A simple text query (will be wrapped in a match query)
        - Full Elasticsearch query DSL JSON
        """
        try:
            # If query looks like JSON, parse it as Elasticsearch DSL
            import json
            try:
                query_dict = json.loads(query)
                if isinstance(query_dict, dict) and "query" in query_dict:
                    es_query = dict(query_dict)
                    if not es_query.get("query"):
                        es_query["query"] = {"match_all": {}}
                elif query_dict == {}:
                    es_query = {"query": {"match_all": {}}}
                else:
                    # Wrap in query DSL
                    es_query = {"query": query_dict}
            except (json.JSONDecodeError, ValueError):
                # Simple text query - use match query
                es_query = {
                    "query": {
                        "query_string": {
                            "query": query
                        }
                    },
                    "size": limit
                }

            # `limit` is part of this method's contract. Apply it to full DSL
            # queries too, both to avoid an implicit Elasticsearch default and
            # to prevent an autorun-provided body from requesting excess data.
            try:
                requested_size = int(es_query.get("size", limit))
            except (TypeError, ValueError):
                requested_size = limit
            es_query["size"] = max(0, min(requested_size, limit))
            
            # Search across common security indices with fallback
            indices_patterns = [
                "logs-*,security-*,winlogbeat-*,filebeat-*",
                "_all",  # Fallback to all indices if specific patterns fail
            ]
            response = self._search_with_fallback(indices_patterns, es_query)
            
            # Parse Elasticsearch response
            hits = response.get("hits", {}).get("hits", [])
            total = response.get("hits", {}).get("total", {})
            if isinstance(total, dict):
                total_count = total.get("value", len(hits))
            else:
                total_count = total
            
            events = []
            for hit in hits[:limit]:
                source = hit.get("_source", {})
                timestamp_str = source.get("@timestamp") or source.get("timestamp")
                timestamp = None
                if timestamp_str:
                    try:
                        timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                    except Exception:
                        pass
                if not timestamp:
                    timestamp = datetime.utcnow()
                
                # Determine source type from index or event fields
                source_type = SourceType.OTHER
                index = hit.get("_index", "")
                if "winlogbeat" in index or "windows" in index.lower():
                    source_type = SourceType.ENDPOINT
                elif "network" in index.lower() or "firewall" in index.lower():
                    source_type = SourceType.NETWORK
                elif "auth" in index.lower() or "login" in index.lower():
                    source_type = SourceType.AUTH
                elif "cloud" in index.lower():
                    source_type = SourceType.CLOUD
                
                event = SiemEvent(
                    id=hit.get("_id", ""),
                    timestamp=timestamp,
                    source_type=source_type,
                    message=source.get("message", source.get("event", {}).get("original", "")),
                    host=source.get("host", {}).get("name") if isinstance(source.get("host"), dict) else source.get("host"),
                    username=source.get("user", {}).get("name") if isinstance(source.get("user"), dict) else source.get("user"),
                    ip=source.get("source", {}).get("ip") if isinstance(source.get("source"), dict) else source.get("source.ip"),
                    process_name=source.get("process", {}).get("name") if isinstance(source.get("process"), dict) else source.get("process.name"),
                    file_hash=source.get("file", {}).get("hash", {}).get("sha256") if isinstance(source.get("file"), dict) else source.get("file.hash.sha256"),
                    raw=source,
                )
                events.append(event)
            
            return QueryResult(
                query=query,
                events=events,
                total_count=total_count,
            )
        except Exception as e:
            logger.exception(f"Error searching Elasticsearch: {e}")
            raise IntegrationError(f"Failed to search security events: {e}") from e

    def get_siem_event_by_id(
        self,
        event_id: str,
    ) -> SiemEvent:
        """
        Retrieve a specific security event by its ID.
        
        Args:
            event_id: The unique identifier of the event to retrieve.
            
        Returns:
            SiemEvent containing the event details.
            
        Raises:
            IntegrationError: If the event is not found or retrieval fails.
        """
        try:
            # Search for the event by _id across all security indices
            # Elasticsearch uses 'ids' query for searching by document IDs
            query = {
                "query": {
                    "ids": {
                        "values": [event_id]
                    }
                },
                "size": 1
            }
            
            # Search across common security indices
            # Search with fallback index patterns
            indices_patterns = [
                "logs-*,security-*,winlogbeat-*,filebeat-*",
                "_all",  # Fallback to all indices if specific patterns fail
            ]
            response = self._search_with_fallback(indices_patterns, query)
            
            hits = response.get("hits", {}).get("hits", [])
            
            if not hits:
                raise IntegrationError(f"Event with ID {event_id} not found")
            
            # Parse the first (and should be only) hit
            hit = hits[0]
            source = hit.get("_source", {})
            timestamp_str = source.get("@timestamp") or source.get("timestamp")
            timestamp = None
            if timestamp_str:
                try:
                    timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                except Exception:
                    pass
            if not timestamp:
                timestamp = datetime.utcnow()
            
            # Determine source type from index or event fields
            source_type = SourceType.OTHER
            index = hit.get("_index", "")
            if "winlogbeat" in index or "windows" in index.lower():
                source_type = SourceType.ENDPOINT
            elif "network" in index.lower() or "firewall" in index.lower():
                source_type = SourceType.NETWORK
            elif "auth" in index.lower() or "login" in index.lower():
                source_type = SourceType.AUTH
            elif "cloud" in index.lower():
                source_type = SourceType.CLOUD
            
            event = SiemEvent(
                id=hit.get("_id", event_id),
                timestamp=timestamp,
                source_type=source_type,
                message=source.get("message", source.get("event", {}).get("original", "")),
                host=source.get("host", {}).get("name") if isinstance(source.get("host"), dict) else source.get("host"),
                username=source.get("user", {}).get("name") if isinstance(source.get("user"), dict) else source.get("user"),
                ip=source.get("source", {}).get("ip") if isinstance(source.get("source"), dict) else source.get("source.ip"),
                process_name=source.get("process", {}).get("name") if isinstance(source.get("process"), dict) else source.get("process.name"),
                file_hash=source.get("file", {}).get("hash", {}).get("sha256") if isinstance(source.get("file"), dict) else source.get("file.hash.sha256"),
                raw=source,
            )
            
            return event
        except IntegrationError:
            raise
        except Exception as e:
            logger.exception(f"Error retrieving event by ID from Elasticsearch: {e}")
            raise IntegrationError(f"Failed to get event by ID {event_id}: {e}") from e

    def _get_events_by_ids(self, event_ids: List[str]) -> List[Dict[str, Any]]:
        """
        Retrieve multiple security events by their IDs from Elasticsearch.
        
        This is used to fetch the ancestor events that triggered an alert.
        
        Args:
            event_ids: List of event IDs to retrieve
            
        Returns:
            List of event dictionaries with normalized structure
        """
        if not event_ids:
            return []
        
        try:
            # Search for events by IDs using ids query
            query = {
                "query": {
                    "ids": {
                        "values": event_ids
                    }
                },
                "size": len(event_ids)
            }
            
            # Search across common security indices
            indices_patterns = [
                "logs-*,security-*,winlogbeat-*,filebeat-*,logs-endpoint.*",
                "_all",  # Fallback to all indices if specific patterns fail
            ]
            response = self._search_with_fallback(indices_patterns, query)
            
            hits = response.get("hits", {}).get("hits", [])
            events = []
            
            for hit in hits:
                source = hit.get("_source", {})
                event_id = hit.get("_id", "")
                
                # Parse timestamp
                timestamp_str = source.get("@timestamp") or source.get("timestamp")
                timestamp = None
                if timestamp_str:
                    try:
                        timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                    except Exception:
                        pass
                if not timestamp:
                    timestamp = datetime.utcnow()
                
                # Determine source type from index or event fields
                source_type = "other"
                index = hit.get("_index", "")
                if "winlogbeat" in index or "windows" in index.lower():
                    source_type = "endpoint"
                elif "network" in index.lower() or "firewall" in index.lower():
                    source_type = "network"
                elif "auth" in index.lower() or "login" in index.lower():
                    source_type = "auth"
                elif "cloud" in index.lower():
                    source_type = "cloud"
                
                # Extract common fields
                # Handle nested structures (e.g., host.name vs host: {name: ...})
                host = None
                if isinstance(source.get("host"), dict):
                    host = source.get("host", {}).get("name")
                else:
                    host = source.get("host.name") or source.get("host")
                
                username = None
                if isinstance(source.get("user"), dict):
                    username = source.get("user", {}).get("name")
                else:
                    username = source.get("user.name") or source.get("user")
                
                ip = None
                if isinstance(source.get("source"), dict):
                    ip = source.get("source", {}).get("ip")
                else:
                    ip = source.get("source.ip") or source.get("source")
                
                process_name = None
                if isinstance(source.get("process"), dict):
                    process_name = source.get("process", {}).get("name")
                else:
                    process_name = source.get("process.name") or source.get("process")
                
                file_hash = None
                file_obj = source.get("file", {})
                if isinstance(file_obj, dict):
                    hash_obj = file_obj.get("hash", {})
                    if isinstance(hash_obj, dict):
                        file_hash = hash_obj.get("sha256")
                if not file_hash:
                    file_hash = source.get("file.hash.sha256")
                
                # Get message
                message = source.get("message") or source.get("event", {}).get("original", "")
                if isinstance(source.get("event"), dict):
                    message = message or source.get("event", {}).get("original", "")
                
                # Build normalized event dictionary
                event = {
                    "id": event_id,
                    "timestamp": timestamp.isoformat() if timestamp else None,
                    "source_type": source_type,
                    "message": message,
                    "host": host,
                    "username": username,
                    "ip": ip,
                    "process_name": process_name,
                    "file_hash": file_hash,
                    "raw": source,  # Include full raw source for detailed analysis
                }
                
                events.append(event)
            
            logger.debug(f"Retrieved {len(events)} events from {len(event_ids)} requested IDs")
            return events
            
        except Exception as e:
            logger.exception(f"Error retrieving events by IDs from Elasticsearch: {e}")
            # Return empty list rather than failing - ancestor events are supplementary
            return []

    def get_file_report(self, file_hash: str) -> FileReport:
        """Get a report about a file by hash."""
        try:
            # Search for events containing this file hash
            query = {
                "query": {
                    "bool": {
                        "should": [
                            {"match": {"file.hash.sha256": file_hash}},
                            {"match": {"file.hash.sha1": file_hash}},
                            {"match": {"file.hash.md5": file_hash}},
                            {"match": {"hash": file_hash}},
                        ]
                    }
                },
                "size": 100,
                "sort": [{"@timestamp": {"order": "asc"}}]
            }
            
            # Search with fallback index patterns
            indices_patterns = [
                "logs-*,security-*,winlogbeat-*,filebeat-*",
                "_all",  # Fallback to all indices if specific patterns fail
            ]
            response = self._search_with_fallback(indices_patterns, query)
            
            hits = response.get("hits", {}).get("hits", [])
            
            first_seen = None
            last_seen = None
            affected_hosts = set()
            
            for hit in hits:
                source = hit.get("_source", {})
                timestamp_str = source.get("@timestamp") or source.get("timestamp")
                if timestamp_str:
                    try:
                        ts = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                        if not first_seen or ts < first_seen:
                            first_seen = ts
                        if not last_seen or ts > last_seen:
                            last_seen = ts
                    except Exception:
                        pass
                
                host = source.get("host", {}).get("name") if isinstance(source.get("host"), dict) else source.get("host")
                if host:
                    affected_hosts.add(host)
            
            return FileReport(
                file_hash=file_hash,
                first_seen=first_seen,
                last_seen=last_seen,
                detection_count=len(hits),
                affected_hosts=list(affected_hosts) if affected_hosts else None,
                raw={"hits": hits[:10]} if hits else None,
            )
        except Exception as e:
            logger.exception(f"Error getting file report from Elasticsearch: {e}")
            raise IntegrationError(f"Failed to get file report: {e}") from e

    def get_file_behavior_summary(self, file_hash: str) -> FileBehaviorSummary:
        """Get behavior summary for a file."""
        # Use get_file_report and extract behavior information
        report = self.get_file_report(file_hash)
        
        # Try to extract process trees and network activity from events
        process_trees = []
        network_activity = []
        
        if report.raw and "hits" in report.raw:
            for hit in report.raw["hits"]:
                source = hit.get("_source", {})
                # Extract process information
                process = source.get("process", {})
                if process:
                    process_trees.append({
                        "name": process.get("name"),
                        "pid": process.get("pid"),
                        "parent": process.get("parent"),
                        "command_line": process.get("command_line"),
                    })
                
                # Extract network information
                network = source.get("network", {}) or source.get("destination", {})
                if network:
                    network_activity.append({
                        "ip": network.get("ip") or source.get("destination", {}).get("ip"),
                        "port": network.get("port") or source.get("destination", {}).get("port"),
                        "protocol": network.get("protocol"),
                    })
        
        return FileBehaviorSummary(
            file_hash=file_hash,
            process_trees=process_trees[:20] if process_trees else None,
            network_activity=network_activity[:20] if network_activity else None,
            persistence_mechanisms=None,  # Would need specific queries for this
            notes=f"Found {report.detection_count} events related to this file",
        )

    def get_entities_related_to_file(self, file_hash: str) -> RelatedEntities:
        """Get entities (hosts, users, processes, alerts) related to a file."""
        report = self.get_file_report(file_hash)
        
        hosts = set()
        users = set()
        processes = set()
        alerts = []
        
        if report.raw and "hits" in report.raw:
            for hit in report.raw["hits"]:
                source = hit.get("_source", {})
                
                host = source.get("host", {}).get("name") if isinstance(source.get("host"), dict) else source.get("host")
                if host:
                    hosts.add(host)
                
                user = source.get("user", {}).get("name") if isinstance(source.get("user"), dict) else source.get("user")
                if user:
                    users.add(user)
                
                process = source.get("process", {}).get("name") if isinstance(source.get("process"), dict) else source.get("process.name")
                if process:
                    processes.add(process)
                
                # Check if this is an alert
                if source.get("event", {}).get("kind") == "alert" or "alert" in source.get("tags", []):
                    alerts.append(hit.get("_id", ""))
        
        return RelatedEntities(
            indicator=file_hash,
            hosts=list(hosts) if hosts else None,
            users=list(users) if users else None,
            processes=list(processes) if processes else None,
            alerts=alerts if alerts else None,
        )

    def get_ip_address_report(self, ip: str) -> IpAddressReport:
        """Get a report about an IP address."""
        try:
            # Search for events containing this IP
            query = {
                "query": {
                    "bool": {
                        "should": [
                            {"match": {"source.ip": ip}},
                            {"match": {"destination.ip": ip}},
                            {"match": {"client.ip": ip}},
                            {"match": {"server.ip": ip}},
                            {"match": {"ip": ip}},
                        ]
                    }
                },
                "size": 50,
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
            
            # Search with fallback index patterns
            indices_patterns = [
                "logs-*,security-*,winlogbeat-*,filebeat-*",
                "_all",  # Fallback to all indices if specific patterns fail
            ]
            response = self._search_with_fallback(indices_patterns, query)
            
            hits = response.get("hits", {}).get("hits", [])
            alerts = []
            
            for hit in hits:
                source = hit.get("_source", {})
                if source.get("event", {}).get("kind") == "alert" or "alert" in source.get("tags", []):
                    alerts.append(hit.get("_id", ""))
            
            return IpAddressReport(
                ip=ip,
                reputation=None,  # Would need threat intelligence integration
                geo=None,  # Would need GeoIP lookup
                related_alerts=alerts if alerts else None,
                raw={"hits": hits[:10]} if hits else None,
            )
        except Exception as e:
            logger.exception(f"Error getting IP report from Elasticsearch: {e}")
            raise IntegrationError(f"Failed to get IP address report: {e}") from e

    def search_user_activity(
        self,
        username: str,
        limit: int = 100,
    ) -> QueryResult:
        """Search for user activity."""
        query = {
            "query": {
                "bool": {
                    "should": [
                        {"match": {"user.name": username}},
                        {"match": {"user": username}},
                        {"match": {"username": username}},
                    ]
                }
            },
            "size": limit,
            "sort": [{"@timestamp": {"order": "desc"}}]
        }
        
        return self.search_security_events(json.dumps(query), limit=limit)

    def pivot_on_indicator(
        self,
        indicator: str,
        limit: int = 200,
    ) -> QueryResult:
        """
        Given an IOC (hash, IP, domain, etc.), search for related events.
        """
        # Try to detect indicator type and search accordingly
        import re
        
        # IP address pattern
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        # Hash patterns (MD5, SHA1, SHA256)
        hash_pattern = r'^[a-fA-F0-9]{32,64}$'
        # Domain pattern
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        
        if re.match(ip_pattern, indicator):
            # IP address
            query = {
                "query": {
                    "bool": {
                        "should": [
                            {"match": {"source.ip": indicator}},
                            {"match": {"destination.ip": indicator}},
                            {"match": {"client.ip": indicator}},
                            {"match": {"server.ip": indicator}},
                        ]
                    }
                },
                "size": limit
            }
        elif re.match(hash_pattern, indicator):
            # File hash
            query = {
                "query": {
                    "bool": {
                        "should": [
                            {"match": {"file.hash.sha256": indicator}},
                            {"match": {"file.hash.sha1": indicator}},
                            {"match": {"file.hash.md5": indicator}},
                            {"match": {"hash": indicator}},
                        ]
                    }
                },
                "size": limit
            }
        elif re.match(domain_pattern, indicator) and '.' in indicator:
            # Domain
            query = {
                "query": {
                    "bool": {
                        "should": [
                            {"match": {"dns.question.name": indicator}},
                            {"match": {"url.domain": indicator}},
                            {"match": {"domain": indicator}},
                        ]
                    }
                },
                "size": limit
            }
        else:
            # Generic search
            query = {
                "query": {
                    "query_string": {
                        "query": indicator
                    }
                },
                "size": limit
            }
        
        return self.search_security_events(json.dumps(query), limit=limit)

    def search_kql_query(
        self,
        kql_query: str,
        limit: int = 500,
        hours_back: Optional[int] = None,
    ) -> QueryResult:
        """
        Execute a KQL (Kusto Query Language) or advanced query for deeper investigations.
        
        For Elasticsearch, this method accepts:
        - Full Elasticsearch Query DSL (JSON)
        - KQL-like queries that are converted to Elasticsearch DSL
        - Advanced aggregations and time-based analysis
        
        Args:
            kql_query: KQL query string or Elasticsearch Query DSL
            limit: Maximum number of events to return (default: 500)
            hours_back: Optional time window in hours to limit the search
        """
        try:
            # Try to parse as JSON first (Elasticsearch Query DSL)
            try:
                query_dict = json.loads(kql_query)
                if isinstance(query_dict, dict):
                    es_query = query_dict
                    # Ensure size is set
                    if "size" not in es_query:
                        es_query["size"] = limit
                else:
                    # Not a dict, treat as KQL
                    es_query = self._kql_to_elasticsearch(kql_query, limit=limit, hours_back=hours_back)
            except (json.JSONDecodeError, ValueError):
                # Parse as KQL-like query and convert to Elasticsearch DSL
                es_query = self._kql_to_elasticsearch(kql_query, limit=limit, hours_back=hours_back)
            
            # Add time range filter if specified
            if hours_back:
                time_filter = {
                    "range": {
                        "@timestamp": {
                            "gte": f"now-{hours_back}h"
                        }
                    }
                }
                if "query" in es_query:
                    if "bool" in es_query["query"]:
                        if "must" not in es_query["query"]["bool"]:
                            es_query["query"]["bool"]["must"] = []
                        es_query["query"]["bool"]["must"].append(time_filter)
                    else:
                        # Wrap existing query in bool
                        es_query["query"] = {
                            "bool": {
                                "must": [
                                    es_query["query"],
                                    time_filter
                                ]
                            }
                        }
                else:
                    es_query["query"] = time_filter
            
            # Search across all security indices with fallback
            indices_patterns = [
                "logs-*,security-*,winlogbeat-*,filebeat-*,alerts-*,.siem-signals-*",
                "_all",  # Fallback to all indices if specific patterns fail
            ]
            response = self._search_with_fallback(indices_patterns, es_query)
            
            # Parse Elasticsearch response
            hits = response.get("hits", {}).get("hits", [])
            total = response.get("hits", {}).get("total", {})
            if isinstance(total, dict):
                total_count = total.get("value", len(hits))
            else:
                total_count = total
            
            events = []
            for hit in hits[:limit]:
                source = hit.get("_source", {})
                timestamp_str = source.get("@timestamp") or source.get("timestamp")
                timestamp = None
                if timestamp_str:
                    try:
                        timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                    except Exception:
                        pass
                if not timestamp:
                    timestamp = datetime.utcnow()
                
                # Determine source type from index or event fields
                source_type = SourceType.OTHER
                index = hit.get("_index", "")
                if "winlogbeat" in index or "windows" in index.lower():
                    source_type = SourceType.ENDPOINT
                elif "network" in index.lower() or "firewall" in index.lower():
                    source_type = SourceType.NETWORK
                elif "auth" in index.lower() or "login" in index.lower():
                    source_type = SourceType.AUTH
                elif "cloud" in index.lower():
                    source_type = SourceType.CLOUD
                
                event = SiemEvent(
                    id=hit.get("_id", ""),
                    timestamp=timestamp,
                    source_type=source_type,
                    message=source.get("message", source.get("event", {}).get("original", "")),
                    host=source.get("host", {}).get("name") if isinstance(source.get("host"), dict) else source.get("host"),
                    username=source.get("user", {}).get("name") if isinstance(source.get("user"), dict) else source.get("user"),
                    ip=source.get("source", {}).get("ip") if isinstance(source.get("source"), dict) else source.get("source.ip"),
                    process_name=source.get("process", {}).get("name") if isinstance(source.get("process"), dict) else source.get("process.name"),
                    file_hash=source.get("file", {}).get("hash", {}).get("sha256") if isinstance(source.get("file"), dict) else source.get("file.hash.sha256"),
                    raw=source,
                )
                events.append(event)
            
            return QueryResult(
                query=kql_query,
                events=events,
                total_count=total_count,
            )
        except Exception as e:
            logger.exception(f"Error executing KQL query: {e}")
            raise IntegrationError(f"Failed to execute KQL query: {e}") from e

    _DEFAULT_EVENT_INDEX_PATTERNS = [
        "logs-*,security-*,winlogbeat-*,filebeat-*,alerts-*,.siem-signals-*",
        "_all",
    ]

    def _infer_source_type(self, index: str) -> SourceType:
        index_l = (index or "").lower()
        if "winlogbeat" in index_l or "windows" in index_l or "endpoint" in index_l:
            return SourceType.ENDPOINT
        if "network" in index_l or "firewall" in index_l:
            return SourceType.NETWORK
        if "auth" in index_l or "login" in index_l:
            return SourceType.AUTH
        if "cloud" in index_l:
            return SourceType.CLOUD
        return SourceType.OTHER

    def _hit_to_siem_event(self, hit: Dict[str, Any]) -> SiemEvent:
        source = hit.get("_source", {}) or {}
        timestamp_str = source.get("@timestamp") or source.get("timestamp")
        timestamp = None
        if timestamp_str:
            try:
                timestamp = datetime.fromisoformat(str(timestamp_str).replace("Z", "+00:00"))
            except Exception:
                timestamp = None
        if not timestamp:
            timestamp = datetime.utcnow()

        host = source.get("host", {}).get("name") if isinstance(source.get("host"), dict) else source.get("host")
        username = source.get("user", {}).get("name") if isinstance(source.get("user"), dict) else source.get("user")
        ip = source.get("source", {}).get("ip") if isinstance(source.get("source"), dict) else source.get("source.ip")
        process_name = (
            source.get("process", {}).get("name")
            if isinstance(source.get("process"), dict)
            else source.get("process.name")
        )
        file_hash = None
        file_obj = source.get("file")
        if isinstance(file_obj, dict):
            hashes = file_obj.get("hash") if isinstance(file_obj.get("hash"), dict) else {}
            file_hash = hashes.get("sha256") or hashes.get("md5")
        if not file_hash:
            file_hash = source.get("file.hash.sha256")

        return SiemEvent(
            id=hit.get("_id", ""),
            timestamp=timestamp,
            source_type=self._infer_source_type(hit.get("_index", "")),
            message=source.get("message")
            or (source.get("event", {}) or {}).get("original", "")
            or (source.get("event", {}) or {}).get("reason", "")
            or "",
            host=host,
            username=username,
            ip=ip,
            process_name=process_name,
            file_hash=file_hash,
            raw=source,
        )

    def _hits_to_query_result(
        self,
        query_label: str,
        hits: List[Dict[str, Any]],
        total_count: int,
        limit: int,
    ) -> QueryResult:
        events = [self._hit_to_siem_event(hit) for hit in hits[:limit]]
        return QueryResult(query=query_label, events=events, total_count=total_count)

    @staticmethod
    def _apply_hours_back_filter(es_query: Dict[str, Any], hours_back: Optional[int]) -> Dict[str, Any]:
        if not hours_back:
            return es_query
        time_filter = {"range": {"@timestamp": {"gte": f"now-{hours_back}h"}}}
        if "query" in es_query:
            if "bool" in es_query["query"]:
                es_query["query"]["bool"].setdefault("must", []).append(time_filter)
            else:
                es_query["query"] = {
                    "bool": {
                        "must": [es_query["query"], time_filter],
                    }
                }
        else:
            es_query["query"] = time_filter
        return es_query

    @staticmethod
    def _extract_total_count(response: Dict[str, Any], fallback: int = 0) -> int:
        total = response.get("hits", {}).get("total", fallback)
        if isinstance(total, dict):
            return int(total.get("value", fallback))
        try:
            return int(total)
        except (TypeError, ValueError):
            return fallback

    def search_lucene_query(
        self,
        lucene_query: str,
        limit: int = 500,
        hours_back: Optional[int] = None,
        index_pattern: Optional[str] = None,
    ) -> QueryResult:
        """Execute a Lucene ``query_string`` search against security indices."""
        try:
            es_query: Dict[str, Any] = {
                "query": {
                    "query_string": {
                        "query": lucene_query,
                        "default_field": "message",
                        "analyze_wildcard": True,
                        "lenient": True,
                    }
                },
                "size": limit,
                "sort": [{"@timestamp": {"order": "desc"}}],
            }
            es_query = self._apply_hours_back_filter(es_query, hours_back)

            patterns = (
                [index_pattern, "_all"]
                if index_pattern
                else list(self._DEFAULT_EVENT_INDEX_PATTERNS)
            )
            response = self._search_with_fallback(patterns, es_query)
            hits = response.get("hits", {}).get("hits", [])
            return self._hits_to_query_result(
                lucene_query,
                hits,
                self._extract_total_count(response, len(hits)),
                limit,
            )
        except Exception as e:
            logger.exception(f"Error executing Lucene query: {e}")
            raise IntegrationError(f"Failed to execute Lucene query: {e}") from e

    def search_eql_query(
        self,
        eql_query: str,
        limit: int = 100,
        hours_back: Optional[int] = None,
        index_pattern: Optional[str] = None,
    ) -> QueryResult:
        """
        Execute an Elastic Event Query Language (EQL) search.

        Uses ``POST /{index}/_eql/search``. Best for process/network sequence hunts.
        """
        try:
            body: Dict[str, Any] = {
                "query": eql_query,
                "size": limit,
            }
            if hours_back:
                body["filter"] = {
                    "range": {"@timestamp": {"gte": f"now-{hours_back}h"}}
                }

            indices = index_pattern or "logs-*,winlogbeat-*,.alerts-security.*"
            response = self._http.post(f"/{indices}/_eql/search", json_data=body)

            # EQL returns hits.events (event queries) or hits.sequences
            hits_block = response.get("hits", {}) or {}
            events_raw = hits_block.get("events") or []
            if not events_raw and hits_block.get("sequences"):
                # Flatten sequence events for a consistent QueryResult
                for sequence in hits_block.get("sequences") or []:
                    events_raw.extend(sequence.get("events") or [])

            total = hits_block.get("total")
            if isinstance(total, dict):
                total_count = int(total.get("value", len(events_raw)))
            elif total is not None:
                total_count = int(total)
            else:
                total_count = len(events_raw)

            return self._hits_to_query_result(eql_query, events_raw, total_count, limit)
        except Exception as e:
            logger.exception(f"Error executing EQL query: {e}")
            raise IntegrationError(f"Failed to execute EQL query: {e}") from e

    def search_dsl_query(
        self,
        dsl_query: str,
        limit: int = 500,
        hours_back: Optional[int] = None,
        index_pattern: Optional[str] = None,
    ) -> QueryResult:
        """Execute a raw Elasticsearch Query DSL search (JSON body)."""
        try:
            try:
                es_query = json.loads(dsl_query)
            except (json.JSONDecodeError, TypeError) as exc:
                raise IntegrationError(
                    "dsl_query must be a JSON Elasticsearch Query DSL object"
                ) from exc

            if not isinstance(es_query, dict):
                raise IntegrationError("dsl_query JSON must be an object")

            if "size" not in es_query:
                es_query["size"] = limit
            if "sort" not in es_query:
                es_query["sort"] = [{"@timestamp": {"order": "desc"}}]

            es_query = self._apply_hours_back_filter(es_query, hours_back)

            patterns = (
                [index_pattern, "_all"]
                if index_pattern
                else list(self._DEFAULT_EVENT_INDEX_PATTERNS)
            )
            response = self._search_with_fallback(patterns, es_query)
            hits = response.get("hits", {}).get("hits", [])
            return self._hits_to_query_result(
                dsl_query,
                hits,
                self._extract_total_count(response, len(hits)),
                limit,
            )
        except IntegrationError:
            raise
        except Exception as e:
            logger.exception(f"Error executing DSL query: {e}")
            raise IntegrationError(f"Failed to execute DSL query: {e}") from e

    def search_esql_query(
        self,
        esql_query: str,
        limit: int = 500,
    ) -> QueryResult:
        """
        Execute an ES|QL query via ``POST /_query``.

        The query should include its own ``FROM`` / ``LIMIT`` clauses. When
        ``LIMIT`` is absent, one is appended using ``limit``.
        """
        try:
            query_text = esql_query.strip().rstrip(";")
            if " limit " not in query_text.lower():
                query_text = f"{query_text} | LIMIT {int(limit)}"

            response = self._http.post(
                "/_query",
                json_data={"query": query_text, "locale": "en-US"},
            )

            columns = response.get("columns") or []
            values = response.get("values") or []
            col_names = [c.get("name") for c in columns]

            events: List[SiemEvent] = []
            for row in values[:limit]:
                row_map = {
                    col_names[i]: row[i]
                    for i in range(min(len(col_names), len(row)))
                    if col_names[i]
                }
                timestamp = datetime.utcnow()
                ts_val = row_map.get("@timestamp") or row_map.get("timestamp")
                if ts_val:
                    try:
                        timestamp = datetime.fromisoformat(str(ts_val).replace("Z", "+00:00"))
                    except Exception:
                        pass

                message_parts = [
                    f"{k}={v}"
                    for k, v in row_map.items()
                    if k not in {"@timestamp", "timestamp"} and v is not None
                ]
                events.append(
                    SiemEvent(
                        id=str(row_map.get("_id") or row_map.get("event.id") or len(events)),
                        timestamp=timestamp,
                        source_type=SourceType.OTHER,
                        message="; ".join(message_parts)[:2000],
                        host=row_map.get("host.name") or row_map.get("host"),
                        username=row_map.get("user.name") or row_map.get("user"),
                        ip=row_map.get("source.ip") or row_map.get("destination.ip"),
                        process_name=row_map.get("process.name"),
                        file_hash=row_map.get("file.hash.sha256"),
                        raw=row_map,
                    )
                )

            return QueryResult(
                query=esql_query,
                events=events,
                total_count=len(values),
            )
        except Exception as e:
            logger.exception(f"Error executing ES|QL query: {e}")
            raise IntegrationError(f"Failed to execute ES|QL query: {e}") from e

    def _kql_to_elasticsearch(self, kql_query: str, limit: int = 500, hours_back: Optional[int] = None) -> Dict[str, Any]:
        """
        Convert a KQL-like query to Elasticsearch Query DSL.
        
        Supports basic KQL patterns:
        - Field filters: field == value, field != value
        - Logical operators: and, or, not
        - Comparison operators: ==, !=, >, <, >=, <=
        - Contains: field contains "value"
        - Time ranges: | where timestamp > ago(1h)
        """
        import re
        
        # Start with base query structure
        query = {
            "size": limit,
            "sort": [{"@timestamp": {"order": "desc"}}]
        }
        
        # Parse KQL query
        # Remove pipe operators and parse filters
        filters = []
        
        # Handle time range (e.g., | where timestamp > ago(1h))
        if "ago(" in kql_query.lower():
            ago_match = re.search(r'ago\((\d+)([hdm])\)', kql_query.lower())
            if ago_match:
                value = int(ago_match.group(1))
                unit = ago_match.group(2)
                if unit == "h":
                    hours_back = value
                elif unit == "d":
                    hours_back = value * 24
                elif unit == "m":
                    hours_back = value / 60
        
        # Remove time filters from query string for field parsing
        query_str = re.sub(r'\|\s*where\s+timestamp.*', '', kql_query, flags=re.IGNORECASE)
        query_str = re.sub(r'ago\([^)]+\)', '', query_str, flags=re.IGNORECASE)
        
        # Parse field filters
        # Pattern: field == value, field != value, field > value, etc.
        field_patterns = [
            (r'(\w+)\s*==\s*"([^"]+)"', "term"),
            (r'(\w+)\s*==\s*(\S+)', "term"),
            (r'(\w+)\s*!=\s*"([^"]+)"', "must_not_term"),
            (r'(\w+)\s*!=\s*(\S+)', "must_not_term"),
            (r'(\w+)\s*contains\s*"([^"]+)"', "match"),
            (r'(\w+)\s*contains\s*(\S+)', "match"),
        ]
        
        bool_query = {"bool": {"must": []}}
        
        for pattern, query_type in field_patterns:
            matches = re.finditer(pattern, query_str)
            for match in matches:
                field = match.group(1)
                value = match.group(2)
                
                # Map common KQL fields to Elasticsearch fields
                field_mapping = {
                    "host": "host.name",
                    "ip": "source.ip",
                    "user": "user.name",
                    "username": "user.name",
                    "process": "process.name",
                    "file": "file.path",
                    "hash": "file.hash.sha256",
                    "domain": "dns.question.name",
                }
                
                es_field = field_mapping.get(field.lower(), field)
                
                if query_type == "term":
                    bool_query["bool"]["must"].append({"term": {es_field: value}})
                elif query_type == "must_not_term":
                    if "must_not" not in bool_query["bool"]:
                        bool_query["bool"]["must_not"] = []
                    bool_query["bool"]["must_not"].append({"term": {es_field: value}})
                elif query_type == "match":
                    bool_query["bool"]["must"].append({"match": {es_field: value}})
        
        # If no filters were parsed, use query_string as fallback
        if not bool_query["bool"]["must"] and not bool_query["bool"].get("must_not"):
            bool_query["bool"]["must"].append({
                "query_string": {
                    "query": query_str.strip()
                }
            })
        
        query["query"] = bool_query
        
        return query

    # Alert Management Methods

    @staticmethod
    def _normalize_alert_status(status: Optional[str]) -> Optional[str]:
        if status is None:
            return None
        normalized = str(status).strip().lower()
        if not normalized:
            return None
        return _ALERT_STATUS_ALIASES.get(normalized, normalized)

    @staticmethod
    def _alert_status_clause(status: str) -> Dict[str, Any]:
        """Match Elastic workflow status across legacy and Kibana alert fields."""
        return {
            "bool": {
                "should": [
                    {"term": {"signal.status": status}},
                    {"term": {"kibana.alert.workflow_status": status}},
                    {"term": {"kibana.alert.workflow_status.keyword": status}},
                ],
                "minimum_should_match": 1,
            }
        }

    @staticmethod
    def _alert_rule_name_clause(rule_name: str) -> Dict[str, Any]:
        return {
            "bool": {
                "should": [
                    {"match_phrase": {"signal.rule.name": rule_name}},
                    {"match_phrase": {"kibana.alert.rule.name": rule_name}},
                    {"match_phrase": {"rule.name": rule_name}},
                ],
                "minimum_should_match": 1,
            }
        }

    @staticmethod
    def _alert_rule_id_clause(rule_id: str) -> Dict[str, Any]:
        return {
            "bool": {
                "should": [
                    {"term": {"signal.rule.id": rule_id}},
                    {"term": {"signal.rule.rule_id": rule_id}},
                    {"term": {"kibana.alert.rule.uuid": rule_id}},
                    {"term": {"kibana.alert.rule.rule_id": rule_id}},
                    {"term": {"rule.id": rule_id}},
                ],
                "minimum_should_match": 1,
            }
        }

    @staticmethod
    def _resolve_include_investigated(
        status_filter: Optional[str],
        include_investigated: Optional[bool],
    ) -> bool:
        if include_investigated is not None:
            return bool(include_investigated)
        # Historical status reviews need verdicted/closed alerts.
        return status_filter in _HISTORICAL_STATUSES

    def _extract_rule_fields(self, source: Dict[str, Any], signal: Dict[str, Any]) -> Dict[str, str]:
        rule = signal.get("rule") if isinstance(signal.get("rule"), dict) else {}
        source_rule = source.get("rule") if isinstance(source.get("rule"), dict) else {}

        rule_name = (
            rule.get("name")
            or source.get("kibana.alert.rule.name", "")
            or source_rule.get("name", "")
            or source.get("message", "")
            or source.get("event", {}).get("reason", "")
            or ""
        )
        rule_id = (
            rule.get("id")
            or rule.get("rule_id")
            or source.get("kibana.alert.rule.uuid", "")
            or source.get("kibana.alert.rule.rule_id", "")
            or source_rule.get("id", "")
            or source_rule.get("rule_id", "")
            or ""
        )
        return {"rule_name": rule_name, "rule_id": str(rule_id) if rule_id else ""}

    def get_security_alerts(
        self,
        hours_back: int = 24,
        max_alerts: int = 10,
        status_filter: Optional[str] = None,
        severity: Optional[str] = None,
        hostname: Optional[str] = None,
        rule_name: Optional[str] = None,
        rule_id: Optional[str] = None,
        include_investigated: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get security alerts from Elasticsearch.

        Searches alerts-* / .siem-signals-* indices with optional filters for
        workflow status (open / acknowledged / closed), rule name/id, severity,
        and hostname.

        By default excludes closed alerts and alerts that already have
        ``signal.ai.verdict`` (triage queue). Pass ``status_filter="closed"`` /
        ``"acknowledged"`` (or ``include_investigated=True``) to include them
        for historical review.
        """
        try:
            status_filter = self._normalize_alert_status(status_filter)
            include_investigated = self._resolve_include_investigated(
                status_filter, include_investigated
            )

            must_clauses: List[Dict[str, Any]] = [
                {"range": {"@timestamp": {"gte": f"now-{hours_back}h"}}}
            ]
            must_not_clauses: List[Dict[str, Any]] = []

            if status_filter:
                must_clauses.append(self._alert_status_clause(status_filter))
            else:
                # Default: exclude closed alerts (both legacy and Kibana fields)
                must_not_clauses.append(self._alert_status_clause("closed"))

            if severity:
                must_clauses.append({
                    "bool": {
                        "should": [
                            {"match": {"signal.rule.severity": severity}},
                            {"match": {"signal.severity": severity}},
                            {"match": {"kibana.alert.severity": severity}},
                        ],
                        "minimum_should_match": 1,
                    }
                })

            if hostname:
                must_clauses.append({
                    "bool": {
                        "should": [
                            {"match": {"host.name": hostname}},
                            {"match": {"hostname": hostname}},
                            {"match": {"host": hostname}},
                        ],
                        "minimum_should_match": 1,
                    }
                })

            if rule_name:
                must_clauses.append(self._alert_rule_name_clause(rule_name))

            if rule_id:
                must_clauses.append(self._alert_rule_id_clause(rule_id))

            if not include_investigated:
                must_not_clauses.append({"exists": {"field": "signal.ai.verdict"}})

            bool_query: Dict[str, Any] = {"must": must_clauses}
            if must_not_clauses:
                bool_query["must_not"] = must_not_clauses

            query = {
                "query": {"bool": bool_query},
                "size": max_alerts,
                "sort": [{"@timestamp": {"order": "desc"}}],
            }

            response = self._search_with_fallback(_ALERT_INDEX_PATTERNS, query)
            hits = response.get("hits", {}).get("hits", [])
            alerts = []

            for hit in hits:
                source = hit.get("_source", {})
                signal = source.get("signal", {}) if isinstance(source.get("signal"), dict) else {}
                signal_ai = signal.get("ai", {}) if isinstance(signal.get("ai"), dict) else {}
                verdict = signal_ai.get("verdict")

                # Safety net when exclude-investigated is active
                if verdict and not include_investigated:
                    continue

                rule_fields = self._extract_rule_fields(source, signal)
                title = rule_fields["rule_name"]
                alert_severity = (
                    signal.get("severity")
                    or source.get("kibana.alert.severity")
                    or "medium"
                )
                status = (
                    signal.get("status")
                    or source.get("kibana.alert.workflow_status")
                    or "open"
                )

                alerts.append({
                    "id": hit.get("_id", ""),
                    "title": title,
                    "rule_name": rule_fields["rule_name"],
                    "rule_id": rule_fields["rule_id"],
                    "severity": alert_severity,
                    "status": status,
                    "created_at": source.get("@timestamp", ""),
                    "description": self._extract_description_from_alert(source, signal),
                    "source": "elastic",
                    "related_entities": self._extract_entities_from_alert(source),
                    "verdict": verdict,
                    "signal": {
                        "ai": {
                            "verdict": verdict,
                        }
                    },
                })

            return alerts
        except Exception as e:
            logger.exception(f"Error getting security alerts: {e}")
            raise IntegrationError(f"Failed to get security alerts: {e}") from e

    def get_security_alert_by_id(
        self,
        alert_id: str,
        include_detections: bool = True,
    ) -> Dict[str, Any]:
        """Get detailed information about a specific security alert."""
        try:
            # Search for alert by ID using ids query (correct way to search by document ID)
            query = {
                "query": {
                    "ids": {
                        "values": [alert_id]
                    }
                }
            }
            
            # Search with fallback index patterns
            indices_patterns = [
                "alerts-*,.siem-signals-*,logs-endpoint.alerts-*",
                "alerts-*",
                "_all",  # Fallback to all indices if specific patterns fail
            ]
            response = self._search_with_fallback(indices_patterns, query)
            
            hits = response.get("hits", {}).get("hits", [])
            if not hits:
                raise IntegrationError(f"Alert {alert_id} not found")
            
            hit = hits[0]
            source = hit.get("_source", {})
            signal = source.get("signal", {})
            rule = signal.get("rule", {}) if isinstance(signal.get("rule"), dict) else {}
            
            # Extract from Kibana alert format (newer format with flat dot notation keys)
            # kibana.alert.rule.parameters is an object, others are flat keys
            kibana_rule_params = source.get("kibana.alert.rule.parameters", {})
            if not isinstance(kibana_rule_params, dict):
                kibana_rule_params = {}
            
            # Get title: prefer signal.rule.name, fallback to kibana.alert.rule.name, then rule.name, then message
            title = rule.get("name", "")
            if not title:
                title = source.get("kibana.alert.rule.name", "")
            if not title:
                # Check for endpoint detection format (rule.name directly on document)
                rule_obj = source.get("rule", {})
                if isinstance(rule_obj, dict):
                    title = rule_obj.get("name", "")
            if not title:
                # Check message field (common in endpoint detections)
                title = source.get("message", "")
            
            # Get description: prefer signal.rule.description, fallback to kibana.alert.rule.parameters.description, then rule.description
            description = rule.get("description", "")
            if not description:
                description = kibana_rule_params.get("description", "")
                # If still empty, try kibana.alert.rule.description (flat key)
                if not description:
                    description = source.get("kibana.alert.rule.description", "")
            if not description:
                # Check for endpoint detection format (rule.description directly on document)
                rule_obj = source.get("rule", {})
                if isinstance(rule_obj, dict):
                    description = rule_obj.get("description", "")
            
            # Get severity: prefer signal.severity, fallback to kibana.alert.severity
            severity = signal.get("severity", "")
            if not severity:
                severity = source.get("kibana.alert.severity", "")
            if not severity:
                severity = "medium"  # Default fallback
            
            # Get status: prefer signal.status, fallback to kibana.alert.workflow_status
            status = signal.get("status", "")
            if not status:
                status = source.get("kibana.alert.workflow_status", "")
            if not status:
                status = "open"  # Default fallback
            
            # Extract comments from signal.ai.comments.comment
            comments = []
            
            # Check signal.ai.comments.comment
            signal_ai = signal.get("ai", {})
            if isinstance(signal_ai, dict):
                ai_comments = signal_ai.get("comments", {})
                if isinstance(ai_comments, dict):
                    ai_comment = ai_comments.get("comment")
                    if isinstance(ai_comment, list):
                        logger.debug(f"Found {len(ai_comment)} comments in signal.ai.comments.comment")
                        comments.extend(ai_comment)
                    elif ai_comment:
                        # Single comment as string or dict
                        comments.append(ai_comment)
            
            logger.debug(f"Total comments found for alert {alert_id}: {len(comments)}")
            
            # Remove duplicates based on comment text and timestamp
            seen_comments = set()
            unique_comments = []
            for comment in comments:
                if isinstance(comment, dict):
                    comment_key = (comment.get("comment", ""), comment.get("timestamp", ""))
                else:
                    comment_key = (str(comment), "")
                if comment_key not in seen_comments:
                    seen_comments.add(comment_key)
                    unique_comments.append(comment)
            
            # Get verdict from signal.ai.verdict
            verdict = ""
            signal_ai = signal.get("ai", {})
            if isinstance(signal_ai, dict):
                verdict = signal_ai.get("verdict", "")
            
            alert = {
                "id": alert_id,
                "title": title,
                "severity": severity,
                "status": status,
                "priority": self._severity_to_priority(severity),
                "verdict": verdict,
                "description": description,
                "created_at": source.get("@timestamp", ""),
                "updated_at": source.get("@timestamp", ""),
                "related_entities": self._extract_entities_from_alert(source),
                "comments": unique_comments,
            }
            
            if include_detections:
                alert["detections"] = [{
                    "id": alert_id,
                    "timestamp": source.get("@timestamp", ""),
                    "severity": severity,
                    "status": status,
                    "description": description,
                }]
            
            # Extract and retrieve ancestor events that triggered this alert
            ancestor_event_ids = []
            
            # Check for kibana.alert.ancestors (newer format)
            kibana_ancestors = source.get("kibana.alert.ancestors", [])
            if isinstance(kibana_ancestors, list):
                for ancestor in kibana_ancestors:
                    if isinstance(ancestor, dict):
                        ancestor_id = ancestor.get("id")
                        if ancestor_id:
                            ancestor_event_ids.append(ancestor_id)
            
            # Check for signal.ancestors (older format) if no kibana ancestors found
            if not ancestor_event_ids:
                signal_ancestors = signal.get("ancestors", [])
                if isinstance(signal_ancestors, list):
                    for ancestor in signal_ancestors:
                        if isinstance(ancestor, dict):
                            ancestor_id = ancestor.get("id")
                            if ancestor_id:
                                ancestor_event_ids.append(ancestor_id)
            
            # Retrieve the ancestor events
            if ancestor_event_ids:
                try:
                    ancestor_events = self._get_events_by_ids(ancestor_event_ids)
                    alert["events"] = ancestor_events
                    logger.debug(f"Retrieved {len(ancestor_events)} ancestor events for alert {alert_id}")
                except Exception as e:
                    logger.warning(f"Failed to retrieve ancestor events for alert {alert_id}: {e}")
                    # Continue without events rather than failing the entire alert retrieval
                    alert["events"] = []
            else:
                alert["events"] = []

            # Security Solution / Rule Tuner notes are NOT on alert _source.
            # Always attach them when loading an alert so triage sees analyst guidance.
            try:
                notes_result = self.get_alert_notes(alert_id=alert_id)
                alert["notes"] = notes_result.get("notes", [])
                alert["note_texts"] = notes_result.get("note_texts", [])
                alert["notes_total_count"] = notes_result.get("total_count", 0)
            except Exception as e:
                logger.warning(
                    "Failed to fetch Kibana notes for alert %s: %s", alert_id, e
                )
                alert["notes"] = []
                alert["note_texts"] = []
                alert["notes_total_count"] = 0
            
            return alert
        except Exception as e:
            logger.exception(f"Error getting security alert by ID: {e}")
            raise IntegrationError(f"Failed to get security alert: {e}") from e
    
    def get_raw_alert_document(self, alert_id: str) -> Dict[str, Any]:
        """
        Get the raw Elasticsearch document for an alert by ID.
        Useful for debugging and investigating field structures.
        
        Args:
            alert_id: The alert ID to fetch
            
        Returns:
            Raw _source document from Elasticsearch
        """
        try:
            query = {
                "query": {
                    "ids": {
                        "values": [alert_id]
                    }
                },
                "size": 1
            }
            
            indices_patterns = [
                "alerts-*,.siem-signals-*,logs-endpoint.alerts-*",
                "alerts-*",
                "_all",
            ]
            response = self._search_with_fallback(indices_patterns, query)
            
            hits = response.get("hits", {}).get("hits", [])
            if not hits:
                raise IntegrationError(f"Alert {alert_id} not found")
            
            return hits[0].get("_source", {})
        except Exception as e:
            logger.exception(f"Error getting raw alert document {alert_id}: {e}")
            raise IntegrationError(f"Failed to get raw alert document: {e}") from e

    def _cases_http(self) -> ElasticHttpClient:
        if self._kibana_http is not None:
            return self._kibana_http
        from ....core.elastic_clusters import derive_kibana_url

        kibana_url = derive_kibana_url(self._http.base_url)
        if kibana_url.rstrip("/") == (self._http.base_url or "").rstrip("/"):
            return self._http
        return ElasticHttpClient(
            base_url=kibana_url,
            api_key=self._http.api_key,
            username=self._http.username,
            password=self._http.password,
            timeout_seconds=self._http.timeout_seconds,
            verify_ssl=self._http.verify_ssl,
        )

    def _search_alert_hit(self, alert_id: str) -> Dict[str, Any]:
        query = {"query": {"ids": {"values": [alert_id]}}}
        indices_patterns = [
            "alerts-*,.siem-signals-*,logs-endpoint.alerts-*",
            "alerts-*",
            "_all",
        ]
        response = self._search_with_fallback(indices_patterns, query)
        hits = response.get("hits", {}).get("hits", [])
        if not hits:
            raise IntegrationError(f"Alert {alert_id} not found")
        return hits[0]

    def create_security_case(
        self,
        title: Optional[str] = None,
        description: Optional[str] = None,
        severity: str = "high",
        tags: Optional[List[str]] = None,
        alert_id: Optional[str] = None,
        identity: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Open a case in Elastic Security (Kibana Cases API), not IRIS/TheHive.

        Pulls the full alert (entities, events, comments) into the case body.
        """
        from .case_builder import (
            build_elastic_case_description,
            default_case_title,
            kibana_severity,
        )

        alert: Optional[Dict[str, Any]] = None
        alert_index: Optional[str] = None
        raw_source: Dict[str, Any] = {}
        if alert_id:
            try:
                hit = self._search_alert_hit(str(alert_id))
                alert_index = hit.get("_index")
                raw_source = hit.get("_source") or {}
                alert = self.get_security_alert_by_id(str(alert_id), include_detections=True)
            except Exception as exc:
                logger.warning("Could not load alert %s for Elastic case: %s", alert_id, exc)
                alert = {
                    "id": str(alert_id),
                    "title": title or "",
                    "description": f"Alert {alert_id} could not be loaded: {exc}",
                }

        case_title = (title or "").strip() or default_case_title(
            alert=alert, identity=identity
        )
        case_description = build_elastic_case_description(
            notes=description or "",
            alert=alert,
            identity=identity,
        )
        case_tags = []
        for item in ["sami-gpt", "escalated", *(tags or [])]:
            text = str(item).strip()
            if text and text not in case_tags:
                case_tags.append(text)
        if identity:
            if "identity-verify" not in case_tags:
                case_tags.append("identity-verify")

        payload = {
            "title": case_title,
            "description": case_description,
            "tags": case_tags,
            "severity": kibana_severity(
                severity or (alert or {}).get("severity") or (alert or {}).get("priority")
            ),
            "connector": {
                "id": "none",
                "name": "none",
                "type": ".none",
                "fields": None,
            },
            "settings": {"syncAlerts": True},
            "owner": "securitySolution",
        }

        kibana = self._cases_http()
        try:
            created = kibana.post("/api/cases", json_data=payload)
        except IntegrationError as exc:
            hint = ""
            if "401" in str(exc) or "Unauthorized" in str(exc):
                hint = (
                    " The cluster API key was accepted by Elasticsearch but rejected by Kibana Cases. "
                    "Use a Kibana API key with cases privileges, or set kibana_url on the cluster."
                )
            raise IntegrationError(f"Failed to open Elastic Security case:{hint} {exc}") from exc
        case_id = created.get("id") or created.get("case_id")
        if not case_id:
            raise IntegrationError(f"Elastic Cases API did not return a case id: {created}")

        attached = False
        attach_error = None
        if alert_id and alert_index:
            try:
                rule = raw_source.get("kibana.alert.rule") or {}
                if not isinstance(rule, dict):
                    rule = {}
                signal_rule = (raw_source.get("signal") or {}).get("rule") or {}
                if not isinstance(signal_rule, dict):
                    signal_rule = {}
                kibana.post(
                    f"/api/cases/{case_id}/comments",
                    json_data={
                        "type": "alert",
                        "alertId": [str(alert_id)],
                        "index": [str(alert_index)],
                        "owner": "securitySolution",
                        "rule": {
                            "id": (
                                raw_source.get("kibana.alert.rule.uuid")
                                or rule.get("uuid")
                                or signal_rule.get("id")
                                or ""
                            ),
                            "name": (
                                raw_source.get("kibana.alert.rule.name")
                                or rule.get("name")
                                or signal_rule.get("name")
                                or (alert or {}).get("title")
                                or ""
                            ),
                        },
                    },
                )
                attached = True
            except Exception as exc:
                attach_error = str(exc)
                logger.warning("Created Elastic case %s but failed to attach alert %s: %s", case_id, alert_id, exc)

        return {
            "success": True,
            "provider": "elastic",
            "case_id": case_id,
            "title": created.get("title") or case_title,
            "description": created.get("description") or case_description,
            "severity": created.get("severity") or payload["severity"],
            "status": created.get("status") or "open",
            "tags": created.get("tags") or case_tags,
            "alert_id": alert_id,
            "alert_attached": attached,
            "attach_error": attach_error,
            "case": created,
        }

    def isolate_endpoint(
        self,
        endpoint_id: str,
        comment: Optional[str] = None,
        hostname: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Isolate a host via Kibana Elastic Defend (Endpoint Security)."""
        return self._submit_host_action("isolate", endpoint_id, comment, hostname)

    def release_endpoint_isolation(
        self,
        endpoint_id: str,
        comment: Optional[str] = None,
        hostname: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Release a host from isolation via Kibana Elastic Defend."""
        return self._submit_host_action("unisolate", endpoint_id, comment, hostname)

    def _submit_host_action(
        self,
        command: str,
        endpoint_id: Optional[str],
        comment: Optional[str],
        hostname: Optional[str],
    ) -> Dict[str, Any]:
        agent_id = self._resolve_agent_id(endpoint_id, hostname)
        kibana = self._cases_http()
        payload = {
            "endpoint_ids": [agent_id],
            "comment": (comment or "").strip()
            or f"SamiGPT {command} ({hostname or agent_id})",
        }
        last_error: Optional[Exception] = None
        response: Optional[Dict[str, Any]] = None
        used = None
        for path in (f"/api/endpoint/action/{command}", f"/api/endpoint/{command}"):
            try:
                response = kibana.post(path, json_data=payload)
                used = path
                break
            except IntegrationError as exc:
                last_error = exc
                status = str(exc)
                if "HTTP 404" in status or "Not Found" in status:
                    continue
                hint = ""
                if "401" in status or "403" in status or "Unauthorized" in status:
                    hint = (
                        " The cluster API key was accepted by Elasticsearch but Kibana rejected "
                        "the host-isolation call. Use a Kibana API key with Elastic Defend "
                        "response-action privileges, or set kibana_url on the cluster."
                    )
                raise IntegrationError(
                    f"Failed to {command} endpoint {agent_id}:{hint} {exc}"
                ) from exc
        if response is None:
            raise IntegrationError(f"Failed to {command} endpoint {agent_id}: {last_error}")
        data = response.get("data") if isinstance(response.get("data"), dict) else response
        return {
            "success": True,
            "provider": "elastic",
            "command": command,
            "endpoint_id": agent_id,
            "hostname": hostname,
            "action_id": data.get("id") or data.get("action_id") or data.get("action"),
            "status": data.get("status") or "pending",
            "comment": payload["comment"],
            "api_path": used,
            "action": data,
        }

    def _resolve_agent_id(
        self,
        endpoint_id: Optional[str],
        hostname: Optional[str],
    ) -> str:
        given = (endpoint_id or "").strip()
        host = (hostname or "").strip()
        if given and _AGENT_ID_RE.match(given):
            return given
        kibana = self._cases_http()
        needles = []
        for item in (given, host):
            if item and item not in needles:
                needles.append(item)
        for needle in needles:
            escaped = needle.replace("\\", "\\\\").replace('"', '\\"')
            kuery = (
                f'agent.id:"{escaped}" or host.name:"{escaped}" or host.hostname:"{escaped}"'
            )
            try:
                meta = kibana.get(
                    "/api/endpoint/metadata",
                    params={"page": 0, "pageSize": 5, "kuery": kuery},
                )
            except IntegrationError as exc:
                logger.debug("Endpoint metadata lookup failed for %s: %s", needle, exc)
                continue
            agent_id = self._agent_id_from_metadata(meta)
            if agent_id:
                return agent_id
        if given:
            return given
        raise IntegrationError(
            f"Could not resolve an Elastic Agent id from endpoint_id={endpoint_id!r} "
            f"hostname={hostname!r}"
        )

    @staticmethod
    def _agent_id_from_metadata(meta: Dict[str, Any]) -> Optional[str]:
        rows = meta.get("data") or meta.get("hosts") or []
        if isinstance(rows, dict):
            rows = [rows]
        for row in rows:
            if not isinstance(row, dict):
                continue
            metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else row
            agent = metadata.get("agent") if isinstance(metadata.get("agent"), dict) else {}
            host = metadata.get("host") if isinstance(metadata.get("host"), dict) else {}
            for candidate in (
                agent.get("id"),
                row.get("agent_id"),
                host.get("id"),
                metadata.get("elastic.agent.id"),
            ):
                if candidate:
                    return str(candidate)
        return None

    def close_alert(
        self,
        alert_id: str,
        reason: Optional[str] = None,
        comment: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Set verdict for an alert in Elasticsearch (FP, TP, etc.).
        
        Updates signal.ai.verdict with the reason instead of closing the alert.
        The reason should be one of: "false_positive", "benign_true_positive", "true_positive", etc.
        """
        try:
            # First, find the alert to get its index
            query = {
                "query": {
                    "term": {"_id": alert_id}
                }
            }
            
            # Search with fallback index patterns
            indices_patterns = [
                "alerts-*,.siem-signals-*,logs-endpoint.alerts-*",
                "alerts-*",
                "_all",  # Fallback to all indices if specific patterns fail
            ]
            response = self._search_with_fallback(indices_patterns, query)
            
            hits = response.get("hits", {}).get("hits", [])
            if not hits:
                raise IntegrationError(f"Alert {alert_id} not found")
            
            hit = hits[0]
            index_name = hit.get("_index")
            if not index_name:
                raise IntegrationError(f"Could not determine index for alert {alert_id}")
            
            # Normalize reason to verdict format
            verdict = reason or "false_positive"
            # Map common reason values to verdict format
            if verdict in ["FP", "fp", "false_positive"]:
                verdict = "false_positive"
            elif verdict in ["BTP", "btp", "benign_true_positive"]:
                verdict = "benign_true_positive"
            elif verdict in ["TP", "tp", "true_positive"]:
                verdict = "true_positive"
            elif verdict in ["in-progress", "in_progress", "inprogress", "investigating"]:
                verdict = "in-progress"
            
            # Build update document using script for nested signal.ai object
            script_update = {
                "script": {
                    "source": """
                        if (ctx._source.signal == null) {
                            ctx._source.signal = [:];
                        }
                        if (ctx._source.signal.ai == null) {
                            ctx._source.signal.ai = [:];
                        }
                        ctx._source.signal.ai.verdict = params.verdict;
                        ctx._source.signal.ai.verdict_at = params.timestamp;
                    """,
                    "lang": "painless",
                    "params": {
                        "verdict": verdict,
                        "timestamp": datetime.utcnow().isoformat() + "Z"
                    }
                }
            }
            
            # If comment is provided, also add it to signal.ai.comments.comment
            if comment:
                # Get existing comments first
                source = hit.get("_source", {})
                existing_comments = []
                signal = source.get("signal", {})
                if isinstance(signal, dict):
                    signal_ai = signal.get("ai", {})
                    if isinstance(signal_ai, dict):
                        ai_comments = signal_ai.get("comments", {})
                        if isinstance(ai_comments, dict):
                            ai_comment = ai_comments.get("comment")
                            if isinstance(ai_comment, list):
                                existing_comments = list(ai_comment)
                            elif ai_comment:
                                existing_comments = [ai_comment]
                
                # Add the new comment
                new_note = {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "comment": comment,
                    "author": "sami-gpt",
                }
                existing_comments.append(new_note)
                
                # Update script to also set comments
                script_update["script"]["source"] = """
                    if (ctx._source.signal == null) {
                        ctx._source.signal = [:];
                    }
                    if (ctx._source.signal.ai == null) {
                        ctx._source.signal.ai = [:];
                    }
                    if (ctx._source.signal.ai.comments == null) {
                        ctx._source.signal.ai.comments = [:];
                    }
                    ctx._source.signal.ai.verdict = params.verdict;
                    ctx._source.signal.ai.verdict_at = params.timestamp;
                    ctx._source.signal.ai.comments.comment = params.comments;
                """
                script_update["script"]["params"]["comments"] = existing_comments
            
            # Update the alert using Elasticsearch update API
            update_response = self._http.post(
                f"/{index_name}/_update/{alert_id}?refresh=wait_for",
                json_data=script_update
            )
            
            # Verify the update was successful
            if update_response.get("result") not in ["updated", "noop"]:
                logger.warning(f"Unexpected update result: {update_response.get('result')}")
            
            # Check for errors in the response
            if "error" in update_response:
                error_msg = update_response.get("error", {})
                logger.error(f"Elasticsearch update error: {error_msg}")
                raise IntegrationError(f"Failed to update alert: {error_msg}")
            
            # Get updated alert details
            updated_alert = self.get_security_alert_by_id(alert_id, include_detections=False)
            
            return {
                "success": True,
                "alert_id": alert_id,
                "verdict": verdict,
                "comment": comment,
                "alert": updated_alert,
            }
        except IntegrationError:
            raise
        except Exception as e:
            logger.exception(f"Error setting verdict for alert {alert_id}: {e}")
            raise IntegrationError(f"Failed to set verdict for alert: {e}") from e

    def update_alert_verdict(
        self,
        alert_id: str,
        verdict: str,
        comment: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Update the verdict for an alert in Elasticsearch.
        
        This method sets or updates the signal.ai.verdict field. The verdict can be:
        - "in-progress": Alert is being investigated
        - "false_positive": Alert is a false positive
        - "benign_true_positive": Alert is a benign true positive
        - "true_positive": Alert is a true positive requiring investigation
        - "uncertain": Alert legitimacy cannot be determined with available information
        
        Args:
            alert_id: The ID of the alert to update
            verdict: The verdict value to set
            comment: Optional comment to add to the alert
            
        Returns:
            Dictionary with success status, alert_id, verdict, and updated alert details
        """
        try:
            # First, find the alert to get its index
            query = {
                "query": {
                    "term": {"_id": alert_id}
                }
            }
            
            # Search with fallback index patterns
            indices_patterns = [
                "alerts-*,.siem-signals-*,logs-endpoint.alerts-*",
                "alerts-*",
                "_all",  # Fallback to all indices if specific patterns fail
            ]
            response = self._search_with_fallback(indices_patterns, query)
            
            hits = response.get("hits", {}).get("hits", [])
            if not hits:
                raise IntegrationError(f"Alert {alert_id} not found")
            
            hit = hits[0]
            index_name = hit.get("_index")
            if not index_name:
                raise IntegrationError(f"Could not determine index for alert {alert_id}")
            
            # Normalize verdict to standard format
            verdict_normalized = verdict.lower().strip()
            # Map common verdict values to standard format
            if verdict_normalized in ["fp", "false_positive", "false-positive"]:
                verdict_normalized = "false_positive"
            elif verdict_normalized in ["btp", "benign_true_positive", "benign-true-positive"]:
                verdict_normalized = "benign_true_positive"
            elif verdict_normalized in ["tp", "true_positive", "true-positive"]:
                verdict_normalized = "true_positive"
            elif verdict_normalized in ["in-progress", "in_progress", "inprogress", "investigating"]:
                verdict_normalized = "in-progress"
            elif verdict_normalized in ["uncertain", "unknown", "unclear", "needs_more_investigation"]:
                verdict_normalized = "uncertain"
            else:
                # Use the provided verdict as-is if it doesn't match known patterns
                verdict_normalized = verdict
            
            # Build update document using script for nested signal.ai object
            script_update = {
                "script": {
                    "source": """
                        if (ctx._source.signal == null) {
                            ctx._source.signal = [:];
                        }
                        if (ctx._source.signal.ai == null) {
                            ctx._source.signal.ai = [:];
                        }
                        ctx._source.signal.ai.verdict = params.verdict;
                        ctx._source.signal.ai.verdict_at = params.timestamp;
                    """,
                    "lang": "painless",
                    "params": {
                        "verdict": verdict_normalized,
                        "timestamp": datetime.utcnow().isoformat() + "Z"
                    }
                }
            }
            
            # If comment is provided, also add it to signal.ai.comments.comment
            if comment:
                # Get existing comments first
                source = hit.get("_source", {})
                existing_comments = []
                signal = source.get("signal", {})
                if isinstance(signal, dict):
                    signal_ai = signal.get("ai", {})
                    if isinstance(signal_ai, dict):
                        ai_comments = signal_ai.get("comments", {})
                        if isinstance(ai_comments, dict):
                            ai_comment = ai_comments.get("comment")
                            if isinstance(ai_comment, list):
                                existing_comments = list(ai_comment)
                            elif ai_comment:
                                existing_comments = [ai_comment]
                
                # Add the new comment
                new_note = {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "comment": comment,
                    "author": "sami-gpt",
                }
                existing_comments.append(new_note)
                
                # Update script to also set comments
                script_update["script"]["source"] = """
                    if (ctx._source.signal == null) {
                        ctx._source.signal = [:];
                    }
                    if (ctx._source.signal.ai == null) {
                        ctx._source.signal.ai = [:];
                    }
                    if (ctx._source.signal.ai.comments == null) {
                        ctx._source.signal.ai.comments = [:];
                    }
                    ctx._source.signal.ai.verdict = params.verdict;
                    ctx._source.signal.ai.verdict_at = params.timestamp;
                    ctx._source.signal.ai.comments.comment = params.comments;
                """
                script_update["script"]["params"]["comments"] = existing_comments
            
            # Update the alert using Elasticsearch update API
            update_response = self._http.post(
                f"/{index_name}/_update/{alert_id}?refresh=wait_for",
                json_data=script_update
            )
            
            # Verify the update was successful
            if update_response.get("result") not in ["updated", "noop"]:
                logger.warning(f"Unexpected update result: {update_response.get('result')}")
            
            # Check for errors in the response
            if "error" in update_response:
                error_msg = update_response.get("error", {})
                logger.error(f"Elasticsearch update error: {error_msg}")
                raise IntegrationError(f"Failed to update alert verdict: {error_msg}")
            
            # Get updated alert details
            updated_alert = self.get_security_alert_by_id(alert_id, include_detections=False)
            
            return {
                "success": True,
                "alert_id": alert_id,
                "verdict": verdict_normalized,
                "comment": comment,
                "alert": updated_alert,
            }
        except IntegrationError:
            raise
        except Exception as e:
            logger.exception(f"Error updating verdict for alert {alert_id}: {e}")
            raise IntegrationError(f"Failed to update alert verdict: {e}") from e

    def tag_alert(
        self,
        alert_id: str,
        tag: str,
    ) -> Dict[str, Any]:
        """
        Tag an alert with a classification tag (FP, TP, or NMI).
        
        Updates the alert with the specified tag, adding it to existing tags if present.
        Valid tags are: FP (False Positive), TP (True Positive), NMI (Need More Investigation).
        """
        try:
            # Validate tag
            valid_tags = {"FP", "TP", "NMI"}
            tag_upper = tag.upper()
            if tag_upper not in valid_tags:
                raise IntegrationError(
                    f"Invalid tag '{tag}'. Must be one of: FP (False Positive), "
                    f"TP (True Positive), or NMI (Need More Investigation)"
                )
            
            # First, find the alert to get its index and current tags
            query = {
                "query": {
                    "term": {"_id": alert_id}
                }
            }
            
            # Search with fallback index patterns
            indices_patterns = [
                "alerts-*,.siem-signals-*,logs-endpoint.alerts-*",
                "alerts-*",
                "_all",  # Fallback to all indices if specific patterns fail
            ]
            response = self._search_with_fallback(indices_patterns, query)
            
            hits = response.get("hits", {}).get("hits", [])
            if not hits:
                raise IntegrationError(f"Alert {alert_id} not found")
            
            hit = hits[0]
            index_name = hit.get("_index")
            if not index_name:
                raise IntegrationError(f"Could not determine index for alert {alert_id}")
            
            source = hit.get("_source", {})
            
            # Get existing tags from signal.ai.tags
            existing_tags = []
            signal = source.get("signal", {})
            if isinstance(signal, dict):
                signal_ai = signal.get("ai", {})
                if isinstance(signal_ai, dict):
                    ai_tags = signal_ai.get("tags")
                    if isinstance(ai_tags, list):
                        existing_tags = list(ai_tags)
                    elif ai_tags:
                        existing_tags = [ai_tags]
            
            # Remove duplicates and ensure tag is added
            existing_tags = list(set(existing_tags))
            
            # Remove any existing classification tags (FP, TP, NMI) to avoid duplicates
            classification_tags = {"FP", "TP", "NMI"}
            existing_tags = [t for t in existing_tags if t.upper() not in classification_tags]
            
            # Add the new tag
            existing_tags.append(tag_upper)
            
            # Build update document using script for nested signal.ai object
            script_update = {
                "script": {
                    "source": """
                        if (ctx._source.signal == null) {
                            ctx._source.signal = [:];
                        }
                        if (ctx._source.signal.ai == null) {
                            ctx._source.signal.ai = [:];
                        }
                        ctx._source.signal.ai.tags = params.tags;
                        ctx._source.signal.ai.tagged_at = params.timestamp;
                    """,
                    "lang": "painless",
                    "params": {
                        "tags": existing_tags,
                        "timestamp": datetime.utcnow().isoformat() + "Z"
                    }
                }
            }
            
            # Update the alert using Elasticsearch update API
            update_response = self._http.post(
                f"/{index_name}/_update/{alert_id}?refresh=wait_for",
                json_data=script_update
            )
            
            # Verify the update was successful
            if update_response.get("result") not in ["updated", "noop"]:
                logger.warning(f"Unexpected update result: {update_response.get('result')}")
            
            # Check for errors in the response
            if "error" in update_response:
                error_msg = update_response.get("error", {})
                logger.error(f"Elasticsearch update error: {error_msg}")
                raise IntegrationError(f"Failed to update alert: {error_msg}")
            
            # Get updated alert details
            updated_alert = self.get_security_alert_by_id(alert_id, include_detections=False)
            
            return {
                "success": True,
                "alert_id": alert_id,
                "tag": tag_upper,
                "tags": existing_tags,
                "alert": updated_alert,
            }
        except IntegrationError:
            raise
        except Exception as e:
            logger.exception(f"Error tagging alert {alert_id}: {e}")
            raise IntegrationError(f"Failed to tag alert: {e}") from e

    @staticmethod
    def _normalize_alert_note(raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize a Kibana Security Solution note into a stable skill shape."""

        def _epoch_ms_to_iso(value: Any) -> Optional[str]:
            if value is None or value == "":
                return None
            try:
                ms = int(value)
                return datetime.utcfromtimestamp(ms / 1000.0).isoformat() + "Z"
            except (TypeError, ValueError, OSError, OverflowError):
                return str(value)

        created = raw.get("created")
        updated = raw.get("updated")
        return {
            "note_id": raw.get("noteId") or raw.get("note_id") or raw.get("id"),
            "note": raw.get("note") or "",
            "event_id": raw.get("eventId") or raw.get("event_id") or "",
            "timeline_id": raw.get("timelineId") if "timelineId" in raw else raw.get("timeline_id", ""),
            "created": created,
            "created_iso": _epoch_ms_to_iso(created),
            "created_by": raw.get("createdBy") or raw.get("created_by") or "",
            "updated": updated,
            "updated_iso": _epoch_ms_to_iso(updated),
            "updated_by": raw.get("updatedBy") or raw.get("updated_by") or "",
            "version": raw.get("version"),
        }

    def get_alert_notes(
        self,
        alert_id: Optional[str] = None,
        alert_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Fetch Security Solution / Rule Tuner alert notes from Kibana.

        Notes live in the Kibana Notes API (``GET /api/note?documentIds=...``),
        not on the alert ``_source``. ``documentIds`` is the alert Elasticsearch
        ``_id`` (same as ``kibana.alert.uuid`` / Rule Tuner ``alert.id``).
        """
        ids: List[str] = []
        if alert_ids:
            for value in alert_ids:
                text = str(value or "").strip()
                if text and text not in ids:
                    ids.append(text)
        if alert_id:
            text = str(alert_id).strip()
            if text and text not in ids:
                ids.append(text)
        if not ids:
            raise IntegrationError(
                "get_alert_notes requires alert_id or alert_ids "
                "(Elasticsearch _id / kibana.alert.uuid)"
            )

        kibana = self._cases_http()
        try:
            response = kibana.get(
                "/api/note",
                params={"documentIds": ids},
                extra_headers={"Elastic-Api-Version": "2023-10-31"},
            )
        except IntegrationError:
            raise
        except Exception as e:
            logger.exception("Error fetching alert notes for %s: %s", ids, e)
            raise IntegrationError(f"Failed to fetch alert notes: {e}") from e

        raw_notes = response.get("notes") if isinstance(response, dict) else None
        if not isinstance(raw_notes, list):
            raw_notes = []

        notes = [
            self._normalize_alert_note(item)
            for item in raw_notes
            if isinstance(item, dict)
        ]
        # Prefer document (alert-flyout) notes; timeline notes still returned.
        notes.sort(
            key=lambda n: (
                0 if not (n.get("timeline_id") or "") else 1,
                -(int(n["created"]) if str(n.get("created") or "").isdigit() else 0),
            )
        )

        total_count = response.get("totalCount") if isinstance(response, dict) else None
        if not isinstance(total_count, int):
            total_count = len(notes)

        return {
            "success": True,
            "alert_ids": ids,
            "total_count": total_count,
            "notes": notes,
            "note_texts": [n.get("note", "") for n in notes if n.get("note")],
        }

    def add_alert_note(
        self,
        alert_id: str,
        note: str,
    ) -> Dict[str, Any]:
        """
        Add a note/comment to an alert in Elasticsearch.
        
        Adds the note to the alert's comments array and also stores it
        in a dedicated notes field for easy retrieval.
        """
        try:
            # First, find the alert to get its index
            query = {
                "query": {
                    "term": {"_id": alert_id}
                }
            }
            
            # Search with fallback index patterns
            indices_patterns = [
                "alerts-*,.siem-signals-*,logs-endpoint.alerts-*",
                "alerts-*",
                "_all",  # Fallback to all indices if specific patterns fail
            ]
            response = self._search_with_fallback(indices_patterns, query)
            
            hits = response.get("hits", {}).get("hits", [])
            if not hits:
                raise IntegrationError(f"Alert {alert_id} not found")
            
            hit = hits[0]
            index_name = hit.get("_index")
            if not index_name:
                raise IntegrationError(f"Could not determine index for alert {alert_id}")
            
            source = hit.get("_source", {})
            
            # Get existing comments from signal.ai.comments.comment
            existing_comments = []
            signal = source.get("signal", {})
            if isinstance(signal, dict):
                signal_ai = signal.get("ai", {})
                if isinstance(signal_ai, dict):
                    ai_comments = signal_ai.get("comments", {})
                    if isinstance(ai_comments, dict):
                        ai_comment = ai_comments.get("comment")
                        if isinstance(ai_comment, list):
                            existing_comments = list(ai_comment)
                        elif ai_comment:
                            existing_comments = [ai_comment]
            
            # Remove duplicates based on comment text and timestamp
            seen_comments = set()
            unique_comments = []
            for comment in existing_comments:
                if isinstance(comment, dict):
                    comment_key = (comment.get("comment", ""), comment.get("timestamp", ""))
                else:
                    comment_key = (str(comment), "")
                if comment_key not in seen_comments:
                    seen_comments.add(comment_key)
                    unique_comments.append(comment)
            
            # Add the new note
            new_note = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "comment": note,
                "author": "sami-gpt",
            }
            unique_comments.append(new_note)
            
            # Build update document using script for nested fields
            # Script updates are more reliable for nested structures in Elasticsearch
            logger.debug(f"Updating alert {alert_id} with {len(unique_comments)} comments using script update")
            
            # Use script update to handle nested signal.ai object properly
            script_update = {
                "script": {
                    "source": """
                        if (ctx._source.signal == null) {
                            ctx._source.signal = [:];
                        }
                        if (ctx._source.signal.ai == null) {
                            ctx._source.signal.ai = [:];
                        }
                        if (ctx._source.signal.ai.comments == null) {
                            ctx._source.signal.ai.comments = [:];
                        }
                        ctx._source.signal.ai.comments.comment = params.comments;
                    """,
                    "lang": "painless",
                    "params": {
                        "comments": unique_comments,
                        "timestamp": datetime.utcnow().isoformat() + "Z"
                    }
                }
            }
            
            # Update the alert using Elasticsearch update API with script
            # Add refresh=wait_for to ensure the update is immediately visible
            update_response = self._http.post(
                f"/{index_name}/_update/{alert_id}?refresh=wait_for",
                json_data=script_update
            )
            
            # Log the response for debugging
            logger.debug(f"Update response for alert {alert_id}: {update_response.get('result')}")
            
            # Verify the update was successful
            if update_response.get("result") not in ["updated", "noop"]:
                logger.warning(f"Unexpected update result: {update_response.get('result')}")
                logger.warning(f"Update response: {update_response}")
            
            # Check for errors in the response
            if "error" in update_response:
                error_msg = update_response.get("error", {})
                logger.error(f"Elasticsearch update error: {error_msg}")
                raise IntegrationError(f"Failed to update alert: {error_msg}")
            else:
                logger.info(f"Script update successful for alert {alert_id}")
            
            # Verify the update by directly fetching the document
            try:
                verify_response = self._http.get(f"/{index_name}/_doc/{alert_id}")
                if verify_response.get("found"):
                    verified_source = verify_response.get("_source", {})
                    verified_signal = verified_source.get("signal", {})
                    verified_ai = verified_signal.get("ai", {})
                    verified_comments_obj = verified_ai.get("comments", {})
                    verified_comments = verified_comments_obj.get("comment", [])
                    if not isinstance(verified_comments, list):
                        verified_comments = [verified_comments] if verified_comments else []
                    logger.debug(f"Verified: Document has {len(verified_comments)} comments in signal.ai.comments.comment")
                    if not verified_comments:
                        logger.warning(f"Update reported success but no comments found in verified document")
            except Exception as e:
                logger.warning(f"Could not verify update: {e}")
            
            # Get updated alert details
            updated_alert = self.get_security_alert_by_id(alert_id, include_detections=False)
            
            return {
                "success": True,
                "alert_id": alert_id,
                "note": note,
                "alert": updated_alert,
            }
        except IntegrationError:
            raise
        except Exception as e:
            logger.exception(f"Error adding note to alert {alert_id}: {e}")
            raise IntegrationError(f"Failed to add note to alert: {e}") from e

    # Entity & Intelligence Methods

    def lookup_entity(
        self,
        entity_value: str,
        entity_type: Optional[str] = None,
        hours_back: int = 24,
    ) -> Dict[str, Any]:
        """Look up an entity (IP, domain, hash, user, etc.) for enrichment."""
        try:
            # Auto-detect entity type if not provided
            if not entity_type:
                entity_type = self._detect_entity_type(entity_value)
            
            # Use pivot_on_indicator to get events
            result = self.pivot_on_indicator(entity_value, limit=100)
            
            # Extract summary information
            first_seen = None
            last_seen = None
            event_count = result.total_count
            related_alerts = []
            related_entities = set()
            
            if result.events:
                timestamps = [e.timestamp for e in result.events if e.timestamp]
                if timestamps:
                    first_seen = min(timestamps)
                    last_seen = max(timestamps)
                
                # Extract related entities
                for event in result.events:
                    if event.host:
                        related_entities.add(f"host:{event.host}")
                    if event.username:
                        related_entities.add(f"user:{event.username}")
                    if event.ip:
                        related_entities.add(f"ip:{event.ip}")
                    if event.file_hash:
                        related_entities.add(f"hash:{event.file_hash}")
            
            # Build summary
            summary = f"Entity {entity_value} ({entity_type}): Found {event_count} events"
            if first_seen:
                summary += f" from {first_seen.isoformat()} to {last_seen.isoformat() if last_seen else 'now'}"
            
            return {
                "entity_value": entity_value,
                "entity_type": entity_type,
                "summary": summary,
                "first_seen": first_seen.isoformat() if first_seen else None,
                "last_seen": last_seen.isoformat() if last_seen else None,
                "event_count": event_count,
                "reputation": None,
                "related_alerts": related_alerts,
                "related_entities": list(related_entities),
            }
        except Exception as e:
            logger.exception(f"Error looking up entity: {e}")
            raise IntegrationError(f"Failed to lookup entity: {e}") from e

    def get_ioc_matches(
        self,
        hours_back: int = 24,
        max_matches: int = 20,
        ioc_type: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get Indicators of Compromise (IoC) matches from Elasticsearch.
        
        This method is selective and only returns actual threat indicators:
        - Threat intelligence indicators (threat.indicator field)
        - File hashes with malicious indicators
        - IP addresses that are in threat feeds or have malicious indicators
        - Excludes private/internal IP addresses (RFC 1918)
        """
        import ipaddress
        
        def is_private_ip(ip_str: str) -> bool:
            """Check if an IP address is private/internal (RFC 1918)."""
            try:
                ip = ipaddress.ip_address(ip_str)
                return ip.is_private or ip.is_loopback or ip.is_link_local
            except (ValueError, AttributeError):
                return False
        
        def is_malicious_indicator(source: Dict[str, Any]) -> bool:
            """Check if an event contains actual malicious indicators."""
            threat = source.get("threat", {})
            
            # Check for threat intelligence indicators
            if threat.get("indicator"):
                # Check if it's marked as malicious
                threat_type = threat.get("framework", "").lower()
                threat_ind = threat.get("indicator", {})
                if isinstance(threat_ind, dict):
                    if threat_ind.get("type") == "malicious" or "malicious" in threat_type:
                        return True
                # If threat.indicator exists, it's likely from a threat feed
                return True
            
            # Check for malicious file indicators
            file = source.get("file", {})
            if file.get("hash"):
                # Check if file is marked as malicious
                if file.get("type") == "malicious" or file.get("malware_classification"):
                    return True
            
            # Check for threat.enrichments (Elastic Security threat intel)
            if threat.get("enrichments"):
                return True
            
            # Check for event.category related to threats
            event = source.get("event", {})
            if event.get("category") in ["threat", "malware", "intrusion_detection"]:
                return True
            
            return False
        
        try:
            # Build query that prioritizes actual threat indicators
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"@timestamp": {"gte": f"now-{hours_back}h"}}},
                            {
                                "bool": {
                                    "should": [
                                        # Priority 1: Explicit threat indicators
                                        {"exists": {"field": "threat.indicator"}},
                                        {"exists": {"field": "threat.enrichments"}},
                                        # Priority 2: Malicious file hashes
                                        {
                                            "bool": {
                                                "must": [
                                                    {"exists": {"field": "file.hash"}},
                                                    {
                                                        "bool": {
                                                            "should": [
                                                                {"term": {"file.type": "malicious"}},
                                                                {"exists": {"field": "file.malware_classification"}},
                                                                {"exists": {"field": "threat.framework"}},
                                                            ]
                                                        }
                                                    }
                                                ]
                                            }
                                        },
                                        # Priority 3: IPs with threat indicators (but we'll filter private IPs)
                                        {
                                            "bool": {
                                                "must": [
                                                    {
                                                        "bool": {
                                                            "should": [
                                                                {"exists": {"field": "source.ip"}},
                                                                {"exists": {"field": "destination.ip"}},
                                                            ]
                                                        }
                                                    },
                                                    {
                                                        "bool": {
                                                            "should": [
                                                                {"exists": {"field": "threat.indicator.ip"}},
                                                                {"exists": {"field": "threat.enrichments"}},
                                                                {"term": {"event.category": "threat"}},
                                                                {"term": {"event.category": "malware"}},
                                                            ]
                                                        }
                                                    }
                                                ]
                                            }
                                        },
                                    ],
                                    "minimum_should_match": 1
                                }
                            }
                        ]
                    }
                },
                "size": max_matches * 3,  # Get more results to filter
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
            
            if ioc_type:
                if ioc_type == "ip":
                    # For IPs, require threat indicators
                    query["query"]["bool"]["must"][1]["bool"]["should"] = [
                        {"exists": {"field": "threat.indicator.ip"}},
                        {"exists": {"field": "threat.enrichments"}},
                    ]
                elif ioc_type == "hash":
                    query["query"]["bool"]["must"][1]["bool"]["should"] = [
                        {
                            "bool": {
                                "must": [
                                    {"exists": {"field": "file.hash"}},
                                    {
                                        "bool": {
                                            "should": [
                                                {"term": {"file.type": "malicious"}},
                                                {"exists": {"field": "file.malware_classification"}},
                                                {"exists": {"field": "threat.framework"}},
                                            ]
                                        }
                                    }
                                ]
                            }
                        }
                    ]
                elif ioc_type == "domain":
                    query["query"]["bool"]["must"][1]["bool"]["should"] = [
                        {"exists": {"field": "threat.indicator.domain"}},
                        {"exists": {"field": "dns.question.name"}},
                    ]
            
            if severity:
                query["query"]["bool"]["must"].append({"match": {"event.severity": severity}})
            
            # Search with fallback index patterns
            indices_patterns = [
                "logs-*,security-*,winlogbeat-*,filebeat-*",
                "_all",  # Fallback to all indices if specific patterns fail
            ]
            response = self._search_with_fallback(indices_patterns, query)
            
            hits = response.get("hits", {}).get("hits", [])
            matches = []
            seen_indicators = set()
            
            for hit in hits:
                source = hit.get("_source", {})
                
                # Extract IoC - prioritize threat indicators
                indicator = None
                ioc_type_detected = None
                is_malicious = False
                
                # Priority 1: Threat intelligence indicators
                threat = source.get("threat", {})
                if threat.get("indicator"):
                    threat_ind = threat.get("indicator", {})
                    if isinstance(threat_ind, dict):
                        # Extract from threat.indicator object
                        indicator = threat_ind.get("ip") or threat_ind.get("domain") or threat_ind.get("file", {}).get("hash", {}).get("sha256")
                        # If threat.indicator exists, it's from a threat feed - consider it malicious
                        is_malicious = True
                    elif isinstance(threat_ind, str):
                        indicator = threat_ind
                        is_malicious = True
                    ioc_type_detected = "threat_indicator"
                
                # Also check threat.enrichments (Elastic Security threat intel)
                if not indicator and threat.get("enrichments"):
                    # Extract IP from enrichments
                    enrichments = threat.get("enrichments", [])
                    for enrichment in enrichments:
                        if isinstance(enrichment, dict):
                            indicator = enrichment.get("indicator", {}).get("ip") or enrichment.get("indicator", {}).get("domain")
                            if indicator:
                                is_malicious = True
                                ioc_type_detected = "threat_indicator"
                                break
                
                # Priority 2: File hashes with malicious indicators
                if not indicator:
                    file = source.get("file", {})
                    file_hash = file.get("hash", {})
                    if isinstance(file_hash, dict):
                        hash_value = file_hash.get("sha256") or file_hash.get("md5") or file_hash.get("sha1")
                    elif isinstance(file_hash, str):
                        hash_value = file_hash
                    else:
                        hash_value = None
                    
                    if hash_value and (file.get("type") == "malicious" or file.get("malware_classification") or threat.get("framework")):
                        indicator = hash_value
                        ioc_type_detected = "hash"
                        is_malicious = True
                
                # Priority 3: IP addresses from threat feeds (exclude private IPs)
                if not indicator:
                    source_ip = source.get("source", {}).get("ip")
                    dest_ip = source.get("destination", {}).get("ip")
                    
                    # Check if IP has threat indicators
                    if source_ip and not is_private_ip(source_ip) and is_malicious_indicator(source):
                        indicator = source_ip
                        ioc_type_detected = "ip"
                        is_malicious = True
                    elif dest_ip and not is_private_ip(dest_ip) and is_malicious_indicator(source):
                        indicator = dest_ip
                        ioc_type_detected = "ip"
                        is_malicious = True
                
                # Only include if we found an indicator and it's marked as malicious or from threat feed
                if indicator and indicator not in seen_indicators and is_malicious:
                    seen_indicators.add(indicator)
                    matches.append({
                        "indicator": indicator,
                        "ioc_type": ioc_type_detected or ioc_type or "unknown",
                        "first_seen": source.get("@timestamp", ""),
                        "last_seen": source.get("@timestamp", ""),
                        "match_count": 1,
                        "severity": source.get("event", {}).get("severity", "medium"),
                        "source": "elastic",
                        "affected_hosts": [source.get("host", {}).get("name")] if source.get("host", {}).get("name") else [],
                    })
            
            # Return top matches sorted by severity (if available)
            matches.sort(key=lambda x: {
                "critical": 4,
                "high": 3,
                "medium": 2,
                "low": 1
            }.get(x.get("severity", "medium").lower(), 0), reverse=True)
            
            return matches[:max_matches]
        except Exception as e:
            logger.exception(f"Error getting IoC matches: {e}")
            raise IntegrationError(f"Failed to get IoC matches: {e}") from e

    def get_threat_intel(
        self,
        query: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Get threat intelligence answers."""
        try:
            answer = f"Threat intelligence query: {query}\n\n"
            
            if context:
                for key, value in context.items():
                    if isinstance(value, str):
                        try:
                            entity_info = self.lookup_entity(value, hours_back=168)
                            answer += f"\n{key} ({value}): {entity_info.get('summary', 'No information found')}\n"
                        except Exception:
                            pass
            
            answer += "\nNote: Full threat intelligence integration requires additional threat intelligence feeds or AI models."
            
            return {
                "query": query,
                "answer": answer,
                "sources": ["elasticsearch"],
                "confidence": "medium",
            }
        except Exception as e:
            logger.exception(f"Error getting threat intelligence: {e}")
            raise IntegrationError(f"Failed to get threat intelligence: {e}") from e

    # Detection Rule Management Methods

    def list_security_rules(
        self,
        enabled_only: bool = False,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """List security detection rules configured in Elasticsearch."""
        try:
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"exists": {"field": "rule"}}
                        ]
                    }
                },
                "size": limit
            }
            
            if enabled_only:
                query["query"]["bool"]["must"].append({"term": {"enabled": True}})
            
            # Search with fallback index patterns
            indices_patterns = [
                ".siem-signals-*,alerts-*",
                "alerts-*",
                "_all",  # Fallback to all indices if specific patterns fail
            ]
            response = self._search_with_fallback(indices_patterns, query)
            
            hits = response.get("hits", {}).get("hits", [])
            rules = []
            seen_rules = {}
            
            for hit in hits:
                source = hit.get("_source", {})
                signal = source.get("signal", {})
                rule = signal.get("rule", {}) if isinstance(signal.get("rule"), dict) else {}
                
                rule_id = rule.get("id") or rule.get("rule_id") or hit.get("_id", "")
                if rule_id and rule_id not in seen_rules:
                    seen_rules[rule_id] = True
                    rules.append({
                        "id": rule_id,
                        "name": rule.get("name", ""),
                        "description": rule.get("description", ""),
                        "enabled": True,
                        "severity": rule.get("severity", "medium"),
                        "category": rule.get("category", ""),
                        "created_at": source.get("@timestamp", ""),
                        "updated_at": source.get("@timestamp", ""),
                    })
            
            return rules[:limit]
        except Exception as e:
            logger.exception(f"Error listing security rules: {e}")
            raise IntegrationError(f"Failed to list security rules: {e}") from e

    def search_security_rules(
        self,
        query: str,
        category: Optional[str] = None,
        enabled_only: bool = False,
    ) -> List[Dict[str, Any]]:
        """Search for security detection rules."""
        try:
            all_rules = self.list_security_rules(enabled_only=enabled_only, limit=1000)
            
            import re
            pattern = re.compile(query, re.IGNORECASE)
            matching_rules = []
            
            for rule in all_rules:
                if pattern.search(rule.get("name", "")) or pattern.search(rule.get("description", "")):
                    if not category or rule.get("category", "").lower() == category.lower():
                        matching_rules.append(rule)
            
            return matching_rules
        except Exception as e:
            logger.exception(f"Error searching security rules: {e}")
            raise IntegrationError(f"Failed to search security rules: {e}") from e

    def get_rule_detections(
        self,
        rule_id: Optional[str] = None,
        alert_state: Optional[str] = None,
        hours_back: int = 24,
        limit: int = 50,
        rule_name: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get historical detections from a specific rule by ID and/or name.

        Unlike ``get_security_alerts``, this always includes investigated/closed
        alerts so analysts can review past firings. Filter with ``alert_state``
        (``open``, ``acknowledged``/``akn``, ``closed``).
        """
        if not rule_id and not rule_name:
            raise IntegrationError("get_rule_detections requires rule_id and/or rule_name")

        try:
            alert_state = self._normalize_alert_status(alert_state)
            must_clauses: List[Dict[str, Any]] = [
                {"range": {"@timestamp": {"gte": f"now-{hours_back}h"}}}
            ]

            rule_clauses: List[Dict[str, Any]] = []
            if rule_id:
                rule_clauses.append(self._alert_rule_id_clause(rule_id))
            if rule_name:
                rule_clauses.append(self._alert_rule_name_clause(rule_name))

            if len(rule_clauses) == 1:
                must_clauses.append(rule_clauses[0])
            else:
                # Both provided: match alerts that satisfy either identifier
                must_clauses.append({
                    "bool": {
                        "should": rule_clauses,
                        "minimum_should_match": 1,
                    }
                })

            if alert_state:
                must_clauses.append(self._alert_status_clause(alert_state))

            query = {
                "query": {"bool": {"must": must_clauses}},
                "size": limit,
                "sort": [{"@timestamp": {"order": "desc"}}],
            }

            response = self._search_with_fallback(_ALERT_INDEX_PATTERNS, query)
            hits = response.get("hits", {}).get("hits", [])
            detections = []

            for hit in hits:
                source = hit.get("_source", {})
                signal = source.get("signal", {}) if isinstance(source.get("signal"), dict) else {}
                rule_fields = self._extract_rule_fields(source, signal)
                signal_ai = signal.get("ai", {}) if isinstance(signal.get("ai"), dict) else {}

                detections.append({
                    "id": hit.get("_id", ""),
                    "alert_id": hit.get("_id", ""),
                    "timestamp": source.get("@timestamp", ""),
                    "severity": signal.get("severity") or source.get("kibana.alert.severity", "medium"),
                    "status": signal.get("status") or source.get("kibana.alert.workflow_status", "open"),
                    "rule_name": rule_fields["rule_name"],
                    "rule_id": rule_fields["rule_id"],
                    "verdict": signal_ai.get("verdict"),
                    "description": self._extract_description_from_alert(source, signal),
                })

            return detections
        except IntegrationError:
            raise
        except Exception as e:
            logger.exception(f"Error getting rule detections: {e}")
            raise IntegrationError(f"Failed to get rule detections: {e}") from e

    def list_rule_errors(
        self,
        rule_id: str,
        hours_back: int = 24,
    ) -> List[Dict[str, Any]]:
        """List execution errors for a specific rule."""
        try:
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"@timestamp": {"gte": f"now-{hours_back}h"}}},
                            {"match": {"message": "error"}},
                            {
                                "bool": {
                                    "should": [
                                        {"match": {"rule_id": rule_id}},
                                        {"match": {"rule.id": rule_id}},
                                    ]
                                }
                            }
                        ]
                    }
                },
                "size": 100
            }
            
            # Search with fallback index patterns
            indices_patterns = [
                "logs-*,.siem-*",
                "_all",  # Fallback to all indices if specific patterns fail
            ]
            response = self._search_with_fallback(indices_patterns, query)
            
            hits = response.get("hits", {}).get("hits", [])
            errors = []
            
            for hit in hits:
                source = hit.get("_source", {})
                errors.append({
                    "timestamp": source.get("@timestamp", ""),
                    "error_type": "execution_error",
                    "error_message": source.get("message", ""),
                    "severity": "high",
                })
            
            return errors
        except Exception as e:
            logger.exception(f"Error listing rule errors: {e}")
            raise IntegrationError(f"Failed to list rule errors: {e}") from e

    # Helper Methods

    def _search_with_fallback(self, indices_patterns: List[str], query: Dict[str, Any]) -> Dict[str, Any]:
        """
        Search Elasticsearch with fallback index patterns.
        
        Tries each index pattern in order until one succeeds. If all fail, raises the last error.
        
        Args:
            indices_patterns: List of index patterns to try (e.g., ["logs-*", "_all"])
            query: Elasticsearch query dictionary
            
        Returns:
            Elasticsearch response dictionary
            
        Raises:
            IntegrationError: If all index patterns fail
        """
        response = None
        last_error = None
        
        for indices in indices_patterns:
            try:
                endpoint = f"/{indices}/_search"
                response = self._http.post(endpoint, json_data=query)
                break  # Success, exit loop
            except IntegrationError as e:
                last_error = e
                # If it's a 404 and we have more patterns to try, continue
                if "404" in str(e) and indices != indices_patterns[-1]:
                    logger.debug(f"Index pattern '{indices}' returned 404, trying next pattern...")
                    continue
                # For non-404 errors or if this is the last pattern, re-raise
                if indices == indices_patterns[-1]:
                    # Last pattern failed, provide helpful error message
                    logger.error(f"Failed to search Elasticsearch with all index patterns. Last error: {e}")
                    raise IntegrationError(
                        f"Failed to search Elasticsearch. Tried patterns: {indices_patterns}. "
                        f"Last error: {e}. "
                        f"This may indicate that the Elasticsearch API path is incorrect or the indices don't exist. "
                        f"Check your base_url configuration."
                    ) from e
                raise
        
        if response is None:
            raise IntegrationError(f"All index patterns failed. Last error: {last_error}") from last_error
        
        return response

    def _extract_description_from_alert(self, source: Dict[str, Any], signal: Dict[str, Any]) -> str:
        """
        Extract description from alert document, supporting multiple formats.
        
        Checks in order:
        1. signal.rule.description (Kibana alert format)
        2. kibana.alert.rule.parameters.description (Kibana alert format)
        3. kibana.alert.rule.description (Kibana alert format, flat key)
        4. rule.description (Endpoint detection format)
        """
        description = ""
        
        # Check signal.rule.description (Kibana alert format)
        if isinstance(signal.get("rule"), dict):
            description = signal.get("rule", {}).get("description", "")
        
        if not description:
            # Check kibana.alert.rule.parameters.description
            kibana_rule_params = source.get("kibana.alert.rule.parameters", {})
            if isinstance(kibana_rule_params, dict):
                description = kibana_rule_params.get("description", "")
        
        if not description:
            # Check kibana.alert.rule.description (flat key)
            description = source.get("kibana.alert.rule.description", "")
        
        if not description:
            # Check for endpoint detection format (rule.description directly on document)
            rule_obj = source.get("rule", {})
            if isinstance(rule_obj, dict):
                description = rule_obj.get("description", "")
        
        return description

    def _extract_entities_from_alert(self, source: Dict[str, Any]) -> List[str]:
        """Extract related entities from an alert source."""
        entities = []
        
        if source.get("source", {}).get("ip"):
            entities.append(f"ip:{source['source']['ip']}")
        if source.get("destination", {}).get("ip"):
            entities.append(f"ip:{source['destination']['ip']}")
        if source.get("dns", {}).get("question", {}).get("name"):
            entities.append(f"domain:{source['dns']['question']['name']}")
        if source.get("file", {}).get("hash", {}).get("sha256"):
            entities.append(f"hash:{source['file']['hash']['sha256']}")
        if source.get("user", {}).get("name"):
            entities.append(f"user:{source['user']['name']}")
        
        return entities

    def _detect_entity_type(self, value: str) -> str:
        """Auto-detect entity type from value."""
        import re
        
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        hash_pattern = r'^[a-fA-F0-9]{32,64}$'
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        
        if re.match(ip_pattern, value):
            return "ip"
        elif re.match(hash_pattern, value):
            return "hash"
        elif re.match(domain_pattern, value) and '.' in value:
            return "domain"
        else:
            return "user"

    def _severity_to_priority(self, severity: str) -> str:
        """Convert severity to priority."""
        mapping = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
        }
        return mapping.get(severity.lower(), "medium")

    def _severity_score_to_level(self, score: int) -> str:
        """Convert severity score (0-100) to level."""
        if score >= 75:
            return "critical"
        elif score >= 50:
            return "high"
        elif score >= 25:
            return "medium"
        else:
            return "low"

    # New SOC1 Tools - Network, DNS, Email Events, and Alert Correlation

    def get_network_events(
        self,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        port: Optional[int] = None,
        protocol: Optional[str] = None,
        hours_back: int = 24,
        limit: int = 100,
        event_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Retrieve network traffic events (firewall, netflow, proxy logs) with structured fields.
        
        Returns network events with source/destination IPs, ports, protocols, bytes, packets, and connection duration.
        """
        try:
            # Build Elasticsearch query for network events
            must_clauses = []
            
            # Time range
            must_clauses.append({"range": {"@timestamp": {"gte": f"now-{hours_back}h"}}})
            
            # Network event type filter
            if event_type and event_type != "all":
                if event_type == "firewall":
                    must_clauses.append({"match": {"event.category": "network"}})
                elif event_type == "netflow":
                    must_clauses.append({"match": {"event.dataset": "flow"}})
                elif event_type == "proxy":
                    must_clauses.append({"match": {"event.category": "web"}})
            
            # IP filters
            if source_ip:
                must_clauses.append({
                    "bool": {
                        "should": [
                            {"match": {"source.ip": source_ip}},
                            {"match": {"client.ip": source_ip}},
                        ]
                    }
                })
            
            if destination_ip:
                must_clauses.append({
                    "bool": {
                        "should": [
                            {"match": {"destination.ip": destination_ip}},
                            {"match": {"server.ip": destination_ip}},
                        ]
                    }
                })
            
            # Port filter
            if port:
                must_clauses.append({
                    "bool": {
                        "should": [
                            {"match": {"source.port": port}},
                            {"match": {"destination.port": port}},
                            {"match": {"client.port": port}},
                            {"match": {"server.port": port}},
                        ]
                    }
                })
            
            # Protocol filter
            if protocol:
                must_clauses.append({
                    "bool": {
                        "should": [
                            {"match": {"network.protocol": protocol}},
                            {"match": {"network.transport": protocol}},
                            {"match": {"protocol": protocol}},
                        ]
                    }
                })
            
            query = {
                "query": {
                    "bool": {
                        "must": must_clauses,
                        "should": [
                            {"match": {"event.category": "network"}},
                            {"match": {"event.dataset": "flow"}},
                            {"exists": {"field": "source.ip"}},
                            {"exists": {"field": "destination.ip"}},
                        ],
                        "minimum_should_match": 1,
                    }
                },
                "size": limit,
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
            
            # Search with fallback index patterns
            indices_patterns = [
                "logs-*,security-*,filebeat-*,packetbeat-*",
                "_all",  # Fallback to all indices if specific patterns fail
            ]
            response = self._search_with_fallback(indices_patterns, query)
            
            hits = response.get("hits", {}).get("hits", [])
            total = response.get("hits", {}).get("total", {})
            if isinstance(total, dict):
                total_count = total.get("value", len(hits))
            else:
                total_count = total
            
            events = []
            for hit in hits[:limit]:
                source = hit.get("_source", {})
                timestamp_str = source.get("@timestamp") or source.get("timestamp")
                timestamp = None
                if timestamp_str:
                    try:
                        timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                    except Exception:
                        timestamp = datetime.utcnow()
                else:
                    timestamp = datetime.utcnow()
                
                # Extract network fields
                network = source.get("network", {})
                source_data = source.get("source", {})
                dest_data = source.get("destination", {})
                
                event = {
                    "id": hit.get("_id", ""),
                    "timestamp": timestamp.isoformat(),
                    "source_ip": source_data.get("ip") if isinstance(source_data, dict) else source.get("source.ip"),
                    "destination_ip": dest_data.get("ip") if isinstance(dest_data, dict) else source.get("destination.ip"),
                    "source_port": source_data.get("port") if isinstance(source_data, dict) else source.get("source.port"),
                    "destination_port": dest_data.get("port") if isinstance(dest_data, dict) else source.get("destination.port"),
                    "protocol": network.get("protocol") or network.get("transport") or source.get("protocol"),
                    "bytes_sent": network.get("bytes") or source.get("bytes"),
                    "bytes_received": network.get("bytes") or source.get("bytes"),  # May need adjustment based on direction
                    "packets_sent": network.get("packets") or source.get("packets"),
                    "packets_received": network.get("packets") or source.get("packets"),  # May need adjustment
                    "connection_duration": source.get("duration") or source.get("connection_duration"),
                    "action": source.get("event", {}).get("action") or source.get("action"),
                    "event_type": "firewall" if "firewall" in str(source).lower() else ("netflow" if "flow" in str(source).lower() else "proxy"),
                    "hostname": source.get("host", {}).get("name") if isinstance(source.get("host"), dict) else source.get("host"),
                    "domain": dest_data.get("domain") if isinstance(dest_data, dict) else source.get("destination.domain"),
                }
                events.append(event)
            
            return {
                "total_count": total_count,
                "events": events,
            }
        except Exception as e:
            logger.exception(f"Error getting network events: {e}")
            raise IntegrationError(f"Failed to get network events: {e}") from e

    def get_dns_events(
        self,
        domain: Optional[str] = None,
        ip_address: Optional[str] = None,
        resolved_ip: Optional[str] = None,
        query_type: Optional[str] = None,
        hours_back: int = 24,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """
        Retrieve DNS query and response events with structured fields.
        
        Returns DNS events with domain, query type, resolved IP, source IP, and response codes.
        """
        try:
            # Build Elasticsearch query for DNS events
            must_clauses = [
                {"range": {"@timestamp": {"gte": f"now-{hours_back}h"}}},
                {"match": {"event.category": "network"}},
            ]
            
            # DNS-specific filters
            dns_should = [
                {"exists": {"field": "dns.question.name"}},
                {"exists": {"field": "dns.question.type"}},
            ]
            
            if domain:
                # Support both exact matches and subdomain matches
                # e.g., "example.com" should match "example.com", "www.example.com", "mail.example.com", etc.
                domain_normalized = domain.lower().strip()
                # Remove leading dot if present
                if domain_normalized.startswith('.'):
                    domain_normalized = domain_normalized[1:]
                
                # Escape dots for regex
                domain_escaped = domain_normalized.replace('.', r'\.')
                
                must_clauses.append({
                    "bool": {
                        "should": [
                            {"match_phrase": {"dns.question.name": domain_normalized}},  # Exact phrase match
                            {"wildcard": {"dns.question.name": f"*{domain_normalized}"}},  # Subdomain match (e.g., *.example.com or www.example.com)
                            {"regexp": {"dns.question.name": f".*{domain_escaped}"}},  # Regex match for flexibility
                        ],
                        "minimum_should_match": 1,
                    }
                })
            
            if ip_address:
                must_clauses.append({
                    "bool": {
                        "should": [
                            {"match": {"source.ip": ip_address}},
                            {"match": {"client.ip": ip_address}},
                        ]
                    }
                })
            
            if resolved_ip:
                must_clauses.append({
                    "bool": {
                        "should": [
                            {"match": {"dns.answers.data": resolved_ip}},
                            {"match": {"dns.response_code": "NOERROR"}},
                        ]
                    }
                })
            
            if query_type:
                must_clauses.append({"match": {"dns.question.type": query_type}})
            
            query = {
                "query": {
                    "bool": {
                        "must": must_clauses,
                        "should": dns_should,
                        "minimum_should_match": 1,
                    }
                },
                "size": limit,
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
            
            # Search with fallback index patterns
            indices_patterns = [
                "logs-*,security-*,filebeat-*,packetbeat-*",
                "_all",  # Fallback to all indices if specific patterns fail
            ]
            response = self._search_with_fallback(indices_patterns, query)
            
            hits = response.get("hits", {}).get("hits", [])
            total = response.get("hits", {}).get("total", {})
            if isinstance(total, dict):
                total_count = total.get("value", len(hits))
            else:
                total_count = total
            
            events = []
            for hit in hits[:limit]:
                source = hit.get("_source", {})
                timestamp_str = source.get("@timestamp") or source.get("timestamp")
                timestamp = None
                if timestamp_str:
                    try:
                        timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                    except Exception:
                        timestamp = datetime.utcnow()
                else:
                    timestamp = datetime.utcnow()
                
                # Extract DNS fields
                dns = source.get("dns", {})
                question = dns.get("question", {}) if isinstance(dns, dict) else {}
                answers = dns.get("answers", []) if isinstance(dns, dict) else []
                source_data = source.get("source", {})
                
                # Get first resolved IP from answers
                resolved_ip_value = None
                if answers and isinstance(answers, list) and len(answers) > 0:
                    first_answer = answers[0] if isinstance(answers[0], dict) else {}
                    resolved_ip_value = first_answer.get("data") or first_answer.get("address")
                
                event = {
                    "id": hit.get("_id", ""),
                    "timestamp": timestamp.isoformat(),
                    "domain": question.get("name") if isinstance(question, dict) else dns.get("question.name"),
                    "query_type": question.get("type") if isinstance(question, dict) else dns.get("question.type"),
                    "resolved_ip": resolved_ip_value,
                    "source_ip": source_data.get("ip") if isinstance(source_data, dict) else source.get("source.ip"),
                    "hostname": source.get("host", {}).get("name") if isinstance(source.get("host"), dict) else source.get("host"),
                    "response_code": dns.get("response_code") if isinstance(dns, dict) else source.get("dns.response_code"),
                    "response_time": dns.get("response_time") if isinstance(dns, dict) else source.get("dns.response_time"),
                    "record_count": len(answers) if isinstance(answers, list) else 0,
                }
                events.append(event)
            
            return {
                "total_count": total_count,
                "events": events,
            }
        except Exception as e:
            logger.exception(f"Error getting DNS events: {e}")
            raise IntegrationError(f"Failed to get DNS events: {e}") from e

    def get_alerts_by_entity(
        self,
        entity_value: str,
        entity_type: Optional[str] = None,
        hours_back: int = 24,
        limit: int = 50,
        severity: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Retrieve alerts filtered by specific entity (IP, user, host, domain, hash) for correlation analysis.
        """
        try:
            # Auto-detect entity type if not provided
            if not entity_type:
                entity_type = self._detect_entity_type(entity_value)
            
            # Build query to find alerts containing this entity
            must_clauses = [
                {"range": {"@timestamp": {"gte": f"now-{hours_back}h"}}}
            ]
            
            # Entity-specific search
            if entity_type == "ip":
                must_clauses.append({
                    "bool": {
                        "should": [
                            {"match": {"source.ip": entity_value}},
                            {"match": {"destination.ip": entity_value}},
                            {"match": {"client.ip": entity_value}},
                            {"match": {"server.ip": entity_value}},
                        ]
                    }
                })
            elif entity_type == "user":
                must_clauses.append({
                    "bool": {
                        "should": [
                            {"match": {"user.name": entity_value}},
                            {"match": {"user": entity_value}},
                            {"match": {"username": entity_value}},
                        ]
                    }
                })
            elif entity_type == "domain":
                must_clauses.append({
                    "bool": {
                        "should": [
                            {"match": {"dns.question.name": entity_value}},
                            {"match": {"url.domain": entity_value}},
                            {"match": {"domain": entity_value}},
                        ]
                    }
                })
            elif entity_type == "hash":
                must_clauses.append({
                    "bool": {
                        "should": [
                            {"match": {"file.hash.sha256": entity_value}},
                            {"match": {"file.hash.sha1": entity_value}},
                            {"match": {"file.hash.md5": entity_value}},
                            {"match": {"hash": entity_value}},
                        ]
                    }
                })
            elif entity_type == "host":
                must_clauses.append({
                    "bool": {
                        "should": [
                            {"match": {"host.name": entity_value}},
                            {"match": {"hostname": entity_value}},
                            {"match": {"host": entity_value}},
                        ]
                    }
                })
            
            # Severity filter
            if severity:
                must_clauses.append({"match": {"signal.severity": severity}})
            
            query = {
                "query": {
                    "bool": {
                        "must": must_clauses,
                    }
                },
                "size": limit,
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
            
            # Search with fallback index patterns
            indices_patterns = [
                "alerts-*,.siem-signals-*,logs-endpoint.alerts-*",
                "alerts-*",
                "_all",  # Fallback to all indices if specific patterns fail
            ]
            response = self._search_with_fallback(indices_patterns, query)
            
            hits = response.get("hits", {}).get("hits", [])
            total = response.get("hits", {}).get("total", {})
            if isinstance(total, dict):
                total_count = total.get("value", len(hits))
            else:
                total_count = total
            
            alerts = []
            for hit in hits:
                source = hit.get("_source", {})
                signal = source.get("signal", {})
                rule = signal.get("rule", {}) if isinstance(signal.get("rule"), dict) else {}
                
                alert = {
                    "id": hit.get("_id", ""),
                    "title": rule.get("name", "") or source.get("event", {}).get("reason", ""),
                    "severity": signal.get("severity", "medium"),
                    "status": signal.get("status", "open"),
                    "created_at": source.get("@timestamp", ""),
                    "alert_type": rule.get("category", "") or source.get("event", {}).get("category", ""),
                    "description": rule.get("description", "") or source.get("event", {}).get("reason", ""),
                    "related_entities": self._extract_entities_from_alert(source),
                    "source": "elastic",
                }
                alerts.append(alert)
            
            return {
                "entity_value": entity_value,
                "entity_type": entity_type,
                "total_count": total_count,
                "returned_count": len(alerts),
                "alerts": alerts,
            }
        except Exception as e:
            logger.exception(f"Error getting alerts by entity: {e}")
            raise IntegrationError(f"Failed to get alerts by entity: {e}") from e

    def get_all_uncertain_alerts_for_host(
        self,
        hostname: str,
        hours_back: int = 7 * 24,  # Default 7 days
        limit: int = 100,
    ) -> Dict[str, Any]:
        """
        Retrieve all alerts with verdict="uncertain" for a specific host.
        
        This is useful for pattern analysis when investigating uncertain alerts
        to determine if multiple uncertain alerts on the same host indicate a broader issue.
        
        Args:
            hostname: The hostname to search for
            hours_back: How many hours to look back (default: 7 days = 168 hours)
            limit: Maximum number of alerts to return (default: 100)
        
        Returns:
            Dictionary containing uncertain alerts for the host
        """
        try:
            must_clauses = [
                {"range": {"@timestamp": {"gte": f"now-{hours_back}h"}}},
                # Match hostname in various fields
                {
                    "bool": {
                        "should": [
                            {"match": {"host.name": hostname}},
                            {"match": {"hostname": hostname}},
                            {"match": {"host": hostname}},
                            {"match": {"host.hostname": hostname}},
                        ]
                    }
                },
                # Match verdict="uncertain"
                {
                    "bool": {
                        "should": [
                            {"term": {"signal.ai.verdict": "uncertain"}},
                            {"term": {"verdict": "uncertain"}},
                        ]
                    }
                }
            ]
            
            query = {
                "query": {
                    "bool": {
                        "must": must_clauses,
                    }
                },
                "size": limit,
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
            
            # Search with fallback index patterns
            indices_patterns = [
                "alerts-*,.siem-signals-*,logs-endpoint.alerts-*",
                "alerts-*",
                "_all",  # Fallback to all indices if specific patterns fail
            ]
            response = self._search_with_fallback(indices_patterns, query)
            
            hits = response.get("hits", {}).get("hits", [])
            total = response.get("hits", {}).get("total", {})
            if isinstance(total, dict):
                total_count = total.get("value", len(hits))
            else:
                total_count = total
            
            alerts = []
            for hit in hits:
                source = hit.get("_source", {})
                signal = source.get("signal", {})
                rule = signal.get("rule", {}) if isinstance(signal.get("rule"), dict) else {}
                
                # Extract verdict
                verdict = signal.get("ai", {}).get("verdict") or source.get("verdict")
                
                alert = {
                    "id": hit.get("_id", ""),
                    "title": rule.get("name", "") or source.get("event", {}).get("reason", ""),
                    "severity": signal.get("severity", "medium"),
                    "status": signal.get("status", "open"),
                    "created_at": source.get("@timestamp", ""),
                    "alert_type": rule.get("category", "") or source.get("event", {}).get("category", ""),
                    "description": rule.get("description", "") or source.get("event", {}).get("reason", ""),
                    "verdict": verdict,
                    "hostname": hostname,
                    "related_entities": self._extract_entities_from_alert(source),
                    "source": "elastic",
                }
                alerts.append(alert)
            
            return {
                "hostname": hostname,
                "hours_back": hours_back,
                "total_count": total_count,
                "returned_count": len(alerts),
                "alerts": alerts,
            }
        except Exception as e:
            logger.exception(f"Error getting uncertain alerts for host: {e}")
            raise IntegrationError(f"Failed to get uncertain alerts for host: {e}") from e

    def get_alerts_by_time_window(
        self,
        start_time: str,
        end_time: str,
        limit: int = 100,
        severity: Optional[str] = None,
        alert_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Retrieve alerts within a specific time window for temporal correlation.
        """
        try:
            # Parse ISO timestamps
            try:
                start_dt = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
                end_dt = datetime.fromisoformat(end_time.replace("Z", "+00:00"))
            except Exception as e:
                raise IntegrationError(f"Invalid time format: {e}")
            
            must_clauses = [
                {"range": {"@timestamp": {"gte": start_time, "lte": end_time}}}
            ]
            
            if severity:
                must_clauses.append({"match": {"signal.severity": severity}})
            
            if alert_type:
                must_clauses.append({
                    "bool": {
                        "should": [
                            {"match": {"signal.rule.category": alert_type}},
                            {"match": {"event.category": alert_type}},
                        ]
                    }
                })
            
            query = {
                "query": {
                    "bool": {
                        "must": must_clauses,
                    }
                },
                "size": limit,
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
            
            # Search with fallback index patterns
            indices_patterns = [
                "alerts-*,.siem-signals-*,logs-endpoint.alerts-*",
                "alerts-*",
                "_all",  # Fallback to all indices if specific patterns fail
            ]
            response = self._search_with_fallback(indices_patterns, query)
            
            hits = response.get("hits", {}).get("hits", [])
            total = response.get("hits", {}).get("total", {})
            if isinstance(total, dict):
                total_count = total.get("value", len(hits))
            else:
                total_count = total
            
            alerts = []
            for hit in hits:
                source = hit.get("_source", {})
                signal = source.get("signal", {})
                rule = signal.get("rule", {}) if isinstance(signal.get("rule"), dict) else {}
                
                alert = {
                    "id": hit.get("_id", ""),
                    "title": rule.get("name", "") or source.get("event", {}).get("reason", ""),
                    "severity": signal.get("severity", "medium"),
                    "status": signal.get("status", "open"),
                    "created_at": source.get("@timestamp", ""),
                    "alert_type": rule.get("category", "") or source.get("event", {}).get("category", ""),
                    "description": rule.get("description", "") or source.get("event", {}).get("reason", ""),
                    "related_entities": self._extract_entities_from_alert(source),
                    "source": "elastic",
                }
                alerts.append(alert)
            
            return {
                "total_count": total_count,
                "returned_count": len(alerts),
                "alerts": alerts,
            }
        except Exception as e:
            logger.exception(f"Error getting alerts by time window: {e}")
            raise IntegrationError(f"Failed to get alerts by time window: {e}") from e

    def get_email_events(
        self,
        sender_email: Optional[str] = None,
        recipient_email: Optional[str] = None,
        subject: Optional[str] = None,
        email_id: Optional[str] = None,
        hours_back: int = 24,
        limit: int = 100,
        event_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Retrieve email security events with structured fields for phishing analysis.
        
        Returns email events with sender, recipient, subject, headers, authentication, URLs, and attachments.
        """
        try:
            # Build Elasticsearch query for email events
            must_clauses = [
                {"range": {"@timestamp": {"gte": f"now-{hours_back}h"}}},
            ]
            
            # Email event type filter
            email_should = [
                {"match": {"event.category": "email"}},
                {"match": {"event.dataset": "email"}},
                {"exists": {"field": "email.from.address"}},
                {"exists": {"field": "email.to.address"}},
            ]
            
            if sender_email:
                must_clauses.append({
                    "bool": {
                        "should": [
                            {"match": {"email.from.address": sender_email}},
                            {"match": {"email.sender.address": sender_email}},
                            {"match": {"sender.email": sender_email}},
                        ]
                    }
                })
            
            if recipient_email:
                must_clauses.append({
                    "bool": {
                        "should": [
                            {"match": {"email.to.address": recipient_email}},
                            {"match": {"email.recipient.address": recipient_email}},
                            {"match": {"recipient.email": recipient_email}},
                        ]
                    }
                })
            
            if subject:
                must_clauses.append({
                    "bool": {
                        "should": [
                            {"match": {"email.subject": subject}},
                            {"wildcard": {"email.subject": f"*{subject}*"}},
                        ]
                    }
                })
            
            if email_id:
                must_clauses.append({
                    "bool": {
                        "should": [
                            {"match": {"email.message_id": email_id}},
                            {"match": {"message_id": email_id}},
                        ]
                    }
                })
            
            if event_type and event_type != "all":
                if event_type == "delivered":
                    must_clauses.append({"match": {"event.action": "delivered"}})
                elif event_type == "blocked":
                    must_clauses.append({"match": {"event.action": "blocked"}})
                elif event_type == "quarantined":
                    must_clauses.append({"match": {"event.action": "quarantined"}})
            
            query = {
                "query": {
                    "bool": {
                        "must": must_clauses,
                        "should": email_should,
                        "minimum_should_match": 1,
                    }
                },
                "size": limit,
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
            
            # Search with fallback index patterns
            indices_patterns = [
                "logs-*,security-*,filebeat-*",
                "_all",  # Fallback to all indices if specific patterns fail
            ]
            response = self._search_with_fallback(indices_patterns, query)
            
            hits = response.get("hits", {}).get("hits", [])
            total = response.get("hits", {}).get("total", {})
            if isinstance(total, dict):
                total_count = total.get("value", len(hits))
            else:
                total_count = total
            
            events = []
            for hit in hits[:limit]:
                source = hit.get("_source", {})
                timestamp_str = source.get("@timestamp") or source.get("timestamp")
                timestamp = None
                if timestamp_str:
                    try:
                        timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                    except Exception:
                        timestamp = datetime.utcnow()
                else:
                    timestamp = datetime.utcnow()
                
                # Extract email fields
                email = source.get("email", {})
                from_addr = email.get("from", {}) if isinstance(email.get("from"), dict) else {}
                to_addr = email.get("to", {}) if isinstance(email.get("to"), dict) else {}
                
                # Extract headers
                headers = {}
                if isinstance(email.get("headers"), dict):
                    headers = email.get("headers", {})
                
                # Extract authentication
                auth = {}
                if isinstance(email.get("authentication"), dict):
                    auth = email.get("authentication", {})
                
                # Extract URLs (from email body or headers)
                urls = []
                if isinstance(email.get("urls"), list):
                    urls = email.get("urls", [])
                elif source.get("urls"):
                    urls = source.get("urls", []) if isinstance(source.get("urls"), list) else []
                
                # Extract attachments
                attachments = []
                if isinstance(email.get("attachments"), list):
                    attachments = email.get("attachments", [])
                elif source.get("attachments"):
                    attachments = source.get("attachments", []) if isinstance(source.get("attachments"), list) else []
                
                event = {
                    "id": hit.get("_id", ""),
                    "timestamp": timestamp.isoformat(),
                    "sender_email": from_addr.get("address") if isinstance(from_addr, dict) else email.get("from.address") or email.get("sender.email"),
                    "sender_domain": from_addr.get("address", "").split("@")[-1] if isinstance(from_addr, dict) and from_addr.get("address") else "",
                    "recipient_email": to_addr.get("address") if isinstance(to_addr, dict) else email.get("to.address") or email.get("recipient.email"),
                    "subject": email.get("subject") or source.get("email.subject"),
                    "message_id": email.get("message_id") or headers.get("Message-ID") or source.get("message_id"),
                    "headers": {
                        "from": headers.get("From") or from_addr.get("address") if isinstance(from_addr, dict) else None,
                        "reply_to": headers.get("Reply-To") or email.get("reply_to"),
                        "return_path": headers.get("Return-Path") or email.get("return_path"),
                        "received": headers.get("Received") if isinstance(headers.get("Received"), list) else [headers.get("Received")] if headers.get("Received") else [],
                    },
                    "authentication": {
                        "spf_status": auth.get("spf") or email.get("spf.status"),
                        "dkim_status": auth.get("dkim") or email.get("dkim.status"),
                        "dmarc_status": auth.get("dmarc") or email.get("dmarc.status"),
                    },
                    "urls": [
                        {
                            "url": url.get("url") if isinstance(url, dict) else url,
                            "domain": url.get("domain") if isinstance(url, dict) else None,
                            "text": url.get("text") if isinstance(url, dict) else None,
                        }
                        for url in urls[:20]  # Limit to top 20 URLs
                    ],
                    "attachments": [
                        {
                            "filename": att.get("filename") if isinstance(att, dict) else att,
                            "file_hash": att.get("hash") or att.get("sha256") if isinstance(att, dict) else None,
                            "file_type": att.get("type") or att.get("mime_type") if isinstance(att, dict) else None,
                            "file_size": att.get("size") if isinstance(att, dict) else None,
                        }
                        for att in attachments[:20]  # Limit to top 20 attachments
                    ],
                    "event_type": source.get("event", {}).get("action") or email.get("action") or "delivered",
                    "threat_score": email.get("threat_score") or source.get("threat_score"),
                }
                events.append(event)
            
            return {
                "total_count": total_count,
                "returned_count": len(events),
                "events": events,
            }
        except Exception as e:
            logger.exception(f"Error getting email events: {e}")
            raise IntegrationError(f"Failed to get email events: {e}") from e

