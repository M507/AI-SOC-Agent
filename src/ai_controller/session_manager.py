"""
Session manager for storing and managing agent execution sessions.

Stores sessions and autoruns in JSON files on the filesystem.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, asdict, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

from ..core.logging import get_logger

logger = get_logger("sami.ai_controller.session_manager")


class SessionType(Enum):
    """Types of sessions."""
    MANUAL = "manual"  # User-initiated session
    AUTORUN = "autorun"  # Scheduled/recurring session


class SessionStatus(Enum):
    """Status of a session."""
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"
    PENDING = "pending"


@dataclass
class SessionEntry:
    """Represents a single execution entry in a session."""
    id: str
    command: str
    timestamp: datetime
    result: Optional[Dict[str, Any]] = None
    status: SessionStatus = SessionStatus.PENDING
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        data["status"] = self.status.value
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SessionEntry:
        """Create from dictionary."""
        data = data.copy()
        data["timestamp"] = datetime.fromisoformat(data["timestamp"])
        data["status"] = SessionStatus(data["status"])
        return cls(**data)


@dataclass
class Session:
    """Represents an agent execution session."""
    id: str
    name: str
    session_type: SessionType
    status: SessionStatus
    created_at: datetime
    updated_at: datetime
    entries: List[SessionEntry] = field(default_factory=list)
    autorun_config: Optional[Dict[str, Any]] = None  # For autorun sessions
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = asdict(self)
        data["session_type"] = self.session_type.value
        data["status"] = self.status.value
        data["created_at"] = self.created_at.isoformat()
        data["updated_at"] = self.updated_at.isoformat()
        data["entries"] = [entry.to_dict() for entry in self.entries]
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Session:
        """Create from dictionary."""
        data = data.copy()
        data["session_type"] = SessionType(data["session_type"])
        data["status"] = SessionStatus(data["status"])
        data["created_at"] = datetime.fromisoformat(data["created_at"])
        data["updated_at"] = datetime.fromisoformat(data["updated_at"])
        data["entries"] = [SessionEntry.from_dict(entry) for entry in data.get("entries", [])]
        return cls(**data)


@dataclass
class AutorunConfig:
    """Configuration for an autorun session."""
    id: str
    name: str
    command: str
    interval_seconds: int
    enabled: bool = True
    session_id: Optional[str] = None  # Persistent session used for this autorun
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.now)
    condition_function: Optional[str] = None  # Function/tool name to check before executing (e.g., "get_recent_alerts")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = asdict(self)
        if self.last_run:
            data["last_run"] = self.last_run.isoformat()
        if self.next_run:
            data["next_run"] = self.next_run.isoformat()
        data["created_at"] = self.created_at.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AutorunConfig:
        """Create from dictionary."""
        data = data.copy()
        if data.get("last_run"):
            data["last_run"] = datetime.fromisoformat(data["last_run"])
        if data.get("next_run"):
            data["next_run"] = datetime.fromisoformat(data["next_run"])
        if data.get("created_at"):
            data["created_at"] = datetime.fromisoformat(data["created_at"])
        return cls(**data)


class SessionManager:
    """Manages agent execution sessions and autoruns."""
    
    def __init__(self, storage_dir: str = "data/ai_controller"):
        """Initialize the session manager."""
        self.storage_dir = Path(storage_dir)
        self.sessions_dir = self.storage_dir / "sessions"
        self.autoruns_dir = self.storage_dir / "autoruns"
        
        # Create directories if they don't exist
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        self.autoruns_dir.mkdir(parents=True, exist_ok=True)
        
        # In-memory cache
        self._sessions: Dict[str, Session] = {}
        self._autoruns: Dict[str, AutorunConfig] = {}
        self._load_all()
    
    def _load_all(self):
        """Load all sessions and autoruns from disk."""
        # Load sessions
        for session_file in self.sessions_dir.glob("*.json"):
            try:
                with open(session_file, "r") as f:
                    data = json.load(f)
                    session = Session.from_dict(data)
                    self._sessions[session.id] = session
            except Exception as e:
                logger.error(f"Failed to load session from {session_file}: {e}")
        
        # Load autoruns
        for autorun_file in self.autoruns_dir.glob("*.json"):
            try:
                with open(autorun_file, "r") as f:
                    data = json.load(f)
                    autorun = AutorunConfig.from_dict(data)
                    self._autoruns[autorun.id] = autorun
            except Exception as e:
                logger.error(f"Failed to load autorun from {autorun_file}: {e}")
        
        logger.info(f"Loaded {len(self._sessions)} sessions and {len(self._autoruns)} autoruns")
    
    def create_session(self, name: str, session_type: SessionType = SessionType.MANUAL) -> Session:
        """Create a new session."""
        session = Session(
            id=str(uuid4()),
            name=name,
            session_type=session_type,
            status=SessionStatus.PENDING,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        
        self._sessions[session.id] = session
        self._save_session(session)
        
        logger.info("Created session: %s (%s, type=%s)", session.id, session.name, session.session_type.value)
        return session
    
    def get_session(self, session_id: str) -> Optional[Session]:
        """Get a session by ID."""
        return self._sessions.get(session_id)
    
    def list_sessions(self, session_type: Optional[SessionType] = None) -> List[Session]:
        """List all sessions, optionally filtered by type."""
        sessions = list(self._sessions.values())
        if session_type:
            sessions = [s for s in sessions if s.session_type == session_type]
        return sorted(sessions, key=lambda s: s.updated_at, reverse=True)
    
    def add_entry(self, session_id: str, command: str, result: Optional[Dict[str, Any]] = None) -> SessionEntry:
        """Add an entry to a session."""
        session = self.get_session(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")
        
        entry = SessionEntry(
            id=str(uuid4()),
            command=command,
            timestamp=datetime.now(),
            result=result,
            status=SessionStatus.COMPLETED if result else SessionStatus.PENDING
        )
        
        session.entries.append(entry)
        session.updated_at = datetime.now()
        session.status = SessionStatus.RUNNING if not result else SessionStatus.COMPLETED

        logger.debug(
            "Added entry %s to session %s (command=%s, immediate_status=%s)",
            entry.id,
            session_id,
            command,
            session.status.value,
        )

        self._save_session(session)
        
        return entry
    
    def update_entry(self, session_id: str, entry_id: str, result: Optional[Dict[str, Any]] = None, status: Optional[SessionStatus] = None):
        """Update an entry in a session."""
        session = self.get_session(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")
        
        entry = next((e for e in session.entries if e.id == entry_id), None)
        if not entry:
            raise ValueError(f"Entry {entry_id} not found in session {session_id}")
        
        if result is not None:
            entry.result = result
        if status is not None:
            entry.status = status
        
        session.updated_at = datetime.now()
        logger.debug(
            "Updated entry %s in session %s (status=%s, has_result=%s)",
            entry_id,
            session_id,
            entry.status.value,
            result is not None,
        )
        self._save_session(session)
    
    def update_session_status(self, session_id: str, status: SessionStatus):
        """Update session status."""
        session = self.get_session(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")
        
        session.status = status
        session.updated_at = datetime.now()
        logger.debug("Updated session %s status to %s", session_id, status.value)
        self._save_session(session)
    
    def delete_session(self, session_id: str):
        """Delete a session."""
        session = self.get_session(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")
        
        # Delete file
        session_file = self.sessions_dir / f"{session_id}.json"
        if session_file.exists():
            try:
                session_file.unlink()
                logger.info(f"Deleted session file: {session_file}")
            except Exception as e:
                logger.error(f"Failed to delete session file {session_file}: {e}")
                raise
        else:
            logger.warning(f"Session file does not exist: {session_file}")
        
        # Remove from cache
        if session_id in self._sessions:
            del self._sessions[session_id]
            logger.info(f"Removed session {session_id} from cache")
        else:
            logger.warning(f"Session {session_id} not in cache")
        
        logger.info(f"Successfully deleted session: {session_id}")
    
    def clear_session_entries(self, session_id: str):
        """Clear all entries from a session."""
        session = self.get_session(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found")
        
        session.entries = []
        session.updated_at = datetime.now()
        logger.info(f"Cleared all entries from session: {session_id}")
        self._save_session(session)
    
    def _save_session(self, session: Session):
        """Save a session to disk."""
        session_file = self.sessions_dir / f"{session.id}.json"
        with open(session_file, "w") as f:
            json.dump(session.to_dict(), f, indent=2)
    
    # Autorun methods
    def create_autorun(self, name: str, command: str, interval_seconds: int, condition_function: Optional[str] = None) -> AutorunConfig:
        """Create a new autorun configuration."""
        # Create a dedicated AUTORUN session that will be reused for all executions
        session = self.create_session(name, SessionType.AUTORUN)

        now = datetime.now()
        autorun = AutorunConfig(
            id=str(uuid4()),
            name=name,
            command=command,
            interval_seconds=interval_seconds,
            enabled=True,
            session_id=session.id,
            created_at=now,
            condition_function=condition_function,
            next_run=now  # Set to now so it runs immediately
        )
        
        self._autoruns[autorun.id] = autorun
        self._save_autorun(autorun)
        
        logger.info(f"Created autorun: {autorun.id} ({autorun.name}) - will run immediately, then every {interval_seconds}s")
        return autorun
    
    def get_autorun(self, autorun_id: str) -> Optional[AutorunConfig]:
        """Get an autorun by ID."""
        return self._autoruns.get(autorun_id)
    
    def list_autoruns(self, enabled_only: bool = False) -> List[AutorunConfig]:
        """List all autoruns."""
        autoruns = list(self._autoruns.values())
        if enabled_only:
            autoruns = [a for a in autoruns if a.enabled]
        return sorted(autoruns, key=lambda a: a.created_at, reverse=True)
    
    def update_autorun(self, autorun_id: str, **kwargs):
        """Update an autorun configuration."""
        autorun = self.get_autorun(autorun_id)
        if not autorun:
            raise ValueError(f"Autorun {autorun_id} not found")
        
        for key, value in kwargs.items():
            if hasattr(autorun, key):
                setattr(autorun, key, value)
        
        self._save_autorun(autorun)
    
    def delete_autorun(self, autorun_id: str):
        """Delete an autorun and its dedicated session if present."""
        autorun = self.get_autorun(autorun_id)
        if not autorun:
            raise ValueError(f"Autorun {autorun_id} not found")

        logger.info(
            "Deleting autorun config %s (%s) with session_id=%s",
            autorun_id,
            autorun.name,
            autorun.session_id,
        )

        # Best-effort: also delete the associated AUTORUN session so it no longer appears in the UI
        if autorun.session_id:
            try:
                logger.info("Deleting associated autorun session %s for autorun %s", autorun.session_id, autorun_id)
                self.delete_session(autorun.session_id)
            except Exception as e:
                logger.error(
                    "Failed to delete associated autorun session %s for autorun %s: %s",
                    autorun.session_id,
                    autorun_id,
                    e,
                )

        # Delete autorun file
        autorun_file = self.autoruns_dir / f"{autorun_id}.json"
        if autorun_file.exists():
            try:
                autorun_file.unlink()
                logger.info("Deleted autorun file: %s", autorun_file)
            except Exception as e:
                logger.error("Failed to delete autorun file %s: %s", autorun_file, e)
                raise

        # Remove from cache
        if autorun_id in self._autoruns:
            del self._autoruns[autorun_id]

        logger.info("Successfully deleted autorun: %s", autorun_id)
    
    def _save_autorun(self, autorun: AutorunConfig):
        """Save an autorun to disk."""
        autorun_file = self.autoruns_dir / f"{autorun.id}.json"
        with open(autorun_file, "w") as f:
            json.dump(autorun.to_dict(), f, indent=2)

