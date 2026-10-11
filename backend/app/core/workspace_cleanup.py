"""Automated workspace garbage collection and temporary directory cleanup."""
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import shutil
import tempfile
from typing import Dict, List, Optional, Tuple
from sqlalchemy.orm import Session

from .config import settings
from .logging import get_logger
from ..models.scan import Scan

logger = get_logger("reposhield.cleanup")


def clean_stale_workspaces(db: Optional[Session] = None, max_age_hours: int = 24) -> Dict[str, int]:
    """Clean up orphan or stale temporary directories and workspaces to prevent disk exhaustion.
    
    Returns:
        Summary dict of cleaned directories and reclaimed bytes.
    """
    reclaimed_bytes = 0
    removed_dirs = 0
    now = datetime.now(timezone.utc)
    cutoff_time = now - timedelta(hours=max_age_hours)

    # 1. Clean disposable reposhield verification workspaces from temp
    temp_dir = Path(tempfile.gettempdir())
    for item in temp_dir.glob("reposhield_*"):
        try:
            mtime = datetime.fromtimestamp(item.stat().st_mtime, tz=timezone.utc)
            if mtime < cutoff_time:
                size = sum(f.stat().st_size for f in item.glob("**/*") if f.is_file())
                if item.is_dir():
                    shutil.rmtree(item, ignore_errors=True)
                else:
                    item.unlink(missing_ok=True)
                removed_dirs += 1
                reclaimed_bytes += size
                logger.info(f"Purged stale temp workspace: {item.name} ({size} bytes)")
        except Exception as exc:
            logger.warning(f"Failed to clean temp item {item}: {exc}")

    # 2. Check main workspace root for orphaned folders if db is provided
    workspace_root = Path(settings.WORKSPACE_ROOT)
    if workspace_root.exists() and db is not None:
        # Get active scan workspace paths to never delete in-use folders
        active_scan_paths = set(
            s.repository.workspace_path for s in db.query(Scan).filter(Scan.status.in_(["running", "pending"])).all()
            if s.repository and s.repository.workspace_path
        )

        for folder in workspace_root.glob("*"):
            if not folder.is_dir():
                continue
            folder_str = str(folder.resolve()).replace("\\", "/")
            if folder_str in active_scan_paths:
                continue

            try:
                mtime = datetime.fromtimestamp(folder.stat().st_mtime, tz=timezone.utc)
                if mtime < cutoff_time:
                    size = sum(f.stat().st_size for f in folder.glob("**/*") if f.is_file())
                    shutil.rmtree(folder, ignore_errors=True)
                    removed_dirs += 1
                    reclaimed_bytes += size
                    logger.info(f"Purged expired repository workspace: {folder.name} ({size} bytes)")
            except Exception as exc:
                logger.warning(f"Error purging workspace folder {folder}: {exc}")

    return {
        "removed_directories": removed_dirs,
        "reclaimed_bytes": reclaimed_bytes,
    }
