# Database identity for the authoritative history writer.
#
# This file may be distributed under the terms of the GNU GPLv3 license.

from __future__ import annotations
import contextlib
import logging
import pathlib
import sqlite3
import sys
import uuid
from typing import IO, Optional, Tuple


_MARKER_TABLE = "anyraid_history_database_generation"
_STATE_TABLE = "generation_state"
_FileIdentity = Tuple[int, int]


class GenerationUnavailable(Exception):
    pass


class HistoryDatabaseGeneration:
    """Bind history evidence to the current database and its restore epoch."""

    def __init__(self, db_path: pathlib.Path) -> None:
        self.db_path = db_path.absolute()
        self.anchor_path = self.db_path.with_name(f"{db_path.name}.history-generation")
        self.lock_path = self.anchor_path.with_name(f"{self.anchor_path.name}.lock")
        self._lock: Optional[IO[bytes]] = None
        self._identity: Optional[_FileIdentity] = None
        self._generation: Optional[str] = None
        self.observe_database_path()

    def observe_database_path(self) -> None:
        if self._identity is None:
            with contextlib.suppress(OSError, GenerationUnavailable):
                self._identity = self._file_identity()

    def initialize(self, conn: sqlite3.Connection) -> None:
        try:
            self._initialize(conn)
        except (OSError, sqlite3.Error, GenerationUnavailable) as exc:
            self._generation = None
            logging.error("History writer database generation unavailable: %s", exc)

    def _initialize(self, conn: sqlite3.Connection) -> None:
        self._acquire_owner()
        identity = self._require_open_path()
        if not self.anchor_path.exists() or self.anchor_path.stat().st_size == 0:
            if self._read_marker(conn) is not None:
                raise GenerationUnavailable(
                    "Database generation anchor is missing or empty"
                )
            self._create_anchor(identity)
        with contextlib.closing(self._connect_anchor()) as anchor:
            generation, anchored_identity = self._read_anchor(anchor)
            if generation is not None and anchored_identity == identity:
                if self._read_marker(conn) != generation:
                    raise GenerationUnavailable(
                        "Database generation marker does not match"
                    )
                self._generation = generation
                return

            # A durable NULL prevents issuing old evidence following interruption.
            with anchor:
                self._write_anchor(anchor, None, identity)
            generation = str(uuid.uuid4())
            with conn:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute(
                    f"CREATE TABLE IF NOT EXISTS {_MARKER_TABLE} ("
                    "singleton INTEGER PRIMARY KEY CHECK (singleton = 1), "
                    "generation TEXT NOT NULL)"
                )
                conn.execute(
                    f"INSERT OR REPLACE INTO {_MARKER_TABLE} VALUES (1, ?)",
                    (generation,)
                )
            if self._file_identity() != identity:
                raise GenerationUnavailable("History database changed while opening")
            with anchor:
                self._write_anchor(anchor, generation, identity)
            self._generation = generation

    def require(self, conn: sqlite3.Connection) -> str:
        generation = self._generation
        if generation is None or self._lock is None:
            raise GenerationUnavailable("History database generation is unavailable")
        try:
            with contextlib.closing(self._connect_anchor(read_only=True)) as anchor:
                live_generation, identity = self._read_anchor(anchor)
            if (
                live_generation != generation or identity != self._identity
                or self._read_marker(conn) != generation
                or self._file_identity() != identity
            ):
                raise GenerationUnavailable("History database generation changed")
        except (OSError, sqlite3.Error, GenerationUnavailable) as exc:
            self._generation = None
            raise GenerationUnavailable(
                "History database generation is unavailable"
            ) from exc
        return generation

    def before_restore(
        self, conn: sqlite3.Connection, restore_conn: sqlite3.Connection
    ) -> None:
        self._generation = None
        try:
            self._acquire_owner()
            identity = self._require_open_path()
            if (
                not self.anchor_path.exists()
                and self._read_marker(conn) is None
                and self._read_marker(restore_conn) is None
            ):
                return
            if not self.anchor_path.exists():
                self._create_anchor(identity)
            with contextlib.closing(self._connect_anchor()) as anchor:
                self._read_anchor(anchor)
                with anchor:
                    self._write_anchor(anchor, None, identity)
        except (OSError, sqlite3.Error) as exc:
            raise GenerationUnavailable(
                "Could not revoke history database generation"
            ) from exc

    def close(self) -> None:
        self._generation = None
        if self._lock is not None:
            self._lock.close()
            self._lock = None

    def _acquire_owner(self) -> None:
        # Keep the lock on a stable path for the lifetime of this opened database.
        if self._lock is not None:
            return
        lock = self.lock_path.open("a+b")
        try:
            if sys.platform == "win32":
                import msvcrt
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            lock.close()
            raise
        self._lock = lock

    def _file_identity(self) -> _FileIdentity:
        stat = self.db_path.stat()
        if stat.st_ino == 0:
            raise GenerationUnavailable(
                "History database filesystem has no file identity"
            )
        return stat.st_dev, stat.st_ino

    def _require_open_path(self) -> _FileIdentity:
        identity = self._file_identity()
        if self._identity is not None and identity != self._identity:
            raise GenerationUnavailable("History database changed since opening")
        self._identity = identity
        return identity

    def _connect_anchor(self, read_only: bool = False) -> sqlite3.Connection:
        mode = "ro" if read_only else "rw"
        anchor = sqlite3.connect(f"{self.anchor_path.as_uri()}?mode={mode}", uri=True)
        try:
            if not read_only:
                anchor.execute("PRAGMA synchronous=EXTRA")
        except sqlite3.Error:
            anchor.close()
            raise
        return anchor

    def _create_anchor(self, identity: _FileIdentity) -> None:
        # Moonraker backup/restore copies the main SQLite database only.
        with contextlib.closing(sqlite3.connect(str(self.anchor_path))) as anchor:
            anchor.execute("PRAGMA synchronous=EXTRA")
            with anchor:
                anchor.execute("BEGIN IMMEDIATE")
                anchor.execute(
                    f"CREATE TABLE {_STATE_TABLE} ("
                    "singleton INTEGER PRIMARY KEY CHECK (singleton = 1), "
                    "generation TEXT, device TEXT NOT NULL, inode TEXT NOT NULL)"
                )
                self._write_anchor(anchor, None, identity)

    def _read_anchor(
        self, anchor: sqlite3.Connection
    ) -> Tuple[Optional[str], _FileIdentity]:
        row = anchor.execute(
            f"SELECT generation, device, inode FROM {_STATE_TABLE} WHERE singleton = 1"
        ).fetchone()
        if row is None:
            raise GenerationUnavailable("Invalid history database generation anchor")
        generation, device, inode = row
        try:
            if generation is not None:
                parsed = uuid.UUID(generation)
                if parsed.version != 4 or str(parsed) != generation:
                    raise ValueError
            return generation, (int(device), int(inode))
        except (ValueError, TypeError, AttributeError) as exc:
            raise GenerationUnavailable(
                "Invalid history database generation anchor"
            ) from exc

    def _write_anchor(
        self,
        anchor: sqlite3.Connection,
        generation: Optional[str],
        identity: _FileIdentity
    ) -> None:
        anchor.execute(
            f"INSERT OR REPLACE INTO {_STATE_TABLE} VALUES (1, ?, ?, ?)",
            (generation, str(identity[0]), str(identity[1]))
        )

    def _read_marker(self, conn: sqlite3.Connection) -> Optional[str]:
        table_exists = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (_MARKER_TABLE,)
        ).fetchone()
        if table_exists is None:
            return None
        row = conn.execute(
            f"SELECT generation FROM {_MARKER_TABLE} WHERE singleton = 1"
        ).fetchone()
        if row is None:
            raise GenerationUnavailable("Database generation marker is missing")
        return row[0]
