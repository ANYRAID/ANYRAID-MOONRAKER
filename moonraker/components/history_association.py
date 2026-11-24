# Signed Klippy start receipts and history row proofs.
#
# This file may be distributed under the terms of the GNU GPLv3 license.

from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import re
import sqlite3
import stat
from typing import TYPE_CHECKING, Any

from ..common import RequestType, SqlTableDefinition

if TYPE_CHECKING:
    from ..confighelper import ConfigHelper
    from ..common import WebRequest
    from .database import DBProviderWrapper, MoonrakerDatabase

CONFIG_SECTION = "history screen_association"
RECEIPT_FIELD = "anyraid_start_receipt"
BINDINGS_TABLE = "screen_history_bindings"
HISTORY_ROW_ID = "history_row_id"
_ORIGIN = re.compile(r"http://127\.0\.0\.1:([1-9][0-9]{0,4})")
_UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
_IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,128}")
_HEX32 = re.compile(r"[0-9a-f]{64}")
_SIGNATURE = re.compile(r"[A-Za-z0-9_-]{86}")
_JOB_ID = re.compile(r"[0-9A-F]{6,16}")
_RECEIPT_FIELDS = (
    "origin", "databaseGeneration", "backendEpoch", "taskId", "startId",
    "authorityKeyId", "filename", "fileSha256"
)
_PROOF_FIELDS = (
    "origin", "jobId", "challenge", "databaseGeneration", "rowId"
)
_SPKI_ED25519_PREFIX = bytes.fromhex("302a300506032b6570032100")


class HistoryBindingsDefinition(SqlTableDefinition):
    name = BINDINGS_TABLE
    prototype = f"""
        {BINDINGS_TABLE} (
            row_id TEXT PRIMARY KEY NOT NULL,
            job_id INTEGER NOT NULL,
            origin TEXT NOT NULL,
            database_generation TEXT NOT NULL,
            backend_epoch TEXT NOT NULL,
            task_id TEXT NOT NULL,
            start_id TEXT NOT NULL,
            authority_key_id TEXT NOT NULL,
            issuer_key_id TEXT NOT NULL,
            UNIQUE (database_generation, start_id),
            UNIQUE (database_generation, backend_epoch, task_id)
        )
    """
    version = 1

    def migrate(self, last_version: int, db_provider: DBProviderWrapper) -> None:
        # The first schema is created by the database during registration.
        pass


def _matches(pattern: re.Pattern[str], value: Any) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _message(domain: bytes, fields: tuple[str, ...], value: dict[str, Any]) -> bytes:
    return domain + json.dumps(
        [value[field] for field in fields], ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def _base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _read_signing_seed(path: pathlib.Path) -> bytes:
    if not path.is_absolute():
        raise ValueError("Expected an absolute key path")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as key_file:
        info = os.fstat(key_file.fileno())
        if (
            not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o077 or info.st_nlink != 1
        ):
            raise ValueError("Expected a private signing key")
        seed = key_file.read(67).decode("ascii").removesuffix("\n")
    if not _matches(_HEX32, seed):
        raise ValueError("Expected a 32-byte signing seed")
    return bytes.fromhex(seed)


class HistoryAssociation:
    def __init__(
        self, config: ConfigHelper, database: MoonrakerDatabase, history_table: str
    ) -> None:
        from libnacl.sign import Signer, Verifier

        self.server = config.get_server()
        self.database = database
        self.history_table = history_table
        self.origin: str = config.get("origin")
        origin_match = _ORIGIN.fullmatch(self.origin)
        port = int(origin_match[1]) if origin_match else 0
        if not 1 <= port <= 65535 or port == 80:
            raise self.server.error("Invalid screen history association origin")
        issuer_key: str = config.get("issuer_public_key")
        signing_key = pathlib.Path(config.get("signing_key_path")).expanduser()
        try:
            if not _matches(_HEX32, issuer_key):
                raise ValueError("Invalid issuer key")
            self.issuer = Verifier(issuer_key.encode("ascii"))
            self.signer = Signer(_read_signing_seed(signing_key))
        except (OSError, ValueError, AttributeError):
            raise self.server.error("Invalid screen history association keys") from None
        if self.signer.vk.hex() == issuer_key:
            raise self.server.error("Screen history issuer and proof keys must differ")
        self.issuer_key_id = hashlib.sha256(bytes.fromhex(issuer_key)).hexdigest()
        self.authority_key_id = hashlib.sha256(
            _SPKI_ED25519_PREFIX + self.signer.vk
        ).hexdigest()
        self.database.enable_history_generation()
        self.database.register_table(HistoryBindingsDefinition())
        self.server.register_endpoint(
            "/server/history/association", RequestType.GET | RequestType.POST,
            self._handle_request
        )

    def verify_receipt(self, receipt: Any, filename: str) -> dict[str, str] | None:
        if (
            not isinstance(receipt, dict)
            or receipt.keys() != {*_RECEIPT_FIELDS, "signature"}
        ):
            return None
        if (
            receipt["origin"] != self.origin
            or receipt["authorityKeyId"] != self.authority_key_id
            or receipt["filename"] != filename
            or not isinstance(filename, str) or not 1 <= len(filename) <= 4096
            or any(part in ("", ".", "..") for part in filename.split("/"))
            or "\\" in filename
            or any(ord(char) < 32 or ord(char) == 127 for char in filename)
            or not _matches(_HEX32, receipt["fileSha256"])
            or not _matches(_UUID4, receipt["databaseGeneration"])
            or not _matches(_UUID4, receipt["startId"])
            or not _matches(_IDENTIFIER, receipt["backendEpoch"])
            or not _matches(_IDENTIFIER, receipt["taskId"])
            or not _matches(_SIGNATURE, receipt["signature"])
        ):
            return None
        signature = base64.urlsafe_b64decode(receipt["signature"] + "==")
        if _base64url(signature) != receipt["signature"]:
            return None
        try:
            message = _message(
                b"screen-history-start-receipt-v1\0", _RECEIPT_FIELDS, receipt
            )
            self.issuer.verify(signature + message)
        except (ValueError, TypeError):
            return None
        return dict(receipt)

    def record_binding(
        self, conn: sqlite3.Connection, row_id: str, job_id: int,
        receipt: dict[str, str]
    ) -> None:
        try:
            generation = self.database.require_history_generation(conn)
        except self.server.error:
            return
        if generation != receipt["databaseGeneration"]:
            return
        # Keep consumed receipts after deletion. An old job ID can be reused,
        # but it cannot match the immutable row ID on a new history row.
        consumed = conn.execute(
            f"SELECT 1 FROM {BINDINGS_TABLE} WHERE database_generation = ? "
            "AND (start_id = ? OR (backend_epoch = ? AND task_id = ?))",
            (generation, receipt["startId"], receipt["backendEpoch"], receipt["taskId"])
        ).fetchone()
        if consumed is not None:
            return
        cursor = conn.execute(
            f"INSERT INTO {BINDINGS_TABLE} VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                row_id, job_id, self.origin, generation, receipt["backendEpoch"],
                receipt["taskId"], receipt["startId"], self.authority_key_id,
                self.issuer_key_id
            )
        )
        if cursor.rowcount != 1:
            raise self.server.error("Unable to insert screen history binding", 500)

    def read_jobs(
        self, conn: sqlite3.Connection, sql: str, args: list[Any]
    ) -> list[dict[str, Any]]:
        rows = [dict(row) for row in conn.execute(sql, args)]
        try:
            generation = self.database.require_history_generation(conn)
        except self.server.error:
            return rows
        for row in rows:
            row_id = row.get(HISTORY_ROW_ID)
            if row_id is None:
                continue
            result = self._lookup_binding(conn, row["job_id"], row_id, generation)
            if result is not None:
                row["rowId"] = row_id
                row["databaseGeneration"] = generation
        return rows

    def _lookup_binding(
        self, conn: sqlite3.Connection, job_id: int, row_id: str, generation: str
    ) -> sqlite3.Row | None:
        return conn.execute(
            f"SELECT binding.* FROM {BINDINGS_TABLE} AS binding "
            f"JOIN {self.history_table} AS job "
            f"ON job.{HISTORY_ROW_ID} = binding.row_id "
            "AND job.job_id = binding.job_id "
            "WHERE binding.job_id = ? AND binding.row_id = ? AND binding.origin = ? "
            "AND binding.database_generation = ? AND binding.authority_key_id = ? "
            "AND binding.issuer_key_id = ?",
            (
                job_id, row_id, self.origin, generation,
                self.authority_key_id, self.issuer_key_id
            )
        ).fetchone()

    async def _handle_request(self, request: WebRequest) -> dict[str, str]:
        args = request.get_args()
        if request.get_request_type() == RequestType.GET:
            if args:
                raise self.server.error("Invalid history association request", 400)
            return await self.database.queue_sql_callback(self._describe)
        if (
            args.keys() != set(_PROOF_FIELDS) or args["origin"] != self.origin
            or not _matches(_UUID4, args["databaseGeneration"])
            or not _matches(_UUID4, args["rowId"])
            or not _matches(_JOB_ID, args["jobId"])
            or not _matches(_HEX32, args["challenge"])
        ):
            raise self.server.error("Invalid screen history association challenge", 400)
        job_id = int(args["jobId"], 16)
        if not 1 <= job_id <= 0x7FFFFFFFFFFFFFFF or f"{job_id:06X}" != args["jobId"]:
            raise self.server.error("Invalid screen history association challenge", 400)
        return await self.database.queue_sql_callback(
            lambda conn: self._prove(conn, job_id, args)
        )

    def _describe(self, conn: sqlite3.Connection) -> dict[str, str]:
        return {
            "origin": self.origin,
            "databaseGeneration": self.database.require_history_generation(conn),
            "authorityKeyId": self.authority_key_id
        }

    def _prove(
        self, conn: sqlite3.Connection, job_id: int, args: dict[str, str]
    ) -> dict[str, str]:
        generation = self.database.require_history_generation(conn)
        if generation != args["databaseGeneration"]:
            raise self.server.error("Screen history association unavailable", 404)
        result = self._lookup_binding(conn, job_id, args["rowId"], generation)
        if result is None:
            raise self.server.error("Screen history association unavailable", 404)
        binding = {
            **args,
            "backendEpoch": result["backend_epoch"],
            "taskId": result["task_id"],
            "startId": result["start_id"]
        }
        message = _message(
            b"screen-isolated-history-binding-v1\0",
            (*_PROOF_FIELDS, "backendEpoch", "taskId", "startId"),
            binding
        )
        binding["signature"] = _base64url(self.signer.signature(message))
        return binding
