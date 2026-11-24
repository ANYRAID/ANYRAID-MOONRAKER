# Offline integration tests for the SCREEN history association writer.

from __future__ import annotations

import asyncio
import base64
import hashlib
import inspect
import json
import os
import shutil
import sqlite3
import tempfile
import unittest
import uuid
from collections import defaultdict
from contextlib import asynccontextmanager, closing
from pathlib import Path
from unittest.mock import AsyncMock, patch

import libnacl

from moonraker.common import APITransport, RequestType, WebRequest
from moonraker.components.database import MoonrakerDatabase
from moonraker.components.history import History
from moonraker.components.history_association import HistoryAssociation
from moonraker.components.job_state import JobState
from moonraker.components.klippy_connection import KlippyConnection
from moonraker.confighelper import ConfigHelper, DictSourceWrapper
from moonraker.eventloop import EventLoop
from moonraker.utils import ServerError


ORIGIN = "http://127.0.0.1:17125"
FILENAME = "plate.gcode"
HISTORY_LIST = "/server/history/list"
HISTORY_JOB = "/server/history/job"
PROOF = "/server/history/association"
RECEIPT_KEY = "anyraid_start_receipt"
ISSUER_SEED = bytes.fromhex("12" * 32)
PROOF_SEED = bytes.fromhex("34" * 32)
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def wire_message(prefix, values):
    return prefix + json.dumps(
        values, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def b64url(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def receipt_signed(fields, secret):
    message = wire_message(b"screen-history-start-receipt-v1\0", list(fields.values()))
    signature = libnacl.crypto_sign(message, secret)[:64]
    return {**fields, "signature": b64url(signature)}


class OfflineServer:
    error = ServerError

    def __init__(self, directory):
        self.loop = EventLoop()
        self.directory = directory
        self.components = {"file_manager": OfflineFileManager()}
        self.endpoints = {}
        self.handlers = defaultdict(list)
        self.pending_events = []

    def get_event_loop(self):
        return self.loop

    def is_running(self):
        return False

    def get_app_args(self):
        return {
            "data_path": str(self.directory),
            "is_default_data_path": False,
            "instance_uuid": "test-moonraker-instance",
        }

    def lookup_component(self, name, default=None):
        return self.components.get(name, default)

    def add_log_rollover_item(self, *_args):
        pass

    def register_notification(self, *_args):
        pass

    def register_endpoint(self, path, methods, callback, **_kwargs):
        self.endpoints[path] = (methods, callback)

    register_debug_endpoint = register_endpoint

    def register_event_handler(self, event, callback):
        self.handlers[event].append(callback)

    def send_event(self, event, *args):
        async def dispatch():
            for callback in self.handlers[event]:
                result = callback(*args)
                if inspect.isawaitable(result):
                    await result

        return self.schedule(dispatch())

    def schedule(self, coroutine):
        task = asyncio.create_task(coroutine)
        self.pending_events.append(task)
        return task

    async def drain_events(self):
        while self.pending_events:
            events, self.pending_events = self.pending_events, []
            await asyncio.gather(*events)

    async def request(self, path, method=RequestType.GET, **args):
        methods, callback = self.endpoints[path]
        if method not in methods:
            raise AssertionError(f"Unexpected API method: {method}")
        return await callback(WebRequest(path, args, request_type=method))


class OfflineFileManager:
    def __init__(self):
        self.metadata = {}

    def get_metadata_storage(self):
        return self.metadata

    def check_file_exists(self, *_args):
        return True


class OfflineMoonraker:
    def __init__(self, directory, section):
        self.server = OfflineServer(directory)
        source = DictSourceWrapper()
        source.read_dict({"server": {}, **section})
        self.config = ConfigHelper(self.server, source, "server", {})
        self.database = MoonrakerDatabase(self.config)
        self.server.components["database"] = self.database
        self.job_state = JobState(self.config)
        self.server.components["job_state"] = self.job_state
        self.history = History(self.config)
        self.server.components["history"] = self.history
        self.job_state.last_print_stats = {"state": "standby", "filename": ""}

    async def init(self):
        await self.database.component_init()
        await self.history.component_init()

    async def rows(self):
        return (await self.server.request(HISTORY_LIST))["jobs"]

    async def generation(self):
        return (await self.server.request(PROOF))["databaseGeneration"]

    async def status(self, state=None, **fields):
        if state is not None:
            fields["state"] = state
        await self.job_state._status_update({"print_stats": fields}, 0.0)
        await self.server.drain_events()

    async def start(self, receipt=None):
        fields = {"filename": FILENAME, "total_duration": 0.0}
        if receipt is not None:
            fields[RECEIPT_KEY] = receipt
        await self.status("printing", **fields)

    async def complete(self):
        await self.status("complete", filename=FILENAME, total_duration=1.0)

    async def proof(self, generation, row, **changes):
        request = {
            "origin": ORIGIN,
            "databaseGeneration": generation,
            "jobId": row["job_id"],
            "rowId": row["rowId"],
            "challenge": "ab" * 32,
        }
        request.update(changes)
        return await self.server.request(PROOF, RequestType.POST, **request)


class ScreenHistoryAssociationTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="moonraker-history-test-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.issuer_public, self.issuer_secret = libnacl.crypto_sign_seed_keypair(
            ISSUER_SEED
        )
        self.proof_public, _ = libnacl.crypto_sign_seed_keypair(PROOF_SEED)
        key_file = self.directory / "proof.key"
        key_file.write_text(PROOF_SEED.hex(), encoding="ascii")
        key_file.chmod(0o600)
        self.section = {"history screen_association": {
            "origin": ORIGIN,
            "issuer_public_key": self.issuer_public.hex(),
            "signing_key_path": str(key_file),
        }}

    @asynccontextmanager
    async def instance(self, directory=None, *, enabled=True):
        printer_data = directory or self.directory
        printer_data.mkdir(exist_ok=True)
        moon = OfflineMoonraker(printer_data, self.section if enabled else {})
        try:
            await moon.init()
            yield moon
        finally:
            await moon.database.close()

    def receipt(self, generation, **adjustment):
        fields = {
            "origin": ORIGIN,
            "databaseGeneration": generation,
            "backendEpoch": "test-backend-epoch",
            "taskId": "test-task-id",
            "startId": "e1522360-9539-41fc-8392-ae50d05b403d",
            "authorityKeyId": hashlib.sha256(
                ED25519_SPKI_PREFIX + self.proof_public
            ).hexdigest(),
            "filename": FILENAME,
            "fileSha256": hashlib.sha256(b"isolated test bytes").hexdigest(),
        }
        fields.update(adjustment)
        return receipt_signed(fields, self.issuer_secret)

    def assert_unbound(self, job):
        self.assertNotIn("rowId", job)
        self.assertNotIn("databaseGeneration", job)
        self.assertNotIn(RECEIPT_KEY, job)

    def assert_proof_signature(self, proof):
        fields = (
            "origin", "jobId", "challenge", "databaseGeneration", "rowId",
            "backendEpoch", "taskId", "startId",
        )
        self.assertEqual(set(proof), {*fields, "signature"})
        message = wire_message(
            b"screen-isolated-history-binding-v1\0", [proof[key] for key in fields]
        )
        signature = base64.urlsafe_b64decode(proof["signature"] + "==")
        self.assertEqual(
            libnacl.crypto_sign_open(signature + message, self.proof_public), message
        )

    async def test_standard_history_available_without_association_config(self):
        async with self.instance(enabled=False) as moon:
            await moon.start()
            await moon.complete()
            (row,) = await moon.rows()
            self.assertEqual(row["filename"], FILENAME)
            self.assertEqual(row["status"], "completed")
            self.assert_unbound(row)
            self.assertNotIn(PROOF, moon.server.endpoints)
            path = moon.database.database_path

        # Recreate the pre-feature table schema while retaining the real
        # history record and the database's existing registration metadata.
        with closing(sqlite3.connect(path)) as conn, conn:
            conn.execute("ALTER TABLE job_history DROP COLUMN history_row_id")
            conn.execute("UPDATE table_registry SET version=1 WHERE name='job_history'")
        async with self.instance() as moon:
            (migrated,) = await moon.rows()
            self.assertEqual(row, migrated)

    async def test_same_file_with_stale_receipt_never_claims_an_intent(self):
        async with self.instance() as moon:
            receipt = self.receipt(await moon.generation())
            await moon.status(**{RECEIPT_KEY: receipt})
            await moon.start()
            await moon.complete()
            (ordinary,) = await moon.rows()
            self.assert_unbound(ordinary)

    async def test_inferred_start_on_terminal_notification_cannot_bind(self):
        async with self.instance() as moon:
            receipt = self.receipt(await moon.generation())
            await moon.status("complete", filename=FILENAME, **{RECEIPT_KEY: receipt})
            (ordinary,) = await moon.rows()
            self.assert_unbound(ordinary)

    async def test_subscription_snapshot_cannot_supply_fresh_start_receipt(self):
        async with self.instance() as moon:
            receipt = self.receipt(await moon.generation())
            socket_path = self.directory / "unused.sock"
            with patch.object(moon.config, "getpath", return_value=socket_path):
                connection = KlippyConnection(moon.config)

            class HistorySubscriber(APITransport):
                def send_status(self, status, eventtime):
                    status_update = moon.job_state._status_update(status, eventtime)
                    moon.server.schedule(status_update)

            connection.subscriptions[HistorySubscriber()] = {"print_stats": None}
            connection.subscription_cache["print_stats"] = {
                "state": "standby", "filename": FILENAME, RECEIPT_KEY: None,
            }
            response = {
                "eventtime": 0.0,
                "status": {"print_stats": {
                    "state": "printing", "filename": FILENAME, RECEIPT_KEY: receipt,
                }},
            }
            request = WebRequest(
                "objects/subscribe", {"objects": {"print_stats": None}},
                transport=APITransport(),
            )
            klippy_request = AsyncMock(return_value=response)
            with patch.object(connection, "_request_standard", klippy_request):
                await connection._request_subscripton(request)
            await moon.server.drain_events()
            (ordinary,) = await moon.rows()
            self.assert_unbound(ordinary)

    @unittest.skipUnless(os.name == "posix", "POSIX private signing key checks")
    async def test_insecure_key_file_disables_writer_registration(self):
        async with self.instance(enabled=False) as moon:
            source = DictSourceWrapper()
            source.read_dict(self.section)
            config = ConfigHelper(moon.server, source, "history screen_association", {})
            key_file = Path(config.get("signing_key_path"))
            key_file.chmod(0o644)
            with self.assertRaises(ServerError):
                HistoryAssociation(config, moon.database, "job_history")
            self.assertNotIn(PROOF, moon.server.endpoints)

    async def test_unsigned_or_wrongly_addressed_receipt_cannot_bind(self):
        async with self.instance() as moon:
            generation = await moon.generation()
            valid = self.receipt(generation)
            invalid_receipts = (
                {**valid, "taskId": "modified-signed-field"},
                {k: v for k, v in valid.items() if k != "signature"},
                self.receipt(generation, origin="http://127.0.0.1:17126"),
                self.receipt(generation, authorityKeyId="0" * 64),
                self.receipt(generation, filename="other.gcode"),
                self.receipt(generation, databaseGeneration=str(uuid.uuid4())),
            )
            for invalid in invalid_receipts:
                with self.subTest(receipt=invalid):
                    await moon.start(invalid)
                    await moon.complete()
                    self.assert_unbound((await moon.rows())[0])

    async def test_binding_survives_completion_and_restart(self):
        async with self.instance() as moon:
            generation = await moon.generation()
            receipt = self.receipt(generation)
            await moon.start(receipt)
            (row,) = await moon.rows()
            self.assertEqual(row["databaseGeneration"], generation)
            self.assertNotIn(RECEIPT_KEY, row)
            self.assertNotIn("history_row_id", row)
            self.assertNotIn("taskId", row)
            self.assertEqual(await moon.server.request(PROOF), {
                "origin": ORIGIN,
                "databaseGeneration": generation,
                "authorityKeyId": receipt["authorityKeyId"],
            })
            await moon.complete()
            completed = (await moon.rows())[0]
            self.assertEqual(completed["rowId"], row["rowId"])
            self.assertEqual(completed["status"], "completed")

        async with self.instance() as moon:
            self.assertEqual(await moon.generation(), generation)
            (reopened,) = await moon.rows()
            self.assertEqual(reopened["rowId"], row["rowId"])
            proof = await moon.proof(generation, reopened)
            self.assertEqual(proof["taskId"], receipt["taskId"])
            self.assertEqual(proof["backendEpoch"], receipt["backendEpoch"])
            self.assertEqual(proof["startId"], receipt["startId"])
            self.assertEqual(proof["jobId"], reopened["job_id"])
            self.assertEqual(proof["rowId"], reopened["rowId"])
            self.assert_proof_signature(proof)
            fresh_proof = await moon.proof(generation, reopened, challenge="cd" * 32)
            self.assert_proof_signature(fresh_proof)
            self.assertNotEqual(fresh_proof["signature"], proof["signature"])
            for changes in (
                {"rowId": str(uuid.uuid4())},
                {"jobId": "000002"},
                {"challenge": "a" * 63},
                {"origin": "http://127.0.0.1:17126"},
                {"taskId": "client-supplied-task"},
            ):
                with self.subTest(changes=changes), self.assertRaises(ServerError):
                    await moon.proof(generation, reopened, **changes)

    async def test_replayed_receipt_leaves_original_as_the_only_bound_history(self):
        async with self.instance() as moon:
            generation = await moon.generation()
            receipt = self.receipt(generation)
            await moon.start(receipt)
            await moon.start(receipt)
            (original,) = await moon.rows()
            await moon.complete()
            for retry in (
                receipt,
                self.receipt(generation, taskId="another-task"),
                self.receipt(generation, startId=str(uuid.uuid4())),
            ):
                await moon.start(retry)
                await moon.complete()
            *replacements, bound = await moon.rows()
            self.assertEqual(len(replacements), 3)
            self.assertEqual(bound["rowId"], original["rowId"])
            for replacement in replacements:
                self.assert_unbound(replacement)
            self.assert_proof_signature(await moon.proof(generation, bound))

    async def test_database_error_between_row_and_binding_rolls_back(self):
        for table in ("job_history", "screen_history_bindings"):
            with self.subTest(table=table):
                async with self.instance(self.directory / table) as moon:
                    generation = await moon.generation()
                    receipt = self.receipt(generation)
                    database_path = moon.database.database_path
                    with closing(sqlite3.connect(database_path)) as monitor:
                        monitor.execute(
                            f"CREATE TRIGGER fail_insert BEFORE INSERT ON {table} "
                            "BEGIN SELECT RAISE(ABORT, 'injected write failure'); END"
                        )
                        with self.assertRaises(sqlite3.IntegrityError):
                            await moon.start(receipt)
                        self.assertEqual(await moon.rows(), [])
                        for name in ("job_history", "screen_history_bindings"):
                            (count,) = monitor.execute(
                                f"SELECT count(*) FROM {name}"
                            ).fetchone()
                            self.assertEqual(count, 0)
                        monitor.execute("DROP TRIGGER fail_insert")
                    await moon.complete()
                    await moon.start(receipt)
                    (bound,) = await moon.rows()
                    self.assert_proof_signature(await moon.proof(generation, bound))

    async def test_reused_job_number_cannot_reuse_binding_or_receipt(self):
        async with self.instance() as moon:
            generation = await moon.generation()
            receipt = self.receipt(generation)
            await moon.start(receipt)
            await moon.complete()
            (bound,) = await moon.rows()
            await moon.server.request(
                HISTORY_JOB, RequestType.DELETE, uid=bound["job_id"]
            )
            await moon.start(receipt)
            await moon.complete()
            (replacement,) = await moon.rows()
            self.assertEqual(replacement["job_id"], bound["job_id"])
            self.assert_unbound(replacement)
            with self.assertRaises(ServerError):
                await moon.proof(generation, bound)

    async def test_independent_database_rejects_receipt_with_reused_job_number(self):
        async with self.instance() as old:
            generation = await old.generation()
            receipt = self.receipt(generation)
            await old.start(receipt)
            (bound,) = await old.rows()

        async with self.instance(self.directory / "replacement") as moon:
            self.assertNotEqual(await moon.generation(), generation)
            await moon.start(receipt)
            (replacement,) = await moon.rows()
            self.assertEqual(replacement["job_id"], bound["job_id"])
            self.assert_unbound(replacement)
            with self.assertRaises(ServerError):
                await moon.proof(generation, bound)

    async def test_replacing_database_file_invalidates_copied_binding(self):
        backup = self.directory / "backup.sqlite"
        async with self.instance() as moon:
            generation = await moon.generation()
            await moon.start(self.receipt(generation))
            await moon.complete()
            (bound,) = await moon.rows()
            path = moon.database.database_path
            await moon.database.backup_database(backup)

        # Keep the old SQLite file alive while replacing its original path so the
        # filesystem cannot recycle its file identity for the replacement.
        path.rename(path.with_suffix(".original"))
        shutil.copyfile(backup, path)
        async with self.instance() as moon:
            self.assertNotEqual(await moon.generation(), generation)
            (copied,) = await moon.rows()
            self.assertEqual(copied["job_id"], bound["job_id"])
            self.assert_unbound(copied)
            with self.assertRaises(ServerError):
                await moon.proof(generation, bound)

    async def test_restored_saved_rows_never_offer_old_binding(self):
        backup = self.directory / "backup.sqlite"
        async with self.instance() as moon:
            generation = await moon.generation()
            receipt = self.receipt(generation)
            await moon.start(receipt)
            await moon.complete()
            (bound,) = await moon.rows()
            await moon.database.backup_database(backup)
            await moon.database.restore_database(backup)
            with self.assertRaises(ServerError):
                await moon.proof(generation, bound)

        async with self.instance() as moon:
            new_generation = await moon.generation()
            self.assertNotEqual(new_generation, generation)
            (restored,) = await moon.rows()
            self.assertEqual(restored["job_id"], bound["job_id"])
            self.assertEqual(restored["status"], "completed")
            self.assert_unbound(restored)
            with self.assertRaises(ServerError):
                await moon.proof(generation, bound)

            new_receipt = self.receipt(
                new_generation, taskId="task-after-restore", startId=str(uuid.uuid4())
            )
            await moon.start(new_receipt)
            await moon.complete()
            new_job, old_job = await moon.rows()
            self.assertEqual(new_job["databaseGeneration"], new_generation)
            self.assertNotEqual(new_job["rowId"], bound["rowId"])
            self.assert_unbound(old_job)
            proof = await moon.proof(new_generation, new_job)
            self.assertEqual(proof["taskId"], new_receipt["taskId"])
            self.assertEqual(proof["startId"], new_receipt["startId"])
            self.assert_proof_signature(proof)

    async def test_interrupted_restore_copy_cannot_revive_revoked_generation(self):
        backup = self.directory / "before-job.sqlite"
        async with self.instance() as moon:
            generation = await moon.generation()
            await moon.database.backup_database(backup)
            await moon.start(self.receipt(generation))
            await moon.complete()
            (bound,) = await moon.rows()
            self.assert_proof_signature(await moon.proof(generation, bound))
            connect = sqlite3.connect

            class InterruptedRestoreSource(sqlite3.Connection):
                def backup(self, target, **kwargs):
                    raise sqlite3.OperationalError("injected restore copy failure")

            def connect_for_restore(path, *args, **kwargs):
                if path == str(backup):
                    kwargs["factory"] = InterruptedRestoreSource
                return connect(path, *args, **kwargs)

            with patch.object(sqlite3, "connect", connect_for_restore):
                with self.assertRaisesRegex(sqlite3.OperationalError, "restore copy"):
                    await moon.database.restore_database(backup)
            with self.assertRaises(ServerError):
                await moon.proof(generation, bound)

        async with self.instance() as moon:
            new_generation = await moon.generation()
            self.assertNotEqual(new_generation, generation)
            # The backup predated this row, so its presence proves that the old
            # SQLite contents survived the interruption at the copy boundary.
            (original,) = await moon.rows()
            self.assertEqual(original["job_id"], bound["job_id"])
            self.assertEqual(original["status"], "completed")
            self.assert_unbound(original)
            with self.assertRaises(ServerError):
                await moon.proof(generation, bound)
            with self.assertRaises(ServerError):
                await moon.proof(new_generation, bound)


if __name__ == "__main__":
    unittest.main()
