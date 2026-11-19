"""Bounded Gemini Developer API access for the local partner demo."""

import asyncio
from datetime import datetime
import os
from pathlib import Path
import stat
import time
from zoneinfo import ZoneInfo

from safeguard.detection.gemini import FLASH_LITE_MODEL, GEMINI_PROVIDER, GeminiClient, GeminiConfig, _sdk_client
from safeguard.detection.media import IMAGE_SUFFIXES, MediaLimits, MediaSelection
from safeguard.detection.model_access import ModelSettings
from safeguard.detection.tools.evidence import PartReference
from safeguard.runtime import NativeMediaOptions


MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024
MAX_TEXT_FILE_BYTES = 16 * 1024
MAX_DAILY_REQUESTS = 500
PACIFIC = ZoneInfo("America/Los_Angeles")


def read_private_key(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or not 0 < info.st_size <= 512):
            raise ValueError("owner_only_key_file_required")
        key = os.read(fd, 513).decode("ascii").strip("\r\n")
        if not key or any(ord(char) < 33 or ord(char) > 126 for char in key):
            raise ValueError("invalid_key_file")
        return key
    finally:
        os.close(fd)


def native_media_options():
    def newest_supported(prepared):
        for message in reversed(prepared.to_dict()["messages"]):
            assets = {item["asset_id"]: item for item in message["assets"]}
            for part in reversed(message["content_parts"]):
                asset = assets.get(part.get("asset_id"))
                if asset is None:
                    continue
                filename = asset["filename"] or ""
                size = asset["declared_size_bytes"]
                if (Path(filename).suffix.lower() in IMAGE_SUFFIXES | {".pdf"}
                        and type(size) is int and 0 < size <= MAX_ATTACHMENT_BYTES):
                    return (MediaSelection(PartReference(**part["source_ref"]), skip_unrecognized=True),)
        return ()

    return NativeMediaOptions(MediaLimits(131072, 1, MAX_ATTACHMENT_BYTES, MAX_ATTACHMENT_BYTES), newest_supported)


class GeminiDemoUsage:
    """Reserve every send before HTTP. A failed or interrupted send consumes a slot."""

    def __init__(self, database, *, clock=time.time):
        self._database, self._clock = database, clock
        with database.transaction() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS gemini_demo_requests (
                id INTEGER PRIMARY KEY, started REAL NOT NULL, quota_day TEXT NOT NULL, status INTEGER)""")

    @staticmethod
    def _quota_day(timestamp):
        return datetime.fromtimestamp(timestamp, PACIFIC).date().isoformat()

    def summary(self):
        day = self._quota_day(self._clock())
        db = self._database.db
        used = db.execute("SELECT count(*) FROM gemini_demo_requests WHERE quota_day = ?", (day,)).fetchone()[0]
        provider_stop = db.execute("""SELECT 1 FROM gemini_demo_requests WHERE status IN (401, 402, 403, 404)
            OR (quota_day = ? AND status = 429) LIMIT 1""", (day,)).fetchone() is not None
        return {"quota_day": day, "used": used, "limit": MAX_DAILY_REQUESTS, "blocked": provider_stop}

    async def on_request(self, request):
        expected = f"/v1beta/models/{FLASH_LITE_MODEL}:generateContent"
        if (request.method != "POST" or request.url.scheme != "https"
                or request.url.host != "generativelanguage.googleapis.com" or request.url.path != expected):
            raise ValueError("unexpected_gemini_target")
        while True:
            now = self._clock()
            summary = self.summary()
            if summary["blocked"] or summary["used"] >= summary["limit"]:
                raise ValueError("gemini_budget_unavailable")
            latest = self._database.db.execute("SELECT max(started) FROM gemini_demo_requests").fetchone()[0]
            if latest is not None and latest > now:
                raise ValueError("gemini_clock_moved_backwards")
            recent = self._database.db.execute("""SELECT started FROM gemini_demo_requests
                WHERE started > ? ORDER BY started DESC LIMIT 5""", (now - 61,)).fetchall()
            if len(recent) < 5:
                break
            await asyncio.sleep(max(0.01, recent[-1][0] + 61 - now))
        with self._database.transaction() as db:
            record = db.execute("INSERT INTO gemini_demo_requests(started, quota_day) VALUES (?, ?)",
                                (now, self._quota_day(now))).lastrowid
        request.extensions["safeguard_demo_request_id"] = record

    async def on_response(self, response):
        ident = response.request.extensions["safeguard_demo_request_id"]
        with self._database.transaction() as db:
            db.execute("UPDATE gemini_demo_requests SET status = ? WHERE id = ?", (response.status_code, ident))

    def client_factory(self, **options):
        options["http_options"]["async_client_args"]["event_hooks"] = {
            "request": [self.on_request], "response": [self.on_response]}
        return _sdk_client(**options)

    def client_and_settings(self, key):
        client = GeminiClient(api_key=key, config=GeminiConfig(15 * 1024 * 1024, 65536, model=FLASH_LITE_MODEL),
                              client_factory=self.client_factory)
        settings = ModelSettings(GEMINI_PROVIDER, FLASH_LITE_MODEL, client.configuration_sha256, 1024, 131072, 65536)
        return client, settings
