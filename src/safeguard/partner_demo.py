"""Serve the loopback Demo Messages app with an explicitly selected engine client."""

import argparse
import asyncio
from contextlib import ExitStack
from dataclasses import replace
from hashlib import sha256
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from importlib.resources import files
import json
from pathlib import Path
import re

from safeguard.adapters.demo import create_demo_adapter
from safeguard.demo import demo_limits
from safeguard.detection.assessment import SCAM_PROFILE
from safeguard.detection.execution_host import CapabilityReply
from safeguard.detection.gemini import FLASH_LITE_MODEL
from safeguard.detection.model_access import ModelSettings
from safeguard.detection.model_contract import encoded
from safeguard.detection.tools.readers import Utf8TextReader
from safeguard.ingress import AccessContext
from safeguard.memory.conversation_status import HistoryError, StateError
from safeguard.memory.original_assets import AssetError
from safeguard.partner import PartnerError, upload_wire_bytes
from safeguard.partner.live import (
    GeminiDemoUsage, MAX_ATTACHMENT_BYTES, MAX_TEXT_FILE_BYTES, native_media_options, read_private_key,
)
from safeguard.partner.rooms import DemoRooms, open_demo_service, require_private_directory
from safeguard.storage.local import LocalDatabase, StorageError


SCENARIOS = (
    dict(label="Library hours", body="The library opens at nine. Return books at the front desk.",
         verdict="no_scam_evidence", rationale="The message gives library hours and return instructions."),
    dict(label="Verification-code request", body="Please send me the secret verification code from your phone.",
         verdict="scam", rationale="The sender asks for a private verification code."),
    dict(label="Unclear payment", body="Someone mentioned a payment but gave me no details.",
         verdict="insufficient_evidence", rationale="The purpose, recipient, and method of payment are unclear."),
)
DEMO_ACCESS = AccessContext("local-demo-partner", frozenset({"library", "marketplace"}))
_ROUTE = re.compile(r"/api/conversations/([a-z][a-z0-9-]{0,63})(/messages|/clear)?")
_IMAGE_ROUTE = re.compile(r"/api/conversations/([a-z][a-z0-9-]{0,63})/images/([0-9a-f]{32})/([0-9]{1,9})/([0-9]{1,9})")
_ERROR_STATUS = {"conversation_not_allowed": HTTPStatus.FORBIDDEN, "event_conflict": HTTPStatus.CONFLICT,
                 "conversation_changed": HTTPStatus.CONFLICT, "clear_unavailable": HTTPStatus.METHOD_NOT_ALLOWED,
                 "clear_storage_unavailable": HTTPStatus.SERVICE_UNAVAILABLE,
                 "processing_unavailable": HTTPStatus.SERVICE_UNAVAILABLE,
                 "attachment_too_large": HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                 "image_not_found": HTTPStatus.NOT_FOUND,
                 "original_unavailable": HTTPStatus.SERVICE_UNAVAILABLE}


async def fixture_model(binding, request):
    """Match only authored examples, with no API keys or networking."""
    reference = dict(observation_number=binding.prepared.observed_count, part_index=0)
    body = binding.prepared.resolve_part(reference).get("text")
    example = next((sample for sample in SCENARIOS if sample["body"] == body), None)
    if example is None:
        output = dict(kind="failure", code="unsupported_request")
    else:
        output = dict(kind="structured_result", profile=SCAM_PROFILE.identity(),
                      payload={field: example[field] for field in ("verdict", "rationale")},
                      supporting=[reference] if example["verdict"] == "scam" else [], counter=[],
                      unresolved=[reference] if example["verdict"] == "insufficient_evidence" else [])
    return CapabilityReply(encoded(dict(model_contract_version="1.0", call_id=request["call_id"],
        provider_attempted=example is not None, finish_reason="not_started" if example is None else "complete",
        output=output)))


class PartnerDemoServer(HTTPServer):
    """One local owner thread for SQLite, HTTP and the async service runner."""

    def __init__(self, port, *, service, runner, context, max_body_bytes, attachment_bytes, usage=None):
        self.service, self.runner, self.context = service, runner, context
        self.max_body_bytes = max_body_bytes
        self.attachment_bytes, self.usage = attachment_bytes, usage
        super().__init__(("127.0.0.1", port), Handler)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(5)
        return connection, address


class Handler(BaseHTTPRequestHandler):
    server: PartnerDemoServer

    def log_message(self, *_):
        pass

    def _send(self, status, content_type, body):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; "
                         "connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status, value):
        self._send(status, "application/json; charset=utf-8", encoded(value))

    def _bound_origin(self):
        expected = f"127.0.0.1:{self.server.server_port}"
        origin = self.headers.get_all("Origin", [])
        if self.headers.get_all("Host", []) != [expected] or origin not in ([], [f"http://{expected}"]):
            self._json(HTTPStatus.FORBIDDEN, {"error": "local_origin_required"})
            return False
        return True

    def _failure(self, error):
        if isinstance(error, PartnerError):
            self._json(_ERROR_STATUS.get(error.code, HTTPStatus.BAD_REQUEST), {"error": error.code})
        else:
            self._json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "storage_unavailable"})

    def do_GET(self):
        if not self._bound_origin():
            return
        if self.path in {"/", "/app.js"}:
            filename = "index.html" if self.path == "/" else "app.js"
            content_type = "text/html" if self.path == "/" else "text/javascript"
            self._send(HTTPStatus.OK, content_type + "; charset=utf-8",
                       files("safeguard.partner").joinpath("ui", filename).read_bytes())
            return
        if self.path == "/api/demo":
            usage = self.server.usage
            examples = [] if usage else [{field: sample[field] for field in ("label", "body")} for sample in SCENARIOS]
            self._json(HTTPStatus.OK, {"conversations": sorted(self.server.context.conversations), "examples": examples,
                "model": FLASH_LITE_MODEL if usage else None, "quota": usage.summary() if usage else None,
                "attachment_bytes": self.server.attachment_bytes, "can_clear": isinstance(self.server.service, DemoRooms)})
            return
        image = _IMAGE_ROUTE.fullmatch(self.path)
        if image is not None:
            try:
                media_type, data = self.server.service.image_preview(
                    self.server.context, image[1], image[2], int(image[3]), int(image[4]))
            except (PartnerError, HistoryError, StateError, AssetError) as error:
                self._failure(error)
            else:
                self._send(HTTPStatus.OK, media_type, data)
            return
        route = _ROUTE.fullmatch(self.path)
        if route is None or route[2] is not None:
            self._json(HTTPStatus.NOT_FOUND, {"error": "unknown_route"})
            return
        try:
            view = self.server.service.conversation(self.server.context, route[1])
        except (PartnerError, HistoryError, StateError, AssetError) as error:
            self._failure(error)
        else:
            self._json(HTTPStatus.OK, view)

    def do_POST(self):
        if not self._bound_origin():
            return
        route = _ROUTE.fullmatch(self.path)
        if route is None or route[2] is None:
            self._json(HTTPStatus.NOT_FOUND, {"error": "unknown_route"})
            return
        if self.headers.get_content_type() != "application/json" or self.headers.get("Transfer-Encoding") is not None:
            self._json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "bounded_json_required"})
            return
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or re.fullmatch(r"[0-9]{1,9}", lengths[0]) is None:
            self._json(HTTPStatus.LENGTH_REQUIRED, {"error": "content_length_required"})
            return
        length = int(lengths[0])
        if length > (512 if route[2] == "/clear" else self.server.max_body_bytes):
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "event_too_large"})
            return
        try:
            raw = self.rfile.read(length)
        except TimeoutError:
            self._json(HTTPStatus.REQUEST_TIMEOUT, {"error": "request_timeout"})
            return
        if len(raw) != length:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "incomplete_request"})
            return
        if route[2] == "/clear":
            self._clear(route[1], raw)
            return
        try:
            receipt = self.server.runner.run(self.server.service.submit(self.server.context, route[1], raw))
        except (PartnerError, HistoryError, StateError, AssetError) as error:
            self._failure(error)
        else:
            result = receipt.to_dict()
            if self.server.usage:
                result["quota"] = self.server.usage.summary()
            self._json(HTTPStatus.OK if receipt.duplicate else HTTPStatus.CREATED, result)

    def _clear(self, name, raw):
        try:
            if not isinstance(self.server.service, DemoRooms):
                raise PartnerError("clear_unavailable")
            try:
                value = json.loads(raw)
                if type(value) is not dict or set(value) != {"revision"} or type(value["revision"]) is not str:
                    raise ValueError()
            except (ValueError, RecursionError) as error:
                raise PartnerError("invalid_clear_request") from error
            view = self.server.service.clear(self.server.context, name, value["revision"])
        except (PartnerError, HistoryError, StateError, AssetError) as error:
            self._failure(error)
        else:
            self._json(HTTPStatus.OK, view)


def partner_demo_limits(*, live):
    limits = demo_limits()
    return replace(limits, assets=replace(limits.assets, max_file_bytes=MAX_ATTACHMENT_BYTES,
        max_total_bytes=4 * MAX_ATTACHMENT_BYTES, max_account_bytes=4 * MAX_ATTACHMENT_BYTES, chunk_bytes=65536),
        evidence=replace(limits.evidence, max_original_bytes=MAX_TEXT_FILE_BYTES, max_text_chars=MAX_TEXT_FILE_BYTES),
        state=replace(limits.state, max_conversation_records=2 * limits.history.max_conversation_messages,
            max_conversation_bytes=limits.state.max_bytes),
        execution=replace(limits.execution, timeout_seconds=60.0 if live else 10.0))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True, help="Private demo store, reusable on restart.")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--gemini-key-file", type=Path, help="Private key for Gemini 3.1 Flash-Lite on a nonbilled Free-tier project.")
    args = parser.parse_args()
    if not 0 <= args.port <= 65535:
        parser.error("port must be between 0 and 65535")
    limits = partner_demo_limits(live=args.gemini_key_file is not None)
    try:
        args.state_dir.mkdir(mode=0o700, exist_ok=True)
        require_private_directory(args.state_dir)
        legacy = (args.state_dir / "memory").exists()
        if legacy and args.gemini_key_file:
            parser.error("use a fresh state directory for the live demo")
        with ExitStack() as stack:
            runner = stack.enter_context(asyncio.Runner())
            usage, media = None, None
            client = fixture_model
            settings = ModelSettings("local-demo", "authored-fixtures", sha256(encoded(SCENARIOS)).hexdigest(), 1024, 131072, 65536)
            if not legacy:
                control = LocalDatabase(root=args.state_dir / "control", kind="partner-demo", limits=limits.storage)
                stack.callback(control.close)
                if args.gemini_key_file:
                    usage = GeminiDemoUsage(control)
                    client, settings = usage.client_and_settings(read_private_key(args.gemini_key_file))
                    media = native_media_options()
                service = DemoRooms(root=args.state_dir, context=DEMO_ACCESS, limits=limits, client=client,
                    settings=settings, text_file_bytes=MAX_TEXT_FILE_BYTES, native_media=media)
            else:
                _, service = stack.enter_context(open_demo_service(args.state_dir, adapter=create_demo_adapter(),
                    limits=limits, client=client, settings=settings,
                    reader=Utf8TextReader(MAX_TEXT_FILE_BYTES, MAX_TEXT_FILE_BYTES)))
            with PartnerDemoServer(args.port, service=service, runner=runner, context=DEMO_ACCESS,
                    max_body_bytes=upload_wire_bytes(limits), attachment_bytes=limits.assets.max_file_bytes, usage=usage) as server:
                print(json.dumps({"url": f"http://127.0.0.1:{server.server_port}/",
                                  "mode": "live-gemini" if usage else "offline-demo"}), flush=True)
                server.serve_forever()
    except KeyboardInterrupt:
        return 0
    except (OSError, ValueError, StorageError):
        print(json.dumps({"error": "demo_startup_failed"}), flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
