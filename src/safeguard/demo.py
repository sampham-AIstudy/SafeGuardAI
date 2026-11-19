"""Run an offline agent/SDK/Memory demonstration with fresh toy messages."""

import argparse
import asyncio
import io
import json
from pathlib import Path
import sys

from safeguard.adapters.demo import create_demo_adapter
from safeguard.detection.context import ContextLimits
from safeguard.detection.execution_host import ExecutionLimits
from safeguard.detection.gemini import GEMINI_MODEL, GEMINI_PROVIDER, GeminiClient, GeminiConfig, _sdk_client
from safeguard.detection.intake import DetectionRequest
from safeguard.detection.model_access import ModelSettings
from safeguard.detection.tools.evidence import EvidenceLimits
from safeguard.detection.tools.readers import Utf8TextReader
from safeguard.ingress import AccessContext, ConversationIngress, InputLimits, ProcessingLimits
from safeguard.memory.conversation_status import ConversationKey, HistoryBoundary, HistoryLimits, StateLimits
from safeguard.memory.original_assets import AssetLimits
from safeguard.runtime import AgentLimits, open_agent_runtime
from safeguard.storage.local import StorageLimits


MODE = "offline-http-replay"
DUMMY_KEY = "offline-agent-demo-dummy-key"
TOY_FILE = b"A newly authored workshop note: bring a pencil and a blank notebook.\n"


def demo_limits():
    """Small local demonstration limits, not deployment defaults."""
    return AgentLimits(
        input=InputLimits(32768, 8192, 24, 8192, 16, 8),
        history=HistoryLimits(8, 32, 524288, 16, 262144, 32, 524288),
        state=StateLimits(32, 524288, 16, 262144, 32, 524288, 65536, 24, 8192, 16),
        assets=AssetLimits(8192, 65536, 16, 65536, 16, 1024),
        storage=StorageLimits(8388608, 0.1),
        context=ContextLimits(16, 262144, 131072, 32768, 64, 16),
        execution=ExecutionLimits(131072, 4096, 8192, 32768, 8192, 65536,
            4, 2, 1, 16, 24, 8192, 10.0),
        evidence=EvidenceLimits(131072, 8192, 8, 8192, 32768, 256))


class OfflineSdk:
    """Return fixed protocol controls through real SDK serialization, with no inference."""

    def __init__(self):
        self.requests = 0
        self.transports = []

    def __call__(self, **options):
        import httpx

        owner = self

        class SyncTransport(httpx.BaseTransport):
            closed = False

            def handle_request(self, request):
                raise RuntimeError("unexpected_sync_request")

            def close(self):
                self.closed = True

        class AsyncTransport(httpx.AsyncBaseTransport):
            closed = False

            async def handle_async_request(self, request):
                if request.url.host != "generativelanguage.googleapis.com" or request.headers.get("x-goog-api-key") != DUMMY_KEY:
                    raise RuntimeError("unexpected_demo_target")
                owner.requests += 1
                body = json.loads(request.content)
                presentation = json.loads(body["contents"][0]["parts"][0]["text"])
                trace = presentation["interaction_trace"]
                if not trace:
                    output = dict(kind="tool_requests", public_text=None, calls=[dict(
                        tool_call_id="read-workshop-note", name="read-evidence",
                        arguments=dict(observation_number=1, part_index=1))])
                else:
                    if trace[-1]["outcome"]["payload"]["status"] != "extracted":
                        raise RuntimeError("demo_reader_did_not_extract")
                    output = dict(kind="structured_result", profile=presentation["output_profile"])
                    output["profile"] = {key: output["profile"][key] for key in ("name", "version")}
                    output.update(payload=dict(verdict="insufficient_evidence",
                        rationale="Offline protocol fixture. No model assessed this conversation."),
                        supporting=[], counter=[], unresolved=[dict(observation_number=1, part_index=1)])
                return httpx.Response(200, json=dict(candidates=[dict(
                    content=dict(role="model", parts=[dict(text=json.dumps(dict(output=output)))]),
                    finishReason="STOP", index=0)], modelVersion="offline-demo-control"))

            async def aclose(self):
                self.closed = True

        sync, asynchronous = SyncTransport(), AsyncTransport()
        self.transports.extend((sync, asynchronous))
        options["http_options"]["client_args"]["transport"] = sync
        options["http_options"]["async_client_args"]["transport"] = asynchronous
        return _sdk_client(**options)


async def run_demo(root):
    limits, sdk = demo_limits(), OfflineSdk()
    client = GeminiClient(api_key=DUMMY_KEY, config=GeminiConfig(262144, 65536), client_factory=sdk)
    settings = ModelSettings(GEMINI_PROVIDER, GEMINI_MODEL, client.configuration_sha256, 1024, 131072, 65536)
    access = AccessContext("offline-demo-account", frozenset(("workshop",)))
    records, saved = [], None
    for number in (1, 2):
        # Closing and reopening here exercises the same assembly used by callers.
        with open_agent_runtime(root=root, limits=limits, client=client, settings=settings,
                input_fit=lambda binding, request: len(binding.presentation_json) <= 131072,
                reader=Utf8TextReader(8192, 8192)) as runtime:
            if saved is not None and runtime.memory.detector.snapshot(access, saved[0]) != saved[1]:
                raise RuntimeError("restart_analysis_mismatch")

            async def consume(snapshot):
                head = runtime.memory.observations.head(access, snapshot.key)
                boundary = HistoryBoundary(snapshot.key, snapshot.observed_count, head.store_id)
                outcome = await runtime.detection.run(DetectionRequest(boundary, access))
                records.append(outcome.to_dict())
                if outcome.status != "completed":
                    raise RuntimeError("demo_assessment_failed")

            async with ConversationIngress(consume, input_limits=limits.input,
                    processing_limits=ProcessingLimits(1, 4, 131072, 4, 4, 15.0),
                    adapter=create_demo_adapter(), intake=runtime.detection.host.intake) as ingress:
                if number == 1:
                    native = dict(thread="workshop", id="workshop-note", author="organizer",
                        content_parts=[dict(kind="text", text="The workshop materials are attached."),
                            dict(kind="file", asset_id="materials")],
                        assets=[dict(asset_id="materials", filename="materials.txt")])
                    with io.BytesIO(TOY_FILE) as stream:
                        ticket = ingress.submit_files(native, {"materials": stream}, access, store=runtime.originals)
                else:
                    ticket = ingress.submit(dict(thread="workshop", id="workshop-followup", author="participant",
                        body="I will bring the notebook to the workshop."), access)
                admission = await ticket.wait()
                if admission.status != "completed":
                    raise RuntimeError("demo_ingress_failed")
            boundary = runtime.memory.observations.head(access, ConversationKey("demo", access.account_id, "workshop"))
            saved = boundary, runtime.memory.detector.snapshot(access, boundary)
            if saved[1].version != number:
                raise RuntimeError("demo_analysis_version_mismatch")
    if sdk.requests != 4 or not all(transport.closed for transport in sdk.transports):
        raise RuntimeError("demo_transport_mismatch")
    return dict(mode=MODE, successful=True, real_model_requests=0, mocked_http_requests=sdk.requests,
        restart_verified=True, results=records)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True,
        help="A new private directory for this offline demonstration; existing directories are refused.")
    args = parser.parse_args()

    def guard(event, values):
        if event in ("socket.connect", "socket.getaddrinfo"):
            raise PermissionError("Network is disabled in the offline demo")

    sys.addaudithook(guard)
    try:
        args.state_dir.mkdir(mode=0o700, exist_ok=False)
        print(json.dumps(asyncio.run(run_demo(args.state_dir)), ensure_ascii=False, sort_keys=True))
    except Exception:
        print(json.dumps(dict(mode=MODE, successful=False, error="offline_demo_failed")))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
