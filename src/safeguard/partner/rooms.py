"""One durable store per demo conversation, with explicit scoped clearing."""

from contextlib import contextmanager
import os
from pathlib import Path
from shutil import rmtree
import stat

from safeguard.adapters.demo import create_demo_adapter
from safeguard.detection.tools.readers import Utf8TextReader
from safeguard.ingress import ProcessingLimits
from safeguard.memory.conversation_status import ConversationKey
from safeguard.partner.service import PartnerError, PartnerService
from safeguard.runtime import open_agent_runtime
from safeguard.warning import WarningPolicy


DEMO_OUTGOING_LABEL = "You"


def require_private_directory(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise PartnerError("unsafe_demo_directory")


@contextmanager
def open_demo_service(root, *, adapter, limits, client, settings, reader, native_media=None):
    with open_agent_runtime(root=root, limits=limits, client=client, settings=settings,
            input_fit=lambda binding, request: len(binding.presentation_json) <= 131072,
            reader=reader, native_media=native_media, private_outgoing_sender=DEMO_OUTGOING_LABEL) as runtime:
        service = PartnerService(runtime, adapter=adapter, limits=limits,
            processing_limits=ProcessingLimits(1, 1, 32768, 1, 1, limits.execution.timeout_seconds + 5),
            policy=WarningPolicy(runtime.memory, warn_on_scam=True), outgoing_label=DEMO_OUTGOING_LABEL)
        yield runtime, service


class DemoRooms:
    """Demo-only routing. The caller holds the exclusive root store lock."""

    def __init__(self, *, root, context, limits, client, settings, text_file_bytes, native_media=None):
        self.root, self.context, self.limits = Path(root), context, limits
        self.client, self.settings, self.native_media = client, settings, native_media
        self.reader = Utf8TextReader(text_file_bytes, text_file_bytes)
        self.adapter = create_demo_adapter()

    def _directory(self, context, name):
        if context != self.context or type(name) is not str or name not in context.conversations:
            raise PartnerError("conversation_not_allowed")
        return self.root / ("room-" + name)

    def _sync(self):
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _finish_clear(self, directory):
        tomb = directory.with_name(".clearing-" + directory.name)
        if tomb.exists() or tomb.is_symlink():
            require_private_directory(tomb)
            rmtree(tomb)
            self._sync()
        return tomb

    @contextmanager
    def _open(self, directory):
        try:
            self._finish_clear(directory)
            directory.mkdir(mode=0o700, exist_ok=True)
            require_private_directory(directory)
            if any(path.name not in {"memory", "originals"} for path in directory.iterdir()):
                raise PartnerError("unsafe_demo_directory")
        except OSError as error:
            raise PartnerError("clear_storage_unavailable") from error
        with open_demo_service(directory, adapter=self.adapter, limits=self.limits, client=self.client,
                settings=self.settings, reader=self.reader, native_media=self.native_media) as instance:
            yield instance

    def _view(self, runtime, service, context, name):
        view = service.conversation(context, name)
        view["revision"] = None
        if view["messages"]:
            head = runtime.memory.observations.head(context, ConversationKey(self.adapter.source, context.account_id, name))
            view["revision"] = f"{head.store_id}:{head.observed_count}"
        return view

    def conversation(self, context, name):
        with self._open(self._directory(context, name)) as (runtime, service):
            return self._view(runtime, service, context, name)

    def image_preview(self, context, name, store_id, number, index):
        with self._open(self._directory(context, name)) as (_, service):
            return service.image_preview(context, name, store_id, number, index)

    async def submit(self, context, name, raw):
        with self._open(self._directory(context, name)) as (_, service):
            return await service.submit(context, name, raw)

    def clear(self, context, name, revision):
        directory = self._directory(context, name)
        with self._open(directory) as (runtime, service):
            current = self._view(runtime, service, context, name)["revision"]
            if type(revision) is not str or revision != current:
                raise PartnerError("conversation_changed")
        try:
            tomb = directory.with_name(".clearing-" + directory.name)
            directory.rename(tomb)
            self._sync()
            self._finish_clear(directory)
        except OSError as error:
            raise PartnerError("clear_storage_unavailable") from error
        return {"messages": [], "active_warning": None, "revision": None}
