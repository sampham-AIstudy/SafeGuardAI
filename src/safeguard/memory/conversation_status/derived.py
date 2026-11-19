"""Atomic, versioned derived-state channels bound to admitted observed prefixes."""

from dataclasses import asdict, dataclass, field, fields
import hashlib
import inspect
import json
import threading
from types import MappingProxyType

from .contracts import HistoryBoundary, HistoryError
from .ports import DerivedState, ObservedHistory

CHANNELS = MappingProxyType({'detector': frozenset(('evidence', 'analysis')),
                             'warning_history': frozenset(('warnings',))})
JSON_OPTIONS = dict(ensure_ascii=False, sort_keys=True, allow_nan=False, separators=(',', ':'))


class StateError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def encoded(value):
    return json.dumps(value, **JSON_OPTIONS).encode('utf-8')


@dataclass(frozen=True, slots=True)
class StateLimits:
    max_records: int
    max_bytes: int
    max_conversation_records: int
    max_conversation_bytes: int
    max_account_records: int
    max_account_bytes: int
    max_record_bytes: int
    max_json_depth: int
    max_json_nodes: int
    max_references: int

    def __post_init__(self):
        if any(type(getattr(self, f.name)) is not int or getattr(self, f.name) <= 0 for f in fields(self)):
            raise StateError('invalid_state_limits')


@dataclass(frozen=True, slots=True)
class StateProfile:
    name: str
    version: str
    validate: object = field(repr=False)

    def __post_init__(self):
        if any(type(x) is not str or not x.strip() for x in (self.name, self.version)) or not callable(self.validate):
            raise StateError('invalid_state_profile')
        try:
            self.name.encode('utf-8');self.version.encode('utf-8')
        except UnicodeError:
            raise StateError('invalid_state_profile') from None
        if inspect.iscoroutinefunction(self.validate) or inspect.iscoroutinefunction(getattr(self.validate, '__call__', None)):
            raise StateError('invalid_state_profile')


@dataclass(frozen=True, slots=True)
class SourceReference:
    observation_number: int
    part_index: int

    def __post_init__(self):
        if type(self.observation_number) is not int or self.observation_number < 1 or type(self.part_index) is not int or self.part_index < 0:
            raise StateError('invalid_source_reference')


@dataclass(frozen=True, slots=True)
class StateWrite:
    namespace: str
    record_id: str
    payload_json: bytes = field(repr=False)
    references: tuple[SourceReference, ...] = ()


@dataclass(frozen=True, slots=True)
class StateRecord:
    namespace: str
    record_id: str
    version: int
    boundary: HistoryBoundary
    observations_sha256: str
    profile_name: str
    profile_version: str
    payload_json: bytes = field(repr=False)
    references: tuple[SourceReference, ...]

    def payload(self):
        return json.loads(self.payload_json)


@dataclass(frozen=True, slots=True)
class StateSnapshot:
    boundary: HistoryBoundary
    version: int
    records: tuple[StateRecord, ...]


@dataclass(frozen=True, slots=True)
class StateReceipt:
    boundary: HistoryBoundary
    version: int
    operation_id: str


class InMemoryDerivedState(DerivedState):
    """Trusted one-thread component. Versions/operation IDs are scoped per channel.

    All validation precedes one publication assignment. Every historical record
    version and retry fingerprint consumes configured capacity. No eviction,
    retention default, business labels or Policy decision is inferred.
    """
    def __init__(self, *, history: ObservedHistory, limits: StateLimits, profiles: dict):
        if not isinstance(history, ObservedHistory) or type(limits) is not StateLimits or type(profiles) is not dict:
            raise StateError('invalid_state_configuration')
        if not profiles or not set(profiles) <= frozenset.union(*CHANNELS.values()) or any(type(p) is not StateProfile for p in profiles.values()):
            raise StateError('invalid_state_configuration')
        self.history, self.limits, self.profiles = history, limits, MappingProxyType(dict(profiles))
        self._owner, self._closed, self._busy = threading.get_ident(), False, False
        # A single immutable-by-convention aggregate is replaced on successful commit.
        self._data = dict(records=(), versions={}, operations={}, bytes=0)

    def _check(self):
        if self._closed: raise StateError('state_closed')
        if getattr(self,'_broken',False): raise StateError('state_storage_broken')
        if threading.get_ident() != self._owner: raise StateError('wrong_thread')
        if self._busy: raise StateError('state_busy')

    def _observed(self, context, boundary):
        self._check()
        try: return self.history.snapshot(context, boundary)
        except HistoryError: raise StateError('invalid_observed_scope') from None

    @staticmethod
    def _channel(channel):
        if type(channel) is not str or channel not in CHANNELS: raise StateError('invalid_state_channel')
        return CHANNELS[channel]

    def _json(self, raw):
        from safeguard.ingress.limits import InputLimits, InputViolation
        limit = self.limits.max_record_bytes
        policy = InputLimits(limit, limit, self.limits.max_json_depth, self.limits.max_json_nodes, limit, limit)
        try:
            doc = policy.decode(raw)
            policy.inspect(doc)
            if type(doc) is not dict: raise StateError('invalid_state_payload')
            return doc
        except InputViolation: raise StateError('invalid_state_payload') from None

    def _text(self, value):
        if type(value) is not str or not value.strip() or len(value) > self.limits.max_record_bytes:
            raise StateError('invalid_state_identity')
        try: value.encode('utf-8')
        except UnicodeError: raise StateError('invalid_state_identity') from None

    def snapshot(self, context, boundary, *, channel):
        self._observed(context, boundary)
        allowed = self._channel(channel)
        selected = {}
        version = 0
        for record in self._data['records']:
            if record.boundary.key == boundary.key and record.namespace in allowed and record.boundary.observed_count <= boundary.observed_count:
                version = max(version, record.version)
                selected[(record.namespace, record.record_id)] = record
        return StateSnapshot(boundary, version, tuple(selected[key] for key in sorted(selected)))

    def commit(self, context, boundary, *, channel, expected_version, operation_id, writes):
        observed = self._observed(context, boundary)
        allowed = self._channel(channel)
        self._text(operation_id)
        if type(expected_version) is not int or expected_version < 0:
            raise StateError('invalid_state_version')
        if type(writes) is not tuple or not writes or len(writes) > self.limits.max_records:
            raise StateError('invalid_state_writes')
        self._busy = True
        try:
            identity = (boundary.key, channel)
            prepared, documents, used = [], [], set()
            history_digest = hashlib.sha256(encoded(observed.messages)).hexdigest()
            for write in writes:
                if type(write) is not StateWrite or type(write.namespace) is not str or write.namespace not in allowed:
                    raise StateError('namespace_not_allowed')
                if write.namespace not in self.profiles: raise StateError('namespace_not_configured')
                self._text(write.record_id)
                marker = (write.namespace, write.record_id)
                if marker in used: raise StateError('duplicate_state_record')
                used.add(marker)
                if type(write.references) is not tuple or len(write.references) > self.limits.max_references or any(type(ref) is not SourceReference for ref in write.references):
                    raise StateError('invalid_source_reference')
                if len(set(write.references)) != len(write.references): raise StateError('invalid_source_reference')
                for ref in write.references:
                    if ref.observation_number > observed.observed_count or ref.part_index >= len(observed.messages[ref.observation_number-1]['content_parts']):
                        raise StateError('invalid_source_reference')
                document = self._json(write.payload_json)
                canonical = encoded(document)
                profile = self.profiles[write.namespace]
                detached = json.loads(canonical)
                try:
                    returned = profile.validate(detached)
                    if inspect.iscoroutine(returned): returned.close()
                    if returned is not None or encoded(detached) != canonical: raise ValueError()
                except Exception: raise StateError('invalid_state_profile_payload') from None
                documents.append(dict(namespace=write.namespace,record_id=write.record_id,payload=document,
                    references=[asdict(ref) for ref in write.references],profile=dict(name=profile.name,version=profile.version)))
                prepared.append((write,canonical,profile))
            request = dict(boundary=asdict(boundary),channel=channel,expected_version=expected_version,
                operation_id=operation_id,writes=documents,observations_sha256=history_digest)
            fingerprint = hashlib.sha256(encoded(request)).hexdigest()
            retry_key = (boundary.key,channel,operation_id)
            cached = self._data['operations'].get(retry_key)
            if cached is not None:
                if cached[0] != fingerprint: raise StateError('operation_conflict')
                return cached[1]
            current = self._data['versions'].get(identity,0)
            if expected_version != current: raise StateError('state_conflict')
            if any(r.boundary.key == boundary.key and r.namespace in allowed and r.boundary.observed_count > boundary.observed_count for r in self._data['records']):
                raise StateError('stale_state_boundary')
            version = current + 1
            records = tuple(StateRecord(w.namespace,w.record_id,version,boundary,history_digest,p.name,p.version,raw,w.references) for w,raw,p in prepared)
            serialized = dict(operation_id=operation_id,request_sha256=fingerprint,version=version,
                records=[dict(namespace=r.namespace,record_id=r.record_id,version=r.version,boundary=asdict(r.boundary),
                    observations_sha256=r.observations_sha256,profile=dict(name=r.profile_name,version=r.profile_version),
                    payload=r.payload(),references=[asdict(ref) for ref in r.references]) for r in records])
            if any(len(encoded(item)) > self.limits.max_record_bytes for item in serialized['records']):
                raise StateError('state_record_limit')
            charged_bytes = len(encoded(serialized))
            self._capacity(boundary.key,records,charged_bytes)
            receipt = StateReceipt(boundary,version,operation_id)
            # No user callback runs after the complete candidate state has been checked.
            versions = dict(self._data['versions']); versions[identity] = version
            operations = dict(self._data['operations']); operations[retry_key] = (fingerprint,receipt)
            try:
                self._publish(dict(records=self._data['records']+records,versions=versions,operations=operations,
                                   bytes=self._data['bytes']+charged_bytes))
            except OSError:
                raise StateError('state_storage_failed') from None
            return receipt
        finally:
            self._busy = False

    def _capacity(self, key, records, charged_bytes):
        before = self._data['records']; limits=self.limits
        def group(match): return sum(1 for r in before if match(r))
        # Transaction byte charges include retry metadata. Keep scope subtotals separately.
        charges=self._charges()
        checks=((len(before)+len(records),limits.max_records,'state_record_count_limit'),
            (self._data['bytes']+charged_bytes,limits.max_bytes,'state_byte_limit'),
            (group(lambda r:r.boundary.key==key)+len(records),limits.max_conversation_records,'conversation_state_record_limit'),
            (charges.get(('conversation',key),0)+charged_bytes,limits.max_conversation_bytes,'conversation_state_byte_limit'),
            (group(lambda r:r.boundary.key.account_id==key.account_id)+len(records),limits.max_account_records,'account_state_record_limit'),
            (charges.get(('account',key.account_id),0)+charged_bytes,limits.max_account_bytes,'account_state_byte_limit'))
        for actual,limit,code in checks:
            if actual>limit: raise StateError(code)
        self._candidate_charges=dict(charges)
        for scope in (('conversation',key),('account',key.account_id)):
            self._candidate_charges[scope]=charges.get(scope,0)+charged_bytes

    def _charges(self): return self._data.get('charges',{})

    def _publish(self, data):
        data['charges']=self._candidate_charges
        self._data=data

    @property
    def stats(self):
        self._check()
        return dict(records=len(self._data['records']),bytes=self._data['bytes'],operations=len(self._data['operations']))

    def close(self):
        if threading.get_ident()!=self._owner: raise StateError('wrong_thread')
        if self._busy: raise StateError('state_busy')
        self._data=dict(records=(),versions={},operations={},bytes=0)
        self._closed=True
