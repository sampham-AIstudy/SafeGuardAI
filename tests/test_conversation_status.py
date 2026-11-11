"""Observed history with independent neutral messages, never benchmark inputs."""

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch

from safeguard.adapters.gateways.demo import DemoGateway
from safeguard.memory.conversation_status import ConversationKey, HistoryBoundary, HistoryError, HistoryLimits, InMemoryConversationStatus
from safeguard.ingress import AccessContext, InputLimits
from safeguard.adapters.norm import normalize


INPUT = InputLimits(65536,4096,16,4096,16,8)
LIMITS = HistoryLimits(16,64,1048576,32,524288,64,1048576)
CONTEXT = AccessContext("toy-account",frozenset(("toy-room","toy-garden")))
KEY = ConversationKey("demo","toy-account","toy-room")


def message(index="0",account="toy-account",room="toy-room"):
    return normalize(DemoGateway(account,clock=lambda:datetime(2026,1,2,tzinfo=timezone.utc)).receive(
        dict(thread=room,id=str(index),author="toy-reader",body="  Newly authored toy café note.\n",
             extra={"values":[None,False,1,"Toy"]})))


class ConversationStatusTests(unittest.TestCase):
    def rejected(self, operation, code):
        with self.assertRaises(HistoryError) as caught: operation()
        self.assertEqual(caught.exception.code,code)
        self.assertNotIn("PRIVATE",str(caught.exception))

    def test_complete_snapshots_are_exact_detached_prefixes(self):
        with InMemoryConversationStatus(message_limits=INPUT,limits=LIMITS) as history:
            originals=[message(i) for i in range(4)]
            boundaries=[history.append(CONTEXT,m) for m in originals]
            self.assertEqual(history.head(CONTEXT,KEY),boundaries[-1])
            for count,boundary in enumerate(boundaries,1):
                with self.subTest(count=count):
                    snapshot=history.snapshot(CONTEXT,boundary)
                    self.assertEqual(snapshot.key,KEY)
                    self.assertEqual(snapshot.observed_count,count)
                    self.assertEqual(snapshot.messages,tuple(originals[:count]))

    def test_source_snapshot_and_later_observations_do_not_mutate_prior_views(self):
        with InMemoryConversationStatus(message_limits=INPUT,limits=LIMITS) as history:
            source=message();before=deepcopy(source);boundary=history.append(CONTEXT,source)
            first=history.snapshot(CONTEXT,boundary)
            source["raw_payload"]["extra"]["values"].append("Source changed")
            first.messages[0]["raw_payload"]["extra"]["values"].append("Receiver changed")
            first.messages[0]["content_parts"][0]["text"]="Receiver text changed"
            history.append(CONTEXT,message("1"))
            second=history.snapshot(CONTEXT,boundary)
            self.assertEqual(second.messages,(before,))
            self.assertEqual(first.observed_count,1)

    def test_identical_ids_remain_separate_arrivals_without_timestamp_sorting(self):
        with InMemoryConversationStatus(message_limits=INPUT,limits=LIMITS) as history:
            for stamp in ("2026-01-03T00:00:00Z","2026-01-01T00:00:00Z"):
                event=message()["raw_payload"];event["sent_at"]=stamp
                normalized=normalize(DemoGateway("toy-account").receive(event))
                history.append(CONTEXT,normalized)
            snapshot=history.snapshot(CONTEXT,history.head(CONTEXT,KEY))
            self.assertEqual([m["message_id"] for m in snapshot.messages],["0","0"])
            self.assertEqual([m["sent_at"] for m in snapshot.messages],["2026-01-03T00:00:00Z","2026-01-01T00:00:00Z"])

    def test_accounts_and_conversations_with_same_native_ids_are_isolated(self):
        with InMemoryConversationStatus(message_limits=INPUT,limits=LIMITS) as history:
            for account in ("toy-account","toy-other"):
                for room in ("toy-room","toy-garden"):
                    context=AccessContext(account,CONTEXT.conversations)
                    boundary=history.append(context,message(account=account,room=room))
                    snapshot=history.snapshot(context,boundary)
                    self.assertEqual(snapshot.observed_count,1)
                    self.assertEqual(snapshot.messages[0]["account_id"],account)
                    self.assertEqual(snapshot.messages[0]["conversation_id"],room)
            self.assertEqual(history.stats["conversations"],4)

    def test_all_history_budgets_fail_without_partial_changes(self):
        size=INPUT.inspect(message())
        cases=[("max_conversations",1,"conversation_limit",True),
               ("max_messages",1,"message_limit",False),
               ("max_bytes",size,"byte_limit",False),
               ("max_conversation_messages",1,"conversation_message_limit",False),
               ("max_conversation_bytes",size,"conversation_byte_limit",False),
               ("max_account_messages",1,"account_message_limit",True),
               ("max_account_bytes",size,"account_byte_limit",True)]
        for field,value,code,other_room in cases:
            with self.subTest(field=field), InMemoryConversationStatus(message_limits=INPUT,limits=replace(LIMITS,**{field:value})) as history:
                boundary=history.append(CONTEXT,message());before=history.stats
                self.rejected(lambda:history.append(CONTEXT,message("1",room="toy-garden" if other_room else "toy-room")),code)
                self.assertEqual(history.stats,before)
                self.assertEqual(history.snapshot(CONTEXT,boundary).observed_count,1)

    def test_new_account_uses_separate_account_budgets(self):
        size=INPUT.inspect(message())
        with InMemoryConversationStatus(message_limits=INPUT,limits=replace(LIMITS,max_account_messages=1,max_account_bytes=size+100)) as history:
            history.append(CONTEXT,message())
            other=AccessContext("toy-other",CONTEXT.conversations)
            history.append(other,message(account="toy-other"))
            self.assertEqual(history.stats["messages"],2)

    def test_preflight_does_not_append_and_append_rechecks_changed_capacity(self):
        with InMemoryConversationStatus(message_limits=INPUT,limits=replace(LIMITS,max_messages=1)) as history:
            history.check(CONTEXT,message());self.assertEqual(history.stats["messages"],0)
            history.append(CONTEXT,message("1"))
            self.rejected(lambda:history.append(CONTEXT,message()),"message_limit")

    def test_permission_is_required_for_append_head_and_every_snapshot(self):
        with InMemoryConversationStatus(message_limits=INPUT,limits=LIMITS) as history:
            boundary=history.append(CONTEXT,message())
            for context in (AccessContext("toy-other",CONTEXT.conversations),AccessContext("toy-account",frozenset())):
                for operation in (lambda:history.append(context,message()),lambda:history.head(context,KEY),lambda:history.snapshot(context,boundary)):
                    with self.subTest(context=context):self.rejected(operation,"conversation_not_allowed")
            self.rejected(lambda:history.append({"account_id":"toy-account"},message()),"trusted_context_required")
            self.assertEqual(history.stats["messages"],1)

    def test_invalid_normalized_fields_and_forged_raw_mapping_are_rejected(self):
        mutations=[lambda m:m.update(message_schema_version="1.0"),lambda m:m.update(is_from_observed_account=0),
                   lambda m:m.update(PRIVATE_KEY_CANARY="PRIVATE_VALUE_CANARY"),
                   lambda m:m["content_parts"][0].update(text="Forged text"),
                   lambda m:m["raw_payload"].update(id="Other identity"),
                   lambda m:m.pop("sent_at")]
        with InMemoryConversationStatus(message_limits=INPUT,limits=LIMITS) as history:
            for mutate in mutations:
                with self.subTest(mutate=mutate):
                    record=message();mutate(record)
                    self.rejected(lambda:history.append(CONTEXT,record),"invalid_normalized_message")
            self.assertEqual(history.stats["messages"],0)

    def test_resources_and_non_json_are_checked_before_history_copy(self):
        with InMemoryConversationStatus(message_limits=replace(INPUT,max_text_chars=2),limits=LIMITS) as history:
            self.rejected(lambda:history.append(CONTEXT,message()),"text_too_long")
        with InMemoryConversationStatus(message_limits=INPUT,limits=LIMITS) as history:
            for value,code in ((float("nan"),"nonfinite_number"),(object(),"unsupported_json_value")):
                record=message();record["raw_payload"]["extra"]=value
                self.rejected(lambda:history.append(CONTEXT,record),code)
            record=message();record["raw_payload"]["extra"]=record
            self.rejected(lambda:history.append(CONTEXT,record),"cyclic_input")
            self.assertEqual(history.stats["messages"],0)

    def test_wrong_store_and_invalid_boundaries_cannot_expose_future_entries(self):
        with InMemoryConversationStatus(message_limits=INPUT,limits=LIMITS) as first, \
             InMemoryConversationStatus(message_limits=INPUT,limits=LIMITS) as second:
            boundary=first.append(CONTEXT,message());second.append(CONTEXT,message())
            self.rejected(lambda:second.snapshot(CONTEXT,boundary),"invalid_boundary")
            for count in (0,-1,2,True,"1"):
                with self.subTest(count=count):self.rejected(lambda:first.snapshot(CONTEXT,replace(boundary,observed_count=count)),"invalid_boundary")
            self.rejected(lambda:first.snapshot(CONTEXT,{}),"invalid_boundary")
            self.rejected(lambda:first.head(CONTEXT,ConversationKey("demo","toy-account","toy-garden")),"conversation_not_found")

    def test_lifecycle_thread_and_limit_configuration(self):
        history=InMemoryConversationStatus(message_limits=INPUT,limits=LIMITS)
        self.rejected(lambda:history.append(CONTEXT,message()),"history_not_open")
        with history:
            errors=[]
            def foreign():
                try:history.append(CONTEXT,message())
                except HistoryError as error:errors.append(error.code)
            thread=threading.Thread(target=foreign,daemon=True);thread.start();thread.join(1)
            self.assertFalse(thread.is_alive());self.assertEqual(errors,["wrong_thread"])
        self.rejected(lambda:history.head(CONTEXT,KEY),"history_not_open")
        self.rejected(lambda:history.__enter__(),"already_started")
        self.assertEqual(history.stats["messages"],0)
        for field in LIMITS.__dataclass_fields__:
            for value in (0,-1,True):
                with self.subTest(field=field,value=value),self.assertRaises(ValueError):replace(LIMITS,**{field:value})

    def test_state_and_snapshot_conversion_perform_no_io(self):
        record=message()
        with InMemoryConversationStatus(message_limits=INPUT,limits=LIMITS) as history:
            with patch("builtins.open",side_effect=AssertionError("No IO")), \
                 patch("pathlib.Path.open",side_effect=AssertionError("No IO")), \
                 patch("socket.socket",side_effect=AssertionError("No network")):
                boundary=history.append(CONTEXT,record)
                self.assertEqual(history.snapshot(CONTEXT,boundary).messages,(record,))

    def test_public_modules_import_in_fresh_processes_with_benchmark_guard(self):
        root=Path(__file__).resolve().parents[1]
        guard='''import os,sys
from pathlib import Path
root=Path.cwd()
forbidden=[root/p for p in ('data/benchmarks','evaluation','testset','devset','.audit-private')]
def audit(event,args):
 if event in ('open','os.listdir','os.scandir') and args and isinstance(args[0],(str,bytes,os.PathLike)):
  path=Path(os.path.abspath(os.fsdecode(args[0])))
  if any(path==p or p in path.parents for p in forbidden):raise AssertionError('Benchmark access prohibited')
sys.addaudithook(audit)
'''
        for module in ("safeguard.memory.conversation_status","safeguard.scam_detection.intake"):
            with self.subTest(module=module):
                result=subprocess.run([sys.executable,"-c",guard+"import "+module],cwd=root,
                    env={**os.environ,"PYTHONPATH":str(root/"src")},capture_output=True,text=True,timeout=5)
                self.assertEqual(result.returncode,0,result.stderr)
