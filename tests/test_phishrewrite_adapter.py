"""Native conversion and fixed-cohort behavior on fresh authored CSV-shaped toys."""

from dataclasses import FrozenInstanceError, replace
import hashlib
import json
import unittest
from unittest.mock import patch

from safeguard.evaluation.phishrewrite import (
    PHISHREWRITE_LEVELS, PhishRewriteError, PhishLimits, PhishCohortLimits,
    PhishProvenance, PhishInput, PhishCase, PhishParentGroup, PhishParentExclusion,
    adapt_original, adapt_rewrite, build_fixed_cohort,
)


LIMITS = PhishLimits(4096, 16384, 128)
COHORT_LIMITS = PhishCohortLimits(100, 1000, LIMITS)
LEVELS = ("0.25", "0.5", "0.75", "1.0")
TEXT = '\ufeff  Authored zinc note "shelf".\r\nq\u0307 🧭\x00 hxxps://sample.example.test/item  '
EXPECTED = ('{"text":"\ufeff  Authored zinc note \\"shelf\\".\\r\\nq\u0307 🧭\\u0000 '
    'hxxps://sample.example.test/item  "}').encode("utf-8")
_OMITTED = object()


def provenance(index, *, rewrite=False):
    return PhishProvenance("a" * 64, ("c" if rewrite else "b") * 64, index)


def original_row(index=1, *, label="1", text=TEXT):
    return dict(id="public-email-" + str(index), label=label, source="SOURCE_METADATA_PRIVATE",
        split="test", original_id="source-item-" + str(index), had_html="False",
        subject="UNSELECTED_SUBJECT_PRIVATE", body="UNSELECTED_BODY_PRIVATE", text=text)


def rewrite_row(parent, level="0.25", *, provider="writer-amber", text="New authored variant.\n"):
    return dict(original_id=parent.reference.original_id, source="SOURCE_METADATA_PRIVATE",
        severity=level, provider=provider, model="rewrite-model-metadata", temperature="0.7",
        refused="False", n_orig_urls="1", retained_urls_strict="True", retained_urls_primary="False",
        n_primary_urls="0", rewrite_subject="UNSELECTED_REWRITE_SUBJECT", rewrite_body="UNSELECTED_REWRITE_BODY",
        rewrite_text=text)


def original(index=1, *, row=_OMITTED, label="1", text=TEXT, **options):
    arguments = dict(case_id="original-case-" + str(index), provenance=provenance(index), limits=LIMITS)
    arguments.update(options)
    return adapt_original(original_row(index, label=label, text=text) if row is _OMITTED else row, **arguments)


def rewrite(parent_case, level="0.25", *, row=_OMITTED, provider="writer-amber", index=None,
        text="New authored variant.\n", **options):
    if index is None:
        index = parent_case.reference.provenance.row_index * 20 + LEVELS.index(level) + (10 if provider != "writer-amber" else 0)
    arguments = dict(case_id="rewrite-case-" + str(index), parent=parent_case.reference,
        provenance=provenance(index, rewrite=True), limits=LIMITS)
    arguments.update(options)
    return adapt_rewrite(rewrite_row(parent_case, level, provider=provider, text=text) if row is _OMITTED else row, **arguments)


def four(parent, *, provider="writer-amber", changes=None):
    rows = []
    for level in LEVELS:
        row = rewrite_row(parent, level, provider=provider, text="Authored variant " + level + " for " + str(parent.reference.provenance.row_index))
        row.update((changes or {}).get(level, {}))
        rows.append(rewrite(parent, level, provider=provider, row=row))
    return tuple(rows)


def cohort(originals, rewrites, **options):
    arguments = dict(provider="writer-amber", limits=COHORT_LIMITS)
    arguments.update(options)
    return build_fixed_cohort(originals, rewrites, **arguments)


class StringSubclass(str):
    pass


class PhishRewriteAdapterTests(unittest.TestCase):
    def error(self, operation, code):
        with self.assertRaises(PhishRewriteError) as caught:
            operation()
        self.assertEqual((caught.exception.code, caught.exception.args, str(caught.exception)), (code, (code,), code))

    def test_exact_projection_preserves_original_and_variant_separately(self):
        row = original_row()
        parent = original(row=row)
        self.assertEqual(parent.input.model_json(), EXPECTED)
        self.assertEqual(json.loads(EXPECTED), dict(text=TEXT))
        self.assertEqual(parent.reference.input_sha256, hashlib.sha256(EXPECTED).hexdigest())
        variant = rewrite(parent, text="  A distinct authored variant.\ufeff\x00\n")
        self.assertEqual(json.loads(variant.input.model_json()), dict(text="  A distinct authored variant.\ufeff\x00\n"))
        self.assertNotIn(b"Authored zinc", variant.input.model_json())
        self.assertEqual(variant.reference.parent, parent.reference)
        self.assertEqual(row, original_row())
        self.assertEqual(PHISHREWRITE_LEVELS, LEVELS)

    def test_metadata_is_excluded_without_traversing_unused_values(self):
        class Untouchable:
            def __str__(self):
                raise AssertionError("Unused value was stringified")
            __repr__ = __str__
        row = original_row()
        row.update(source=Untouchable(), subject=Untouchable(), body=Untouchable(), had_html=Untouchable())
        parent = original(row=row)
        changed = original(2, label="0", text=TEXT)
        self.assertEqual(parent.input.model_json(), changed.input.model_json())
        first = rewrite_row(parent, text=TEXT)
        first.update(source=Untouchable(), temperature=Untouchable(), n_orig_urls=Untouchable(),
            retained_urls_primary=Untouchable(), n_primary_urls=Untouchable(),
            rewrite_subject=Untouchable(), rewrite_body=Untouchable())
        variant = rewrite(parent, row=first)
        second = dict(first, provider="another-provider", model="another-model", severity="1.0",
            refused="TRUE", retained_urls_strict="")
        changed_variant = rewrite(parent, row=second, case_id="different-case", provenance=provenance(999, rewrite=True))
        self.assertEqual(variant.input.model_json(), changed_variant.input.model_json())
        self.assertEqual(variant.input.model_json(), EXPECTED)
        self.assertEqual(changed_variant.reference.retained_urls_strict, None)
        self.assertEqual(changed_variant.reference.model, "another-model")

    def test_immutable_records_and_mutable_caller_views_are_detached(self):
        row = original_row()
        parent = original(row=row)
        variant = rewrite(parent)
        row.clear()
        detached = json.loads(parent.input.model_json())
        detached["text"] = "modified copy"
        self.assertEqual(parent.input.model_json(), EXPECTED)
        for record, name in ((parent, "input"), (parent.input, "text"), (parent.reference, "label"),
                (variant.reference, "parent"), (parent.reference.provenance, "row_index")):
            with self.subTest(record=type(record).__name__, field=name), self.assertRaises(FrozenInstanceError):
                setattr(record, name, None)
        for record in (parent, parent.input, parent.reference, variant, variant.reference, parent.reference.provenance):
            self.assertNotIn("Authored zinc", repr(record))
            self.assertNotIn("source-item-", repr(record))
            self.assertNotIn("a" * 64, repr(record))

    def test_closed_native_headers_require_exact_builtin_keys_without_extra_traversal(self):
        parent = original()
        class DictSubclass(dict):
            pass
        for factory, convert in ((original_row, lambda row: original(row=row)),
                (lambda: rewrite_row(parent), lambda row: rewrite(parent, row=row))):
            good = factory()
            cases = [None, [], DictSubclass(good), {}, dict(good, extension=object()),
                {key: value for key, value in good.items() if key != "original_id"},
                {StringSubclass(key): value for key, value in good.items()}]
            changed = dict(good)
            changed[5] = changed.pop("original_id")
            cases.append(changed)
            for row in cases:
                with self.subTest(kind=type(row).__name__, native_fields=len(good)):
                    self.error(lambda: convert(row), "invalid_row")

    def test_exact_csv_labels_split_severity_and_flags(self):
        parent = original()
        for value in (True, 1, None, "", "01", " 1", "phishing", StringSubclass("1")):
            with self.subTest(label_type=type(value).__name__):
                self.error(lambda: original(row=dict(original_row(), label=value)), "invalid_label")
        for value in (None, "train", "Test", "test ", StringSubclass("test")):
            with self.subTest(split_type=type(value).__name__):
                self.error(lambda: original(row=dict(original_row(), split=value)), "invalid_split")
        for value in (None, 0.25, True, "0", "1", "0.50", " 0.5", "0.5 ", "NaN", StringSubclass("0.5")):
            with self.subTest(severity_type=type(value).__name__):
                self.error(lambda: rewrite(parent, row=dict(rewrite_row(parent), severity=value)), "invalid_severity")
        for field in ("refused", "retained_urls_strict"):
            for value in (None, True, 1, "1", "yes", "null", " True", "False ", StringSubclass("True")):
                with self.subTest(field=field, flag_type=type(value).__name__):
                    self.error(lambda: rewrite(parent, row=dict(rewrite_row(parent), **{field: value})), "invalid_flag")
        self.error(lambda: rewrite(parent, row=dict(rewrite_row(parent), refused="")), "invalid_flag")
        for value, parsed in (("True", True), ("TRUE", True), ("tRuE", True), ("false", False), ("FALSE", False), ("", None)):
            with self.subTest(flag=value):
                case = rewrite(parent, row=dict(rewrite_row(parent), retained_urls_strict=value))
                self.assertIs(case.reference.retained_urls_strict, parsed)

    def test_identity_text_and_provenance_types_are_strict(self):
        parent = original()
        for value in (None, False, b"raw", 1, StringSubclass("text"), "PRIVATE\udfff"):
            with self.subTest(text_type=type(value).__name__):
                self.error(lambda: original(text=value), "invalid_text")
                self.error(lambda: rewrite(parent, text=value), "invalid_text")
        for value in (None, False, "", " \n", StringSubclass("id"), "PRIVATE\ud800"):
            for field in ("id", "original_id"):
                with self.subTest(field=field, value_type=type(value).__name__):
                    self.error(lambda: original(row=dict(original_row(), **{field: value})), "invalid_identity")
            for field in ("provider", "model"):
                with self.subTest(field=field, value_type=type(value).__name__):
                    self.error(lambda: rewrite(parent, row=dict(rewrite_row(parent), **{field: value})), "invalid_identity")
        for field in ("release_sha256", "shard_sha256"):
            for value in (None, 64, "A" * 64, "z" * 64, "a" * 63, StringSubclass("a" * 64)):
                with self.subTest(field=field, value_type=type(value).__name__):
                    self.error(lambda: replace(provenance(1), **{field: value}), "invalid_provenance")
        for index in (-1, None, False, 1.0):
            with self.subTest(index_type=type(index).__name__):
                self.error(lambda: provenance(index), "invalid_provenance")

    def test_original_id_join_rejects_email_id_fallback_and_bad_parent(self):
        parent = original()
        self.assertNotEqual(parent.reference.email_id, parent.reference.original_id)
        variant = rewrite(parent)
        self.assertEqual(variant.reference.parent.original_id, parent.reference.original_id)
        self.error(lambda: rewrite(parent, row=dict(rewrite_row(parent), original_id=parent.reference.email_id)), "parent_mismatch")
        self.error(lambda: rewrite(parent, parent=None), "invalid_parent")
        ham = original(2, label="0")
        self.error(lambda: rewrite(ham), "invalid_parent")
        self.error(lambda: rewrite(parent, provenance=replace(provenance(23, rewrite=True), release_sha256="f" * 64)), "release_mismatch")

    def test_case_hash_and_direct_reference_construction(self):
        parent = original()
        variant = rewrite(parent)
        for observed, reference in ((None, parent.reference), (parent.input, None),
                (parent.input, replace(parent.reference, case_id="another-case")),
                (parent.input, replace(parent.reference, input_sha256="0" * 64)),
                (replace(parent.input, text="another string"), parent.reference)):
            with self.subTest(input_type=type(observed).__name__):
                self.error(lambda: PhishCase(observed, reference), "invalid_case")
        self.error(lambda: replace(parent.reference, label=True), "invalid_label")
        self.error(lambda: replace(parent.reference, split="train"), "invalid_split")
        self.error(lambda: replace(variant.reference, parent=original(2, label="0").reference), "invalid_parent")
        self.error(lambda: replace(variant.reference, retained_urls_strict=0), "invalid_flag")
        self.error(lambda: replace(variant.reference, refused=0), "invalid_flag")
        self.error(lambda: replace(variant.reference, severity="0.50"), "invalid_severity")

    def test_conversion_limits_at_equality_and_one_short(self):
        row = original_row()
        longest = max(map(len, ("original-case-1", row["id"], row["original_id"])))
        exact = PhishLimits(len(TEXT), len(EXPECTED), longest)
        self.assertEqual(original(limits=exact).input.model_json(), EXPECTED)
        for field, code in (("max_text_chars", "text_limit"), ("max_input_bytes", "input_byte_limit"),
                ("max_identifier_chars", "identifier_limit")):
            with self.subTest(field=field):
                self.error(lambda: original(limits=replace(exact, **{field: getattr(exact, field) - 1})), code)
        self.error(lambda: original(limits=replace(LIMITS, max_input_bytes=len(EXPECTED.decode("utf-8")))), "input_byte_limit")
        self.error(lambda: original(text="PRIVATE_LONG\udfff", limits=replace(LIMITS, max_text_chars=1)), "text_limit")
        parent = original()
        variant = rewrite(parent, text=TEXT)
        self.error(lambda: rewrite(parent, text=TEXT, limits=replace(LIMITS, max_input_bytes=len(variant.input.model_json()) - 1)), "input_byte_limit")

    def test_limit_configuration_rejects_wrong_types_and_nonpositive_values(self):
        for field in ("max_text_chars", "max_input_bytes", "max_identifier_chars"):
            for value in (None, False, 0, -1, 3.0, "3"):
                with self.subTest(field=field, value_type=type(value).__name__):
                    self.error(lambda: replace(LIMITS, **{field: value}), "invalid_limits")
        for field in ("max_originals", "max_rewrites"):
            for value in (None, False, 0, -1, 3.0):
                with self.subTest(field=field, value_type=type(value).__name__):
                    self.error(lambda: replace(COHORT_LIMITS, **{field: value}), "invalid_limits")
        self.error(lambda: replace(COHORT_LIMITS, case_limits=object()), "invalid_limits")
        self.error(lambda: original(limits=None), "invalid_limits")
        self.error(lambda: cohort((), (), limits=None), "invalid_limits")

    def test_empty_and_whitespace_content_remain_explicit(self):
        for text in ("", " \t\n", "\ufeff\x00"):
            with self.subTest(length=len(text)):
                parent = original(text=text)
                variant = rewrite(parent, text=text)
                self.assertEqual(json.loads(parent.input.model_json()), dict(text=text))
                self.assertEqual(json.loads(variant.input.model_json()), dict(text=text))
                self.assertEqual(parent.reference.label, 1)


class PhishCohortTests(unittest.TestCase):
    def error(self, operation, code):
        with self.assertRaises(PhishRewriteError) as caught:
            operation()
        self.assertEqual((caught.exception.code, str(caught.exception)), (code, code))

    def test_fixed_group_membership_unchanged_ham_and_unrewritten_population(self):
        parents = (original(3), original(1), original(2))
        ham = original(4, label="0", text="Untouched authored ham control.\n")
        result = cohort(parents + (ham,), four(parents[0]) + four(parents[1]))
        self.assertEqual([g.original.reference.original_id for g in result.parents], ["source-item-1", "source-item-3"])
        self.assertEqual(result.ham, (ham,))
        self.assertEqual(result.unrewritten, (parents[2].reference,))
        self.assertEqual(result.exclusions, ())
        self.assertEqual(result.baseline_cases(), (parents[1], parents[0], ham))
        for index, level in enumerate(LEVELS):
            with self.subTest(level=level):
                cases = result.rewrite_cases(level)
                self.assertEqual([case.reference.parent.original_id for case in cases[:-1]], ["source-item-1", "source-item-3"])
                self.assertEqual([case.reference.severity for case in cases[:-1]], [level, level])
                self.assertIs(cases[-1], ham)
                self.assertIs(result.parents[0].rewrites[index], cases[0])
        self.assertEqual(cohort(tuple(reversed(parents + (ham,))), tuple(reversed(four(parents[0]) + four(parents[1])))), result)
        self.assertEqual(json.loads(ham.input.model_json()), dict(text="Untouched authored ham control.\n"))

    def test_complete_exclusions_keep_false_unknown_refused_empty_and_missing_separate(self):
        parent = original()
        variants = four(parent, changes={
            "0.25": dict(retained_urls_strict="", refused="True", rewrite_text=" \t"),
            "0.5": dict(retained_urls_strict="False", refused="True"),
        })[:3]
        result = cohort((parent,), variants)
        self.assertEqual(result.parents, ())
        self.assertEqual(result.unrewritten, ())
        self.assertEqual(result.exclusions[0].level_reasons, (
            ("0.25", "retention_unknown"), ("0.25", "refused"), ("0.25", "empty_text"),
            ("0.5", "retention_false"), ("0.5", "refused"), ("1.0", "missing_level")))
        self.assertEqual(result.exclusions[0].parent, parent.reference)
        self.assertEqual(result.baseline_cases(), ())
        for level in LEVELS:
            self.assertEqual(result.rewrite_cases(level), ())

    def test_provider_populations_are_separate_and_unrelated_phishing_is_not_a_candidate(self):
        amber, jade, untouched = original(1), original(2), original(3)
        ham = original(4, label="0")
        variants = four(amber) + four(jade, changes={"0.5": dict(retained_urls_strict="False")})
        variants += four(amber, provider="writer-jade", changes={"0.75": dict(refused="True")}) + four(jade, provider="writer-jade")
        first = cohort((amber, jade, untouched, ham), variants)
        second = cohort((amber, jade, untouched, ham), variants, provider="writer-jade")
        self.assertEqual([g.original for g in first.parents], [amber])
        self.assertEqual([g.original for g in second.parents], [jade])
        self.assertEqual(first.ham, second.ham)
        self.assertEqual(first.unrewritten, (untouched.reference,))
        absent = cohort((amber, jade, untouched, ham), variants, provider="absent-provider")
        self.assertEqual(absent.parents, ())
        self.assertEqual(absent.exclusions, ())
        self.assertEqual(absent.unrewritten, (amber.reference, jade.reference, untouched.reference))

    def test_empty_inputs_and_missing_ham_are_valid_explicit_states(self):
        empty = cohort((), ())
        self.assertEqual((empty.parents, empty.ham, empty.exclusions, empty.unrewritten), ((), (), (), ()))
        parent = original()
        no_ham = cohort((parent,), four(parent))
        self.assertEqual(len(no_ham.parents), 1)
        self.assertEqual(no_ham.ham, ())
        ham = original(2, label="0", text="")
        no_candidates = cohort((parent, ham), ())
        self.assertEqual(no_candidates.ham, (ham,))
        self.assertEqual(no_candidates.unrewritten, (parent.reference,))
        self.assertEqual(no_candidates.baseline_cases(), (ham,))

    def test_count_preflight_and_case_readmission_limits(self):
        parent = original()
        variants = four(parent)
        exact = PhishCohortLimits(1, 4, LIMITS)
        self.assertEqual(len(cohort((parent,), variants, limits=exact).parents), 1)
        self.error(lambda: cohort((object(), object()), (), limits=replace(exact, max_originals=1)), "original_count_limit")
        self.error(lambda: cohort((), tuple(object() for _ in range(5)), limits=exact), "rewrite_count_limit")
        self.error(lambda: cohort([parent], variants), "invalid_cohort")
        self.error(lambda: cohort((parent,), list(variants)), "invalid_cohort")
        self.error(lambda: cohort((parent,), variants, limits=replace(exact, case_limits=replace(LIMITS, max_text_chars=1))), "text_limit")
        self.error(lambda: cohort((parent,), variants, limits=replace(exact, case_limits=replace(LIMITS, max_input_bytes=len(EXPECTED) - 1))), "input_byte_limit")
        self.error(lambda: cohort((), (), provider="x" * 129), "identifier_limit")
        direct_input = PhishInput("direct-case", "x" * 5000)
        direct_ref = replace(parent.reference, case_id="direct-case", input_sha256=hashlib.sha256(direct_input.model_json()).hexdigest())
        direct = PhishCase(direct_input, direct_ref)
        self.error(lambda: cohort((direct,), ()), "text_limit")
        long_ref = replace(parent.reference, original_id="x" * 129)
        long_case = PhishCase(parent.input, long_ref)
        self.error(lambda: cohort((long_case,), ()), "identifier_limit")

    def test_duplicate_case_email_original_provenance_and_variant_rows_are_errors(self):
        first = original(1)
        second = original(2)
        duplicate_case = original(2, case_id=first.input.case_id)
        self.error(lambda: cohort((first, duplicate_case), ()), "duplicate_case_id")
        same_email = PhishCase(second.input, replace(second.reference, email_id=first.reference.email_id))
        self.error(lambda: cohort((first, same_email), ()), "duplicate_email_id")
        same_original = PhishCase(second.input, replace(second.reference, original_id=first.reference.original_id))
        self.error(lambda: cohort((first, same_original), ()), "duplicate_original_id")
        same_provenance = PhishCase(second.input, replace(second.reference, provenance=first.reference.provenance))
        self.error(lambda: cohort((first, same_provenance), ()), "duplicate_provenance")
        variants = four(first)
        repeated = rewrite(first, index=999, case_id="duplicate-variant-case")
        self.error(lambda: cohort((first,), variants + (repeated,)), "duplicate_rewrite")
        outside = four(first, provider="writer-jade")
        repeated_outside = rewrite(first, provider="writer-jade", index=999, case_id="outside-duplicate")
        self.error(lambda: cohort((first,), variants + outside + (repeated_outside,)), "duplicate_rewrite")

    def test_orphan_changed_parent_and_mixed_releases_fail_before_provider_filter(self):
        parent = original()
        variants = four(parent, provider="writer-jade")
        self.error(lambda: cohort((), variants), "missing_parent")
        changed = original(text="A changed parent declaration.")
        self.error(lambda: cohort((changed,), variants), "parent_mismatch")
        other = original(2, provenance=replace(provenance(2), release_sha256="d" * 64))
        self.error(lambda: cohort((parent, other), ()), "release_mismatch")

    def test_group_and_cohort_constructors_enforce_roles_order_eligibility_and_disjointness(self):
        parent = original()
        variants = four(parent)
        group = PhishParentGroup(parent, variants)
        self.error(lambda: replace(group, rewrites=variants[:3]), "invalid_cohort")
        self.error(lambda: replace(group, rewrites=tuple(reversed(variants))), "invalid_cohort")
        bad = four(parent, changes={"0.25": dict(refused="True")})
        self.error(lambda: replace(group, rewrites=bad), "invalid_cohort")
        self.error(lambda: PhishParentGroup(original(2, label="0"), variants), "invalid_cohort")
        result = cohort((parent,), variants)
        self.error(lambda: replace(result, provider="another-provider"), "invalid_cohort")
        self.error(lambda: replace(result, ham=(parent,)), "invalid_cohort")
        self.error(lambda: replace(result, unrewritten=(parent.reference,)), "invalid_cohort")
        self.error(lambda: PhishParentExclusion(parent.reference, ()), "invalid_cohort")
        for issues in ((("0.25", "unknown"),), (("1.0", "empty_text"), ("0.25", "refused")),
                (("0.25", "missing_level"), ("0.25", "refused")),
                (("0.25", "retention_unknown"), ("0.25", "retention_false"))):
            with self.subTest(issues=issues):
                self.error(lambda: PhishParentExclusion(parent.reference, issues), "invalid_cohort")
        self.error(lambda: result.rewrite_cases("0.50"), "invalid_severity")

    def test_frozen_membership_has_no_dependency_on_later_predictions(self):
        parent = original()
        result = cohort((parent,), four(parent))
        before = tuple(case.input.case_id for case in result.baseline_cases())
        predictions = {case.input.case_id: "failed" for case in result.baseline_cases()}
        predictions.clear()
        self.assertEqual(tuple(case.input.case_id for case in result.baseline_cases()), before)
        with self.assertRaises(TypeError):
            build_fixed_cohort((parent,), four(parent), provider="writer-amber", limits=COHORT_LIMITS, predictions={})
        for record, field in ((result, "parents"), (result.parents[0], "rewrites")):
            with self.subTest(field=field), self.assertRaises(FrozenInstanceError):
                setattr(record, field, ())

    def test_public_conversion_and_cohort_calls_do_not_open_files_or_connect(self):
        original_data = original_row()
        with patch("builtins.open", side_effect=AssertionError("Conversion file IO")), \
                patch("io.open", side_effect=AssertionError("Conversion Path IO")), \
                patch("socket.getaddrinfo", side_effect=AssertionError("Conversion DNS")), \
                patch("socket.socket.connect", side_effect=AssertionError("Conversion connect")):
            parent = original(row=original_data)
            result = cohort((parent,), four(parent))
            self.assertEqual(result.parents[0].original.input.model_json(), EXPECTED)


class PhishEngineBoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def test_original_and_rewrite_use_separate_exact_bound_documents_and_terminal_paths(self):
        import test_agent_controller as agent
        import test_execution_host as fixture
        from safeguard.adapters.demo import create_demo_adapter
        from safeguard.detection.agent_controller import AgentController
        from safeguard.detection.assessment import SCAM_INSTRUCTIONS, SCAM_PROFILE
        from safeguard.detection.context import ContextPreparer
        from safeguard.detection.execution_host import ExecutionHost
        from safeguard.detection.intake import DetectionIntake
        from safeguard.detection.model_access import ModelAccess
        from safeguard.ingress import AccessContext
        from safeguard.memory.conversation_status import InMemoryConversationStatus

        parent = original(41, text="ORIGINAL_ONLY_AUTHORED_DOCUMENT\n A zinc shelf note.")
        variant = rewrite(parent, text="REWRITE_ONLY_AUTHORED_DOCUMENT\n A separate copper cabinet note.")
        cases = (("original-document", parent, "REWRITE_ONLY_AUTHORED_DOCUMENT"),
            ("rewrite-document", variant, "ORIGINAL_ONLY_AUTHORED_DOCUMENT"))
        access = AccessContext("phish-engine-toy-account", frozenset(room for room, _, _ in cases))
        adapter = create_demo_adapter(clock=lambda: fixture.NOW)
        ref = dict(observation_number=1, part_index=0)
        future = "FUTURE_ONLY_DOCUMENT_EXCLUDED"
        with InMemoryConversationStatus(message_limits=fixture.INPUT, limits=fixture.HISTORY) as history:
            intake = DetectionIntake(history)
            requests = {}
            for room, case, _ in cases:
                message = adapter.receive(dict(thread=room, id="case-document", author="evaluation-document",
                    body=case.input.model_json().decode("utf-8")), account_id=access.account_id, conversation_id=room)
                requests[room] = intake.record(message, access)
                later = adapter.receive(dict(thread=room, id="later-document", author="evaluation-document", body=future),
                    account_id=access.account_id, conversation_id=room)
                intake.record(later, access)
            for room, case, counterpart in cases:
                contexts = []
                for mode in ("valid", "invalid", "unavailable"):
                    with self.subTest(room=room, mode=mode):
                        finalized = []
                        def finish(binding, request):
                            visible = json.loads(binding.presentation_json)
                            observed = visible["observed_context"]
                            self.assertEqual(observed["observed_count"], 1)
                            self.assertEqual(len(observed["messages"]), 1)
                            body = observed["messages"][0]["content_parts"][0]["text"]
                            self.assertEqual(body.encode("utf-8"), case.input.model_json())
                            self.assertEqual(json.loads(body), dict(text=case.input.text))
                            for absent in (counterpart, future, "source-item-", "rewrite-model-metadata"):
                                self.assertNotIn(absent, binding.presentation_json.decode("utf-8"))
                            contexts.append(binding.prepared.json_bytes)
                            output = (dict(kind="no_result", reason="incomplete", unresolved=[ref]) if mode == "unavailable" else
                                dict(kind="structured_result", profile=SCAM_PROFILE.identity(),
                                    payload=dict(verdict="scam" if mode == "valid" else "outside-verdict",
                                        rationale="Scripted protocol control only."), supporting=[ref], counter=[], unresolved=[]))
                            return agent.envelope(request, output)
                        client = agent.ScriptedClient([finish])
                        model = ModelAccess(name="phish-toy-model", version="1.0", client=client,
                            instructions=SCAM_INSTRUCTIONS, profile=SCAM_PROFILE, tools=(), settings=agent.SETTINGS,
                            input_fit=lambda binding, request: True, select_visible_state=lambda state: b"{}")
                        host = ExecutionHost(intake=intake,
                            preparer=ContextPreparer(message_limits=fixture.INPUT, limits=fixture.CONTEXT),
                            limits=fixture.LIMITS, capabilities=(model.capability(),), profile=SCAM_PROFILE.assessment)
                        async def finalize(*arguments):
                            finalized.append(True)
                        result = await host.run(requests[room], strategy=AgentController(model=model).spec,
                            allowed_capabilities=frozenset((model.name,)), initial_state_json=b"{}", finalizer=finalize)
                        self.assertEqual(len(client.requests), 1)
                        self.assertEqual(result.status, dict(valid="completed", invalid="failed", unavailable="unavailable")[mode])
                        self.assertEqual(bool(finalized), mode == "valid")
                        self.assertEqual(result.to_dict()["assessment"] is not None, mode == "valid")
                self.assertTrue(all(context == contexts[0] for context in contexts))
