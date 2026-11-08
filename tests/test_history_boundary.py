"""Independent neutral toy fixtures; no benchmark inputs, labels or loaders.

These examples were written for this component. They have no fraud labels and
are not copied, paraphrased or sampled from any evaluation corpus.
"""

from copy import deepcopy
import unittest
from unittest.mock import patch

from engine.history import build_observed_history


def toy_history():
    return [
        {"role": "contact", "text": "Toy greeting", "details": {"tags": ["opening"]}},
        {"role": "user", "text": "Toy reply", "details": {"tags": []}},
        {"role": "contact", "text": "UNOBSERVED_CANARY", "details": {"tags": ["later"]}},
    ]


class ObservedHistoryTests(unittest.TestCase):
    def test_every_boundary_preserves_exact_prefix(self):
        source = toy_history()
        for count in range(len(source) + 1):
            with self.subTest(observed_count=count):
                self.assertEqual(build_observed_history(source, count), tuple(source[:count]))

    def test_unobserved_suffix_is_not_delivered_to_consumer(self):
        consumed = []

        def recording_consumer(messages):
            consumed.extend(messages)

        recording_consumer(build_observed_history(toy_history(), 2))
        self.assertEqual([m["text"] for m in consumed], ["Toy greeting", "Toy reply"])

    def test_build_does_not_modify_source(self):
        source = toy_history()
        before = deepcopy(source)
        build_observed_history(source, 2)
        self.assertEqual(source, before)

    def test_unobserved_payload_is_not_copied(self):
        class FuturePayload:
            def __deepcopy__(self, memo):
                raise AssertionError("Unobserved payload must not be copied")

        source = [{"text": "Observed toy message"}, FuturePayload()]
        self.assertEqual(build_observed_history(source, 1), ({"text": "Observed toy message"},))

    def test_later_source_changes_do_not_change_returned_history(self):
        source = toy_history()
        prefix = build_observed_history(source, 2)
        expected = deepcopy(prefix)
        source[0]["text"] = "Changed source"
        source[0]["details"]["tags"].append("changed")
        source.append({"role": "user", "text": "Another future message"})
        self.assertEqual(prefix, expected)

    def test_consumer_mutation_does_not_change_source(self):
        source = toy_history()
        before = deepcopy(source)
        prefix = build_observed_history(source, 2)
        prefix[0]["text"] = "Changed only by consumer"
        prefix[0]["details"]["tags"].append("consumer-change")
        self.assertEqual(source, before)

    def test_invalid_count_types_are_rejected(self):
        for count in [True, False, 1.0, "1", None]:
            with self.subTest(count=count):
                with self.assertRaises(TypeError):
                    build_observed_history(toy_history(), count)

    def test_out_of_range_counts_are_rejected(self):
        for count in [-1, 4]:
            with self.subTest(count=count):
                with self.assertRaises(ValueError):
                    build_observed_history(toy_history(), count)

    def test_empty_history_and_prefix_are_supported(self):
        self.assertEqual(build_observed_history([], 0), ())
        self.assertEqual(build_observed_history(toy_history(), 0), ())

    def test_separate_conversations_do_not_share_payloads(self):
        first = build_observed_history([{"text": "Conversation one"}], 1)
        second = build_observed_history([{"text": "Conversation two"}], 1)
        first[0]["text"] = "Changed first conversation"
        self.assertEqual(second, ({"text": "Conversation two"},))

    def test_component_uses_no_file_or_network_access(self):
        with patch("builtins.open", side_effect=AssertionError("File access prohibited")), \
                patch("pathlib.Path.open", side_effect=AssertionError("File access prohibited")), \
                patch("socket.socket", side_effect=AssertionError("Network access prohibited")):
            result = build_observed_history(toy_history(), 2)
        self.assertEqual(len(result), 2)


if __name__ == "__main__":
    unittest.main()
