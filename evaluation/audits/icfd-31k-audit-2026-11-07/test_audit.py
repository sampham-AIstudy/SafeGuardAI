"""Public invented fixtures exercise timing, information boundaries and scoring."""

import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit_core import annotation_map, chunker, observed_input, score_binary, source_issues, verdict


class AuditContractTests(unittest.TestCase):
    def setUp(self):
        self.engine = chunker(Path(__file__).parent / 'upstream')

    def test_known_confusion_matrix(self):
        metrics = score_binary([1, 1, 1, 0, 0, 0], [1, 1, 0, 1, 0, 0])['metrics']
        self.assertEqual({k: metrics[k] for k in ('tp','tn','fp','fn')}, {'tp':2,'tn':2,'fp':1,'fn':1})
        for key in ('accuracy','precision','recall','f1'):
            self.assertAlmostEqual(metrics[key], 2/3)

    def test_no_warning_is_not_failure(self):
        self.assertTrue(score_binary([1, 0], [0, 0])['complete'])
        self.assertFalse(score_binary([1, 0], [None, 0])['complete'])

    def test_missing_and_invalid_predictions(self):
        with self.assertRaises(ValueError):
            score_binary([1], [])
        self.assertFalse(score_binary([1], ['YES'])['complete'])
        self.assertFalse(score_binary([1], [True])['complete'])

    def test_undefined_denominators(self):
        self.assertIsNone(score_binary([], [])['metrics']['accuracy'])
        self.assertIsNone(score_binary([0], [0])['metrics']['precision'])
        self.assertIsNone(score_binary([0], [0])['metrics']['recall'])

    def test_unknown_gold_is_rejected(self):
        with self.assertRaises(ValueError):
            verdict('MAYBE')

    def test_annotation_fault_does_not_discard_source(self):
        source = {'transcript':[{'speaker':'Caller','text':'Hello.','timestamp_end':3}],
                  'chunk_level_analysis':[{'timestamp':3,'verdict_at_chunk':'UNKNOWN'}]}
        issues, end = source_issues(source)
        self.assertEqual(issues['nonbinary_source_annotations'],1)
        self.assertEqual(end,3)
        self.assertEqual(len(source['transcript']),1)

    def test_missing_timestamp_is_reported_without_aborting(self):
        issues, end = source_issues({'transcript':[{'speaker':'Caller','text':'Hello.'}]})
        self.assertEqual(issues['invalid_transcript_timestamps'],1)
        self.assertEqual(end,0)

    def test_malformed_annotations_are_not_silently_repaired(self):
        source={'chunk_level_analysis':[{'timestamp':'3','verdict_at_chunk':'YES'},
                                       {'timestamp':3,'verdict_atChunk':'YES'},
                                       {'timestamp':6,'verdict_at_chunk':'NO'}]}
        self.assertEqual(annotation_map(source),{6:'NO'})
        issues,_=source_issues(source)
        self.assertEqual(issues['invalid_annotation_timestamps'],1)
        self.assertEqual(issues['nonbinary_source_annotations'],1)

    def test_input_drops_gold_and_metadata(self):
        source = {'chunk_timestamp': 3, 'final_verdict':'YES', 'scenario_info_json':'SECRET',
                  'cumulative_transcript_json':json.dumps([{'speaker':'Caller','text':'Hello.',
                                                          'timestamp_end':3,'gold':'SECRET'}])}
        self.assertEqual(observed_input(source), {'messages':[{'speaker':'Caller','text':'Hello.','timestamp_end':3}]})

    def test_future_and_unordered_text_are_rejected(self):
        for ends in ([4], [3, 2]):
            source = {'chunk_timestamp':3, 'cumulative_transcript_json':json.dumps([
                {'speaker':'Caller','text':'invented','timestamp_end':end} for end in ends])}
            with self.assertRaises(ValueError):
                observed_input(source)

    def test_native_keyword_boundary_is_not_evidence_annotation(self):
        source = {'transcript':[{'speaker':'Receiver','text':'Please confirm the appointment.', 'timestamp_end':3},
                                {'speaker':'Caller','text':'The later request is omitted here.', 'timestamp_end':9}],
                  'scenario':{'case_type':'Clear Fraud'},'final_verdict':'YES'}
        chunks = self.engine.expand_conversation_into_chunks(source)
        self.assertEqual(chunks[0]['final_verdict'], 'YES')
        source['final_verdict'] = 'NO'
        self.assertEqual(self.engine.expand_conversation_into_chunks(source)[0]['final_verdict'], 'NO')

    def test_native_fallback_is_sixty_percent_duration(self):
        source = {'transcript':[{'speaker':'Caller','text':'Hello.', 'timestamp_end':3},
                                {'speaker':'Receiver','text':'Good afternoon.', 'timestamp_end':10}],
                  'scenario':{'case_type':'Clear Fraud'}, 'final_verdict':'YES'}
        self.assertEqual(self.engine._find_fraud_start_time(source['transcript'],source['scenario'],source), 6)
        self.assertEqual([r['final_verdict'] for r in self.engine.expand_conversation_into_chunks(source)], ['NO','YES','YES'])

    def test_native_never_includes_unfinished_utterance(self):
        source = {'transcript':[{'speaker':'Caller','text':'Hello.', 'timestamp_end':4},
                                {'speaker':'Receiver','text':'Good afternoon.', 'timestamp_end':10}],
                  'scenario':{'case_type':'Clear Normal'}, 'final_verdict':'NO'}
        chunks = self.engine.expand_conversation_into_chunks(source)
        self.assertEqual([c['chunk_timestamp'] for c in chunks], [6,9])
        self.assertEqual([len(c['cumulative_transcript']) for c in chunks], [1,1])


if __name__ == '__main__':
    unittest.main()
