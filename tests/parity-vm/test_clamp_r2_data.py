#!/usr/bin/python3
"""Independent data regressions only: imports no fixture, guest or syscall code."""
import copy
import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).parent / 'helpers/clamp_r2_model.py'
spec = importlib.util.spec_from_file_location('clamp_data_model', path)
model = importlib.util.module_from_spec(spec)
spec.loader.exec_module(model)


class Classifications(unittest.TestCase):
    def test_observer_and_product_are_separate(self):
        # Fixed outcomes from the audit, independent of wrapper implementation.
        rows = [
            ('clean completed observation', 0, True, {}, None, None, (), 'PASS', 'PASS'),
            ('helper timeout before any check', -9, False, {}, 'wall-clock limit', None, (), 'ERROR', None),
            ('resource kill after completed checks', -9, True, {'readback': True}, None, None, (), 'ERROR', None),
            ('strays without proved defect', 0, True, {'readback': True}, 'fixture left live child processes', None, (), 'ERROR', None),
            ('Python crash is not a candidate error', 1, False, {}, None, None, ('stderr',), 'ERROR', None),
            ('unattributed nonzero is never PASS', 1, True, {}, None, None, (), 'ERROR', None),
            ('completed candidate mismatch', 1, True, {'readback': False}, None, None, (), 'FAIL', 'FAIL'),
            ('wrong readback then cleanup error', 125, False, {'readback': False}, 'cleanup failed', None, (), 'FAIL', 'FAIL'),
            ('wrong readback then outer kill', -9, False, {'readback': False}, 'wall-clock limit', None, (), 'FAIL', 'FAIL'),
            ('complete private model byte mismatch', 0, True, {}, None, None, ('expected stdout',), 'FAIL', 'FAIL'),
            ('missing observation with matching outer output', 0, False, {}, None, None, (), 'ERROR', None),
            ('global cleanup fails without product defect', 125, False, {}, None, {'restored': False, 'writers_gone': True}, (), 'ERROR', None),
            ('global cleanup fails with product defect', 125, False, {'query_bytes': False}, None, {'restored': False, 'writers_gone': True}, (), 'ERROR', 'FAIL'),
            ('writer remains despite matching values', 0, True, {}, None, {'restored': True, 'writers_gone': False}, (), 'ERROR', None),
            ('clean outer restoration', 0, True, {'query': True}, None, {'restored': True, 'writers_gone': True}, (), 'PASS', 'PASS'),
        ]
        for name, status, complete, checks, error, cleanup, differences, expected, product in rows:
            with self.subTest(name=name):
                observation = {'schema': 'clamp-observations-r2', 'complete': complete,
                               'checks': checks, 'incomplete': []}
                raw = {'status': status, 'error': error}
                if cleanup is not None:
                    raw['clamp_cleanup'] = cleanup
                answer = model.classify(raw, observation, differences)
                self.assertEqual(answer['status'], expected)
                self.assertEqual(answer['product_status'], product)
                self.assertEqual(answer['release_eligible'], expected == 'PASS')

    def test_program_interruptions_are_not_product_mismatches(self):
        # Independent outcome table: an interrupted invocation proves no FAIL;
        # an earlier completed mismatch remains a FAIL if a later invocation dies.
        for signal_number in (1, 2, 9, 15, 24, 25):
            for status, encoding in ((-signal_number, 'subprocess'),
                                     (128 + signal_number, 'shell')):
                with self.subTest(status=status, encoding=encoding):
                    self.assertFalse(model.program_result_usable(status, encoding))
                    incomplete = {'schema': 'clamp-observations-r2', 'complete': False,
                                  'checks': {}, 'incomplete': ['program interrupted']}
                    self.assertEqual(model.classify({'status': 125}, incomplete)['status'], 'ERROR')
                    incomplete['checks']['earlier-readback'] = False
                    self.assertEqual(model.classify({'status': 125}, incomplete)['product_status'], 'FAIL')
        for status in (0, 1, 7, 73, 126, 127, 255):
            self.assertTrue(model.program_result_usable(status))
            self.assertTrue(model.program_result_usable(status, 'shell'))
        # A wait-observed ordinary exit 137 is distinct from an actual SIGKILL;
        # shell status 137 lacks that distinction and stays unresolved.
        self.assertTrue(model.program_result_usable(137))
        self.assertTrue(model.program_result_usable(-11))
        self.assertTrue(model.program_result_usable(-31))
        for status in (None, True, '0', -65, 256):
            self.assertFalse(model.program_result_usable(status))
        self.assertFalse(model.program_result_usable(-9, 'shell'))
        self.assertFalse(model.program_result_usable(0, 'unknown'))

    def test_mismatch_persisted_before_cleanup(self):
        report = {'control_valid': True, 'candidate_checks': {}, 'runs': [
            {'kind': 'native', 'qualified': True, 'checks': {'pair': False}},
            {'kind': 'candidate', 'qualified': False, 'checks': {'status': False}},
            {'kind': 'candidate', 'qualified': True, 'checks': {'pair': False, 'status': True},
             'cleanup': {'forced': True}}]}
        self.assertEqual(model.qualified_checks(report), {'run.2.pair': False, 'run.2.status': True})
        report['control_valid'] = False
        self.assertEqual(model.qualified_checks(report), {})

    def test_notification_receipt_requires_delivery_and_completion(self):
        trace = [{'id': 10, 'syscall': 'sched_getattr'}, {'id': 11, 'syscall': 'sched_getattr'}]
        valid = {'schema': 'clamp-notification-r2', 'observer_status': 'completed',
                 'termination': 'exit',
                 'exec_confirmed': True, 'program_status': 1, 'reaped': True,
                 'cleanup_complete': True, 'acknowledged_ids': [10, 11]}
        self.assertTrue(model.notification_valid(valid, trace, 1))
        for field, value in [
            ('observer_status', 'incomplete'), ('exec_confirmed', False),
            ('program_status', 0), ('program_status', True), ('reaped', False),
            ('cleanup_complete', False), ('acknowledged_ids', [10]),
            ('acknowledged_ids', [11, 10]), ('acknowledged_ids', [10, 10]),
        ]:
            with self.subTest(field=field, value=value):
                receipt = dict(valid, **{field: value})
                self.assertFalse(model.notification_valid(receipt, trace, 1))
        self.assertFalse(model.notification_valid(valid, [trace[0], trace[0]], 1))
        self.assertFalse(model.notification_valid(None, trace, 1))
        # A logged final getattr followed by a failed SEND is not validation PASS.
        receipt = dict(valid, observer_status='incomplete', acknowledged_ids=[10])
        self.assertFalse(model.notification_valid(receipt, trace, 1))
        # Child wait/status and acknowledgments were complete before cleanup
        # failed: behavioral failure remains usable, full qualification does not.
        cleanup_failed = dict(valid, cleanup_complete=False)
        self.assertFalse(model.notification_valid(cleanup_failed, trace, 1))
        self.assertTrue(model.notification_valid(cleanup_failed, trace, 1, require_cleanup=False))

    def test_signal_of_real_filtered_program_remains_an_observation(self):
        receipt = {'schema': 'clamp-notification-r2', 'observer_status': 'completed',
                   'termination': 'signal', 'signal': 31,
                   'exec_confirmed': True, 'program_status': 159, 'reaped': True,
                   'cleanup_complete': True, 'acknowledged_ids': []}
        self.assertTrue(model.notification_valid(receipt, [], 159))
        # The query helper's independently qualified no-write obligation failed;
        # the OUTER observer exits 1, rather than being mistaken for a timeout.
        record = {'schema': 'clamp-observations-r2', 'complete': True,
                  'checks': {'query_status': False}, 'incomplete': []}
        self.assertEqual(model.classify({'status': 1}, record)['product_status'], 'FAIL')

    def test_missing_and_malformed_envelopes_do_not_qualify(self):
        for record in (None, {}, {'schema': 'old-version', 'complete': True, 'checks': {}}):
            self.assertEqual(model.classify({'status': 0}, record)['status'], 'ERROR')


if __name__ == '__main__':
    unittest.main()
