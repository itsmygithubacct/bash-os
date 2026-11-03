#!/usr/bin/env python3
"""Data-only checks that catalog drift cannot silently shrink reference scope."""
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
spec = importlib.util.spec_from_file_location('reference_inventory', HERE / 'inventory.py')
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


class ScopeChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.here = self.root / 'tests/parity-debian'
        self.here.mkdir(parents=True)
        (self.root / 'config').mkdir()
        for path in (ROOT / 'config').glob('*'):
            if path.name in {'loadables.py', 'bash-loadables.list', 'bash-loadables-optional.list', 'versions.sh', 'uv.json'}:
                shutil.copyfile(path, self.root / 'config' / path.name)
        for name in ('inventory.py', 'references.json', 'packages.list', 'util-linux.json'):
            shutil.copyfile(HERE / name, self.here / name)
        self.patcher = patch.multiple(inventory, ROOT=self.root, HERE=self.here)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def change_mapping(self, change):
        path = self.here / 'references.json'
        mapping = json.loads(path.read_text())
        change(mapping['groups'])
        path.write_text(json.dumps(mapping))

    def test_new_loadable_needs_a_reference(self):
        path = self.root / 'config/bash-loadables.list'
        path.write_text(path.read_text() + '\nparity_new_command|new command\n')
        with self.assertRaisesRegex(ValueError, 'unmapped=.*parity_new_command'):
            inventory.scope()

    def test_deleted_mapping_is_rejected(self):
        self.change_mapping(lambda groups: groups[0]['loadables'].remove('basename'))
        with self.assertRaisesRegex(ValueError, 'unmapped=.*basename'):
            inventory.scope()

    def test_duplicate_mapping_is_rejected(self):
        self.change_mapping(lambda groups: groups.append(copy.deepcopy(groups[0])))
        with self.assertRaisesRegex(ValueError, 'duplicate loadable mapping'):
            inventory.scope()

    def test_stale_mapping_is_rejected(self):
        self.change_mapping(lambda groups: groups[0]['loadables'].append('parity_removed_command'))
        with self.assertRaisesRegex(ValueError, 'stale=.*parity_removed_command'):
            inventory.scope()

    def test_group_cannot_require_an_undeclared_package(self):
        self.change_mapping(lambda groups: groups[0]['packages'].append('parity-missing-package'))
        with self.assertRaisesRegex(ValueError, 'undeclared Debian packages'):
            inventory.scope()

    def test_executable_fields_cannot_hide_shell_arguments(self):
        self.change_mapping(lambda groups: groups[0].update(programs=['curl --version']))
        with self.assertRaisesRegex(ValueError, 'not shell commands'):
            inventory.scope()

    def test_contract_only_entries_remain_visible(self):
        report = inventory.scope()
        rows = {row['name']: row for row in report['loadables']}
        self.assertEqual(rows['auth']['kind'], 'contract-only')
        self.assertTrue(rows['auth']['notes'])
        self.assertTrue(rows['uv']['optional'])
        self.assertEqual(len(rows), report['full_catalog_count'] + report['optional_catalog_count'])


if __name__ == '__main__':
    unittest.main()
