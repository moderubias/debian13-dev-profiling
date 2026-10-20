import copy
import unittest

from d13dp import migration


class MigrationTests(unittest.TestCase):
    def test_supported_template_round_trip(self):
        for tcp in ([22], [22, 80, 443]):
            record = migration.recognize(migration.objects(tcp), '#!/usr/sbin/nft -f\n' + migration.source(tcp))
            self.assertEqual(record['tcp'], tcp)
            self.assertEqual(migration.restore(record, migration.objects(tcp)), '')
            restored = migration.restore(record, migration.objects(tcp, retained=True))
            self.assertIn('add chain inet filter input', restored)
            self.assertNotIn('forward', restored)
            self.assertNotIn('f2b', restored)

    def test_unknown_semantics_or_source_fail_closed(self):
        for edit in ('extra_rule', 'priority', 'counter', 'output'):
            rules = copy.deepcopy(migration.objects([22]))
            if edit == 'extra_rule':
                rules.append({'rule': {'family': 'inet', 'table': 'filter', 'chain': 'input', 'expr': [{'accept': None}]}})
            elif edit == 'priority':
                next(item['chain'] for item in rules if item.get('chain', {}).get('name') == 'input')['prio'] = -1
            elif edit == 'counter':
                next(item['rule'] for item in rules if 'rule' in item)['expr'].insert(0, {'counter': {'packets': 0, 'bytes': 0}})
            else:
                next(item['chain'] for item in rules if item.get('chain', {}).get('name') == 'output')['policy'] = 'drop'
            with self.subTest(edit=edit), self.assertRaises(ValueError):
                migration.recognize(rules, migration.source([22]))
        for suffix in ('include "other.nft"', 'flush ruleset', 'table inet extra {}'):
            with self.assertRaises(ValueError):
                migration.recognize(migration.objects([22]), migration.source([22]) + suffix)

    def test_source_live_mismatch_and_rollback_drift_refused(self):
        with self.assertRaises(ValueError):
            migration.recognize(migration.objects([22]), migration.source([22, 80]))
        record = migration.recognize(migration.objects([22]), migration.source([22]))
        with self.assertRaises(ValueError):
            migration.restore(record, migration.objects([22, 80]))

    def test_dynamic_foreign_tables_not_owned(self):
        foreign = [{'table': {'family': 'inet', 'name': 'f2b-table'}},
                   {'set': {'family': 'inet', 'table': 'f2b-table', 'name': 'bans', 'elem': ['203.0.113.99']}}]
        self.assertEqual(migration.recognize(migration.objects([22]) + foreign, migration.source([22]))['tcp'], [22])

    def test_offline_plan_reports_real_port_delta_without_host_probes(self):
        import contextlib
        import io
        import json
        from pathlib import Path
        import tempfile
        from unittest.mock import patch
        from d13dp.cli import main
        with tempfile.TemporaryDirectory() as directory:
            rules, source = Path(directory)/'rules.json', Path(directory)/'nftables.conf'
            rules.write_text(json.dumps({'nftables': migration.objects([22])}))
            source.write_text(migration.source([22]))
            output = io.StringIO()
            with patch('d13dp.network.run', side_effect=AssertionError('Offline analysis must not probe the host')), contextlib.redirect_stdout(output):
                code = main(['network','migration-plan','--ruleset',str(rules),'--source',str(source),'--profile','web'])
            self.assertEqual(code, 0)
            report = json.loads(output.getvalue())
            self.assertTrue(report['offline'])
            self.assertEqual(report['ports']['tcp'], {'add':[80,443], 'remove':[]})
            self.assertIn('flush chain inet filter input', report['candidate_batch'])
            self.assertNotIn('flush ruleset', report['candidate_batch'])
            self.assertNotIn('f2b-table', report['rollback_batch'])
            self.assertTrue(report['requires_live_preflight'])

    def test_legacy_permission_metadata_is_strict(self):
        record = migration.recognize(migration.objects([22]), migration.source([22]), mode=0o640, gid=42)
        self.assertEqual((record['mode'], record['gid']), (0o640,42))
        for mode, gid in ((0o666,0), (0o4755,0), (True,0), (0o644,-1), (0o644,True)):
            with self.subTest(mode=mode,gid=gid), self.assertRaises(ValueError):
                migration.recognize(migration.objects([22]), migration.source([22]), mode=mode, gid=gid)
