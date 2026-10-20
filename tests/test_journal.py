from dataclasses import asdict
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from d13dp.journal import JournalError, load_json, rollback_text, state_record, transaction_record
from d13dp.network import run
from d13dp.network_policy import NetworkPolicy, expected_state, load_network_policy, render_network


class JournalTests(unittest.TestCase):
    def transaction(self):
        policy=load_network_policy('web')
        previous=load_network_policy('minimal')
        return {'id':'a'*32,'before':{'policy':asdict(previous),'effective':expected_state(previous)},
                'before_config':render_network(previous),'restore':'legacy raw text',
                'before_live':expected_state(previous),'after':expected_state(policy),'config':render_network(policy),
                'policy':asdict(policy),'session':None,'boot':'test-boot','deadline':100.0,'timeout':120}

    def json_transaction(self):
        return json.loads(json.dumps(self.transaction()))

    def test_old_valid_journal_remains_readable(self):
        tx=self.json_transaction()
        self.assertEqual(transaction_record(tx,'a'*32),tx)

    def test_raw_restoration_text_is_never_used_as_commands(self):
        tx=self.json_transaction()
        tx['restore']='flush ruleset\ninclude "/root/*"\n'
        validated=transaction_record(tx,'a'*32)
        restore=rollback_text(validated['before_live'])
        self.assertEqual(restore,render_network(load_network_policy('minimal')))
        self.assertNotIn('flush',restore)
        self.assertNotIn('include',restore)

    def test_corrupt_transaction_fields_fail_closed(self):
        for field,value in [('id','b'*32),('before_config','flush ruleset'),('after',[]),('deadline',float('inf')),('timeout',True),('boot',None),('session',['invalid',1,'192.0.2.2',22])]:
            with self.subTest(field=field):
                tx=self.json_transaction(); tx[field]=value
                with self.assertRaises(ValueError): transaction_record(tx,'a'*32)

    def test_corrupt_previous_live_structure_refused(self):
        tx=self.json_transaction()
        tx['before_live'][-1]['rule']['expr']=[{'accept':None}]
        with self.assertRaises(JournalError): transaction_record(tx,'a'*32)

    def test_committed_policy_and_effective_mismatch_refused(self):
        tx=self.json_transaction()
        tx['before']['effective']=expected_state(load_network_policy('web'))
        with self.assertRaises(JournalError): transaction_record(tx,'a'*32)

    def test_state_schema_is_strict(self):
        for state in ({'version':True,'committed':None,'pending':None},
                      {'version':1,'committed':None,'pending':'../../etc/passwd'},
                      {'version':1,'committed':[],'pending':None},
                      {'version':1,'committed':None,'pending':None,'extra':True}):
            with self.subTest(state=state), self.assertRaises(ValueError): state_record(state)

    def test_non_finite_json_and_invalid_roots_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'journal.json'
            for content in ('{"deadline":NaN}', '{"deadline":Infinity}', '{"version":1,"version":2}', '[]', 'null'):
                with self.subTest(content=content):
                    path.write_text(content)
                    with self.assertRaises(JournalError): load_json(path)

    def test_invalid_constructed_policy_refused(self):
        for tcp in ((True,), (0,), (65536,), (22,22)):
            with self.subTest(tcp=tcp), self.assertRaises(ValueError): NetworkPolicy('custom',tcp)

    @patch('d13dp.network.shutil.which', return_value='/usr/sbin/nft')
    @patch('d13dp.network.subprocess.run', return_value=subprocess.CompletedProcess([],0,'{}',''))
    def test_privileged_child_environment_is_sanitized(self, command, which):
        with patch.dict('os.environ', {'PATH':'/tmp/untrusted','LD_PRELOAD':'/tmp/inject.so','PYTHONPATH':'/tmp/inject'}):
            run('nft','-j','list','ruleset')
        options=command.call_args.kwargs
        self.assertEqual(command.call_args.args[0][0],'/usr/sbin/nft')
        self.assertEqual(options['env']['PATH'],'/usr/sbin:/usr/bin:/sbin:/bin')
        self.assertNotIn('LD_PRELOAD',options['env'])
        self.assertNotIn('PYTHONPATH',options['env'])
        self.assertNotIn('shell',options)
