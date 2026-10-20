#!/usr/bin/env python3
"""Standard-library unit runner with JUnit output for CI."""
from pathlib import Path
import sys
import time
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
suite = ET.Element('testsuite', name='unit')


class Result(unittest.TextTestResult):
    def startTest(self, test):
        self.started = time.monotonic()
        self.case = ET.SubElement(suite, 'testcase', classname=type(test).__module__+'.'+type(test).__name__, name=test._testMethodName)
        super().startTest(test)

    def stopTest(self, test):
        self.case.set('time', str(time.monotonic()-self.started))
        super().stopTest(test)

    def addFailure(self, test, err):
        ET.SubElement(self.case, 'failure').text = self._exc_info_to_string(err, test)
        super().addFailure(test, err)

    def addError(self, test, err):
        ET.SubElement(self.case, 'error').text = self._exc_info_to_string(err, test)
        super().addError(test, err)

    def addSkip(self, test, reason):
        ET.SubElement(self.case, 'skipped', message=reason)
        super().addSkip(test, reason)

    def addSubTest(self, test, subtest, err):
        if err:
            ET.SubElement(self.case, 'failure', message=str(subtest)).text = self._exc_info_to_string(err, test)
        super().addSubTest(test, subtest, err)


if __name__ == '__main__':
    result = unittest.TextTestRunner(resultclass=Result, verbosity=2).run(unittest.defaultTestLoader.discover(str(ROOT/'tests')))
    target = ROOT/'.build/reports/unit.xml'
    target.parent.mkdir(parents=True, exist_ok=True)
    suite.set('tests', str(result.testsRun))
    suite.set('failures', str(len(result.failures)))
    suite.set('errors', str(len(result.errors)))
    ET.ElementTree(suite).write(target, encoding='utf-8', xml_declaration=True)
    raise SystemExit(not result.wasSuccessful())
