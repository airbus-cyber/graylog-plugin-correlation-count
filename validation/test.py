# to create and populate the test venv:
# * python3 -m venv venv
# * source venv/bin/activate
# * pip install -r requirements.txt
# to execute these tests:
# * activate venv
#   source ./venv/bin/activate
# * execute tests
#   python -m unittest

from unittest import TestCase
from graylog_server import GraylogServer


class Test(TestCase):

    def setUp(self) -> None:
        self._graylog = GraylogServer('../runtime')
        self._graylog.start()

    def tearDown(self) -> None:
        self._graylog.stop()

    def test_start_should_load_plugin(self):
        logs = self._graylog.extract_logs()
        self.assertIn('INFO : org.graylog2.bootstrap.CmdLineTool - Loaded plugin: Correlation Count Alert Condition', logs)

