# to create and populate the test venv:
# * python3 -m venv venv
# * source venv/bin/activate
# * pip install -r requirements.txt
# to execute these tests:
# * activate venv
#   source ./venv/bin/activate
# * execute tests
#   python -m unittest --verbose
# To execute only one test, suffix with the fully qualified test name. Example:
#   python -m unittest test.Test.test_sending_message_should_trigger_correlation_rule

from unittest import TestCase
import time
from graylog import Graylog

_PERIOD = 5


class Test(TestCase):

    def setUp(self) -> None:
        self._graylog = Graylog()
        self._graylog.start()

    def tearDown(self) -> None:
        self._graylog.stop()

    def _assert_got_new_event_within(self, timeout):
        for i in range(timeout):
            events_count = self._graylog.get_events_count()
            if events_count == 1:
                return
            time.sleep(1)
        self.fail('Event not generated within ' + str(timeout) + ' seconds')

    def test_start_should_load_plugin(self):
        logs = self._graylog.extract_logs()
        self.assertIn('INFO : org.graylog2.bootstrap.CmdLineTool - Loaded plugin: Correlation Count Alert Condition', logs)

    def test_sending_message_should_trigger_correlation_rule(self):
        self._graylog.create_correlation_count(period=_PERIOD)
        with self._graylog.create_gelf_input() as inputs:
            inputs.send({})
            time.sleep(_PERIOD)
            inputs.send({'short_message': 'pop'})

            self._assert_got_new_event_within(60)
