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
#   python -m unittest test.Test.test_send_message_should_trigger_correlation_rule

from unittest import TestCase
import time
from graylog import Graylog
from server_timeout_error import ServerTimeoutError

_PERIOD = 5


class Test(TestCase):

    def setUp(self) -> None:
        self._graylog = Graylog()
        self._graylog.start()

    def tearDown(self) -> None:
        self._graylog.stop()

    def test_start_should_load_plugin(self):
        logs = self._graylog.extract_logs()
        self.assertIn('INFO : org.graylog2.bootstrap.CmdLineTool - Loaded plugin: Correlation Count Alert Condition', logs)

    def test_send_message_should_trigger_correlation_rule(self):
        self._graylog.create_correlation_count(0, period=_PERIOD)
        with self._graylog.create_gelf_input() as inputs:
            inputs.send({})
            time.sleep(_PERIOD)

            try:
                self._graylog.wait_until_event()
            except ServerTimeoutError:
                print(self._graylog.get_events())
                events_count = self._graylog.get_events_count()
                self.fail(f'Events count: {events_count} (expected 1)')

    def test_send_message_should_trigger_correlation_rule_with_group_by(self):
        self._graylog.create_correlation_count(1, group_by=['x'], period=_PERIOD)
        with self._graylog.create_gelf_input() as inputs:
            inputs.send({'_x': 1})
            inputs.send({'_x': 1})
            time.sleep(_PERIOD)
            inputs.send({'short_message': 'pop'})

            self._graylog.wait_until_event()

    def test_send_message_with_different_values_for_group_by_field_should_not_trigger_correlation_rule_with_group_by(self):
        self._graylog.create_correlation_count(1, group_by=['x'], period=_PERIOD)
        with self._graylog.create_gelf_input() as inputs:
            inputs.send({'_x': 1})
            inputs.send({'_x': 2})
            time.sleep(_PERIOD)
            inputs.send({'short_message': 'pop'})

            time.sleep(20)
            self.assertEqual(0, self._graylog.get_events_count())

    def test_send_message_should_trigger_correlation_rule_with_group_by_when_value_has_a_space__issue27(self):
        self._graylog.create_correlation_count(1, group_by=['x'], period=_PERIOD, messages_order='BEFORE')
        with self._graylog.create_gelf_input() as inputs:
            inputs.send({'_x': 'hello world'})
            inputs.send({'_x': 'hello world'})
            # need to sleep for 1 to be sure that the timestamp of the second message is strictly before the timestamp of the third message
            # the precision is only of a millisecond and there is otherwise a risk that the event does not trigger
            time.sleep(1)
            inputs.send({'_x': 'hello world'})
            inputs.send({'_x': 'hello world'})
            time.sleep(_PERIOD)
            inputs.send({'short_message': 'pop'})

            self._graylog.wait_until_event()

    def test_send_message_should_not_fail_on_correlation_rule_with_group_by_when_value_has_a_double_quote__issue27(self):
        self._graylog.create_correlation_count(1, group_by=['x'], period=_PERIOD, messages_order='BEFORE')
        with self._graylog.create_gelf_input() as inputs:
            self._graylog.start_logs_capture()
            inputs.send({'_x': 'hello"world'})
            inputs.send({'_x': 'hello"world'})
            time.sleep(_PERIOD)
            inputs.send({'short_message': 'pop'})

            time.sleep(2*_PERIOD)
            logs = self._graylog.extract_logs()
            self.assertNotIn('ERROR', logs)

    def test_send_message_should_not_fail_with_out_of_bounds_when_group_by_fields_are_missing__issue34(self):
        self._graylog.create_correlation_count(0, group_by=['field1', 'field2'], period=_PERIOD)
        with self._graylog.create_gelf_input() as inputs:
            self._graylog.start_logs_capture()
            inputs.send({})
            inputs.send({})

            time.sleep(2*_PERIOD)
            logs = self._graylog.extract_logs()
            self.assertNotIn('Caught an unhandled exception while executing event processor', logs)
            self.assertNotIn('| java.lang.IndexOutOfBoundsException:', logs)
