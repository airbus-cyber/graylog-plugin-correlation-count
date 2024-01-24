import time
from graylog_server import GraylogServer
from graylog_rest_api import GraylogRestApi
from graylog_inputs import GraylogInputs
from server_timeout_error import ServerTimeoutError


class Graylog:

    def __init__(self):
        self._server = GraylogServer('../runtime')
        self._api = GraylogRestApi()

    def _wait(self, condition, attempts, sleep_duration=1):
        count = 0
        while not condition():
            time.sleep(sleep_duration)
            count += 1
            if count > attempts:
                print(self._server.extract_all_logs())
                raise ServerTimeoutError()

    def _wait_until_graylog_has_started(self):
        """
        We wait until the default deflector is up, as it seems to be the last operation done on startup
        This might have to change in the future, if graylog changes its ways...
        :return:
        """
        print('Waiting for graylog to start...')
        self._wait(self._api.default_deflector_is_up, 180)
        self._wait(self._api.events_search_is_available, 180)

    def start(self):
        self._server.start()
        self._wait_until_graylog_has_started()

    def stop(self):
        self._server.stop()

    def start_logs_capture(self):
        self._server.start_logs_capture()

    def extract_logs(self):
        return self._server.extract_logs()

    def create_gelf_input(self):
        gelf_input = self._api.create_gelf_input()
        self._wait(gelf_input.is_running, 10, sleep_duration=.1)
        return GraylogInputs()

    def create_correlation_count(self, *args, **kwargs):
        self._api.create_correlation_count(*args, **kwargs)

    def get_events_count(self):
        return self._api.get_events_count()

    def get_events(self):
        return self._api.get_events()

    def _has_event(self):
        events_count = self.get_events_count()
        return events_count == 1

    def wait_until_event(self):
       self._wait(self._has_event, 60)

