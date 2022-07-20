import time
from graylog_server import GraylogServer
from graylog_rest_api import GraylogRestApi
from graylog_inputs import GraylogInputs


class Graylog:

    def __init__(self):
        self._server = GraylogServer('../runtime')
        self._api = GraylogRestApi()

    def _wait_until_graylog_has_started(self):
        """
        We wait until the default deflector is up, as it seems to be the last operation done on startup
        This might have to change in the future, if graylog changes its ways...
        :return:
        """
        print('Waiting for graylog to start...')

        while not self._api.default_deflector_is_up():
            time.sleep(1)

        while not self._api.events_search_is_available():
            time.sleep(1)

    def start(self):
        self._server.start()
        self._wait_until_graylog_has_started()

    def stop(self):
        self._server.stop()

    def extract_logs(self):
        return self._server.extract_logs()

    def create_gelf_input(self):
        identifier = self._api.create_gelf_input()
        while not self._api.gelf_input_is_running(identifier):
            time.sleep(.1)
        return GraylogInputs()

    def create_correlation_count(self, *args, **kwargs):
        self._api.create_correlation_count(*args, **kwargs)

    def get_events_count(self):
        return self._api.get_events_count()