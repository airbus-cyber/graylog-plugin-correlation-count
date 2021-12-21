import subprocess
import time
from requests.exceptions import ConnectionError
from graylog_rest_api import GraylogRestApi
from graylog_inputs import GraylogInputs


class GraylogServer:

    def __init__(self, docker_compose_path):
        self._docker_compose_path = docker_compose_path
        self._rest_api = GraylogRestApi()

    def start(self):
        subprocess.run(['docker-compose', 'up', '--detach'], cwd=self._docker_compose_path)
        self.wait_until_graylog_has_started()

    def extract_logs(self, line_count='all'):
        tail_option = '--tail={}'.format(line_count)
        return subprocess.check_output(['docker-compose', 'logs', tail_option, '--no-color', 'graylog'], cwd=self._docker_compose_path, universal_newlines=True)

    def stop(self):
        subprocess.run(['docker-compose', 'down'], cwd=self._docker_compose_path)

    def has_pipeline_rule_function(self, name):
        return self.get_pipeline_rule_function(name) is not None

    def get_pipeline_rule_function(self, name):
        pipeline_rule_functions = self._rest_api.get('system/pipelines/rule/functions')
        for pipeline_rule_function in pipeline_rule_functions.json():
            if pipeline_rule_function['name'] == name:
                return pipeline_rule_function
        return None

    def _input_is_running(self, identifier):
        response = self._rest_api.get('system/inputstates/')
        body = response.json()
        for state in body['states']:
            if state['id'] != identifier:
                continue
            return state['state'] == 'RUNNING'
        return False

    def create_gelf_input(self):
        payload = {
            'configuration': {
                'bind_address': '0.0.0.0',
                'decompress_size_limit': 8388608,
                'max_message_size': 2097152,
                'number_worker_threads': 8,
                'override_source': None,
                'port': 12201,
                'recv_buffer_size': 1048576,
                'tcp_keepalive': False,
                'tls_cert_file': '',
                'tls_client_auth': 'disabled',
                'tls_client_auth_cert_file': '',
                'tls_enable': False,
                'tls_key_file': 'admin',
                'tls_key_password': 'admin',
                'use_null_delimiter': True
            },
            'global': True,
            'title': 'Inputs',
            'type': 'org.graylog2.inputs.gelf.tcp.GELFTCPInput'
        }
        response = self._rest_api.post('system/inputs', payload)
        identifier = response.json()['id']
        while not self._input_is_running(identifier):
            time.sleep(.1)
        return GraylogInputs()

    def wait_until_graylog_has_started(self):
        """
        We wait until the default deflector is up, as it seems to be the last operation done on startup
        This might have to change in the future, if graylog changes its ways...
        :return:
        """
        print('Waiting for graylog to start...')

        # TODO move as a method in _graylog_rest_api
        #only for 60s maximum
        while True:
            try:
                response = self._rest_api.get('system/deflector')
                body = response.json()
                if body['is_up']:
                    break
            except ConnectionError:
                pass
            time.sleep(1)

