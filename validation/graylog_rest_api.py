import requests
from urllib import parse
from requests.exceptions import ConnectionError
from gelf_input import GelfInput

_AUTH = ('admin', 'admin')
_HEADERS = {"X-Requested-By": "test-program"}
_STREAM_ALL_MESSAGES = '000000000000000000000001'


class GraylogRestApi:

    def _print(self, message):
        print(message, flush=True)

    def _build_url(self, path):
        return parse.urljoin('http://127.0.0.1:9000/api/', path)

    def _get(self, path):
        url = self._build_url(path)
        response = requests.get(url, auth=_AUTH, headers=_HEADERS)
        self._print('GET {} => {}'.format(url, response.status_code))
        return response

    def _post(self, path, payload=None):
        url = self._build_url(path)
        response = requests.post(url, json=payload, auth=_AUTH, headers=_HEADERS)
        self._print('POST {} {} => {}'.format(url, payload, response.status_code))
        return response

    def default_deflector_is_up(self):
        try:
            response = self._get('system/deflector')
            body = response.json()
            if body['is_up']:
                return True
            return False
        except ConnectionError:
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
        response = self._post('system/inputs', payload)
        identifier = response.json()['id']
        return GelfInput(self, identifier)

    def gelf_input_is_running(self, identifier):
        response = self._get('system/inputstates/')
        body = response.json()
        for state in body['states']:
            if state['id'] != identifier:
                continue
            return state['state'] == 'RUNNING'
        return False

    def create_correlation_count(self, threshold, group_by=None, period=5, messages_order='ANY'):
        if group_by is None:
            group_by = []
        event_definition = {
            'alert': False,
            'config': {
                'type': 'correlation-count',
                'comment': '',
                'execute_every_ms': period*1000,
                'search_within_ms': period*1000,
                'grouping_fields': group_by,

                'stream': _STREAM_ALL_MESSAGES,
                'threshold': threshold,
                'threshold_type': 'MORE',
                'additional_stream': _STREAM_ALL_MESSAGES,
                'additional_threshold': threshold,
                'additional_threshold_type': 'MORE',

                'search_query': '*',
                'messages_order': messages_order
            },
            'description': '',
            'field_spec': {},
            'key_spec': [],
            'notification_settings': {
                'backlog_size': None,
                'grace_period_ms': 0
            },
            'notifications': [],
            'priority': 2,
            'title': 'AAA'
        }
        self._post('events/definitions', event_definition)

    # TODO simplify this: have only get_events at this level
    def _search_events(self):
        return self._post('events/search', {})

    def events_search_is_available(self):
        response = self._search_events()
        return response.status_code == 200

    def get_events(self):
        response = self._search_events()
        return response.json()
