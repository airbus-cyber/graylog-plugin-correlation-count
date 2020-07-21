import subprocess
from threading import Thread
from queue import Queue

DOCKER_COMPOSE_PATH = 'execution_environment'


class GraylogServer:

    def _put_stream_lines_in_queue(self, stream, queue):
        while True:
            line = stream.readline()
            if (line == ''): 
                break
            queue.put(line)
    
    URL = 'http://127.0.0.1:9000'
    
    def start(self):
        subprocess.run(['docker-compose', 'up', '--detach'], cwd=DOCKER_COMPOSE_PATH)
        
    def wait_until_log(self, message):
        graylog_logs = subprocess.Popen(['docker-compose', 'logs', '--no-color', '--follow'], cwd=DOCKER_COMPOSE_PATH, stdout=subprocess.PIPE, text=True)
        logs = Queue()
        reading_logs = Thread(target=self._put_stream_lines_in_queue, args=[graylog_logs.stdout, logs])
        reading_logs.start()
        while True:
            try:
                log = logs.get(1)
            except Empty:
                raise AssertionError(expected_message)
                break
            print(log)
            if 'Graylog server up and running.' in log:
                break
        graylog_logs.terminate()
        reading_logs.join()
    
    def stop(self):
        subprocess.run(['docker-compose', 'stop'], cwd=DOCKER_COMPOSE_PATH)

