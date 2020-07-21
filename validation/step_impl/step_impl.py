from getgauge.python import before_suite, after_suite, step
from selenium.webdriver import Firefox
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from step_impl.graylog_server import GraylogServer

def focus_is_on_username_input(driver):
    return driver.switch_to.active_element.get_attribute('id') == 'username'

@before_suite
def init():
    # Note: I am not sure this is better, or using the data_store.suite is better...
    global server
    server = GraylogServer()
    global driver
    driver = Firefox()
    
@after_suite
def close():
    driver.close()

@step("Start Graylog server")
def start_graylog_server():
    server.start()
    server.wait_until_log('Graylog server did not start correctly')

@step("Login as <login>/<password>")
def login(login, password):
    driver.get('http://127.0.0.1:9000/')
    WebDriverWait(driver, 10).until(focus_is_on_username_input)
    driver.switch_to.active_element.send_keys(login + Keys.TAB)
    driver.switch_to.active_element.send_keys(password + Keys.TAB)
    driver.switch_to.active_element.send_keys(Keys.ENTER)

@step("Stop Graylog server")
def stop_graylog_server():
    server.stop()

