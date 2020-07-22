from getgauge.python import before_suite, after_suite, step
from getgauge.python import custom_screenshot_writer
from selenium.webdriver import Firefox
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support.expected_conditions import presence_of_element_located
from step_impl.graylog_server import GraylogServer

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

@step("Stop Graylog server")
def stop_graylog_server():
    server.stop()

@step("Login as <login>/<password>")
def login(login, password):
    driver.get(server.URL)
    fill_input('username', login)
    fill_input('password', password)
    # note: could alternatively do send_keys(Keys.ENTER)
    driver.find_element_by_css_selector('button[type=submit]').click()

@step("Go to page <page_name>")
def go_to_page(page_name):
    driver.get(server.URL + page_name)

@step("Click button <>")
def click_button(text):
    driver.find_element_by_xpath('//button[text()="' + text + '"]').click()

@step("Fill <identifier> input with <value>")
def fill_input(identifier, value):
    WebDriverWait(driver, 10).until(presence_of_element_located([By.ID, identifier]))
    driver.find_element_by_id(identifier).send_keys(value)

@custom_screenshot_writer
def take_screenshot():
    image = driver.get_screenshot_as_png()
    file_name = os.path.join(os.getenv("gauge_screenshots_dir"), "screenshot-{0}.png".format(uuid1().int))
    file = open(file_name, "wb")
    file.write(image)
    return os.path.basename(file_name)
