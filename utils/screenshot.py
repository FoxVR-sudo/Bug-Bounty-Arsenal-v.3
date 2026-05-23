from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
import time


def take_screenshot(url, output_path, payload=None, form_selector=None, input_selector=None, submit_selector=None):
    options = Options()
    options.headless = True
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=options)
    try:
        driver.get(url)
        # Ако има payload и селектори, инжектирай payload-а във формата
        if payload and input_selector and submit_selector:
            input_elem = driver.find_element("css selector", input_selector)
            input_elem.clear()
            input_elem.send_keys(payload)
            submit_btn = driver.find_element("css selector", submit_selector)
            submit_btn.click()
            time.sleep(2)  # Изчакай да се зареди резултатът
        driver.save_screenshot(output_path)
    finally:
        driver.quit()
