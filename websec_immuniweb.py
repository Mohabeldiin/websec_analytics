"""WebSite Security Assessment Tool for Immuniweb.

    This tool is used to assess the security of a website.
    It is based on the OWASP Top 10 and OWASP Mobile Top 10.
    For more info Refer to https://www.immuniweb.com/websec/"""


import logging

try:
    from modules.validators import url as url_validator
except (ImportError, ModuleNotFoundError) as e:
    logging.error("Module validators not found: %s", e.__doc__)
    raise (f"Module validators not found: {e.__doc__}") from e

try:
    from selenium import webdriver
    from selenium.common import exceptions as selenium_exceptions
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.support.ui import WebDriverWait
except (ImportError, ModuleNotFoundError) as e:
    logging.error("Module selenium not found: %s", e.__doc__)
    raise (f"Module selenium not found: {e.__doc__}") from e


class Locators:
    """Defines the locator for the web elements."""
    _IMMUNIWEB = "https://www.immuniweb.com/websec/"


class WebSec(Locators):
    """WebSite Security Assessment Tool"""

    def __init__(self,  url) -> None:
        """Initializes the class"""
        self.__logger = self.__setup_loger()
        url = self.__validate_url(self.__logger, url)
        self.__driver = self.__setup_selenium_driver(self.__logger)
        self.__open_immuniweb(self.__logger, self.__driver, self._IMMUNIWEB)

    def __del__(self) -> None:
        """Tears down the driver"""
        self.__logger.debug("Tearing down driver")
        try:
            self.__driver.quit()
        except selenium_exceptions.WebDriverException as ex:
            self.__logger.critical("Unable to quit driver: %s", ex.__doc__)
            raise (f"Unable to quit driver: {ex.__doc__}") from ex
        except Exception as ex:
            self.__logger.critical("Unable to quit driver: %s", ex.__doc__)
            raise (f"Unable to quit driver: {ex.__doc__}") from ex
        else:
            del self.__driver
            self.__logger.debug("Tear Down Successfully.")
            del self.__logger

    @staticmethod
    def __setup_loger():
        """setup the logger
            Log Example:
                2022-05-24 00:45:56,230 - WebSec - DEBUG: Message
            Returns:
                logging.Logger: logger"""
        logging.basicConfig(
            format='%(asctime)s - %(name)s - %(levelname)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            level=logging.DEBUG,
            filename='logs/seo_se_ranking.log',
            filemode="w")
        return logging.getLogger("WebSec")

    @staticmethod
    def __setup_selenium_driver(logger) -> webdriver.Chrome:
        """Sets up the selenium driver
            Returns:
                webdriver.Chrome: selenium driver
            Raises:
                WebDriverException: if unable to open selenium driver
                Exception: if unable to open selenium driver"""
        logger.debug("Setting up selenium")
        options = webdriver.ChromeOptions()
        options.headless = True
        try:
            driver = webdriver.Chrome(
                executable_path="C:\\Program Files (x86)\\chromedriver.exe", options=options)
        except selenium_exceptions.WebDriverException:
            try:
                driver = webdriver.Chrome(
                    executable_path="C:\\chromedriver.exe", options=options)
            except selenium_exceptions.WebDriverException as ex:
                logger.critical("Chrome driver not found: %s", ex.__doc__)
                raise (f"Chrome driver not found: {ex.__doc__}") from ex
            except Exception as ex:
                logger.critical("Exception: %s", ex.__doc__)
                raise (f"Exception: {ex.__doc__}") from ex
            else:
                driver.implicitly_wait(5)
                logger.debug("Returning driver: %s", driver)
        return driver

    @staticmethod
    def __validate_url(logger, url: str) -> str:
        """validate the url
            by removing the http:// or https:// or www.
            Args:
            url (str): url to validate
            Returns:
                str: url without http:// or https:// or www.
            Raises:
                Exception: if url is not string"""
        if url_validator(url):
            logger.info("Valid url: %s", url)
            if url.startswith("http://www."):
                url = url[11:]
            elif url.startswith("http://"):
                url = url[7:]
            elif url.startswith("https://www."):
                url = url[12:]
            elif url.startswith("https://"):
                url = url[8:]
            elif url.startswith("www."):
                url = url[4:]
            if url.endswith("/"):
                url = url[:-1]
            logger.debug("Returning url: %s", url)
        else:
            logger.critical("Invalid url: %s", url)
            raise Exception("Invalid url")
        return url

    @staticmethod
    def __open_immuniweb(logger, driver, url):
        """Opens the immuniweb page

        Args:
            logger (logging.Logger): logger
            driver (webdriver.Chrome): driver
            url (str): url to open

        Raises:
            TimeoutException: if timeout
            WebDriverException: if chrome driver not found
            Exception: if any other exception"""
        try:
            driver.get(url)
        except selenium_exceptions.TimeoutException as ex:
            logger.critical("TimeoutException: %s", ex.__doc__)
            raise (f"TimeoutException: {ex.__doc__}") from ex
        except selenium_exceptions.WebDriverException as ex:
            logger.critical("Unable to open SE Ranking: %s", ex.__doc__)
            raise (f"Unable to open SE Ranking: {ex.__doc__}") from ex
        except Exception as ex:
            logger.critical("Unable to open SE Ranking: %s", ex.__doc__)
            raise (f"Unable to open SE Ranking: {ex.__doc__}") from ex
        else:
            driver.maximize_window()
            driver.implicitly_wait(5)

    @staticmethod
    def __define_text_field(logger, driver, locator):
        """Defines the text field

        Args:
            logger (logging.Logger): logger
            driver (webdriver.Chrome): driver
            locator (tuple): locator

        Returns:
            WebElement: text field
        Raises:
            NoSuchElementException: if text field not found
            Exception: if any other exception"""
        try:
            text_field = WebDriverWait(driver, 10).until(
                EC.presence_of_element_located(locator))
        except selenium_exceptions.NoSuchElementException as ex:
            logger.critical("NoSuchElementException: %s", ex.__doc__)
            raise (f"NoSuchElementException: {ex.__doc__}") from ex
        except Exception as ex:
            logger.critical("Exception: %s", ex.__doc__)
            raise (f"Exception: {ex.__doc__}") from ex
        else:
            logger.debug("Returning text field: %s", text_field)
        return text_field

    @staticmethod
    def __define_button(logger, driver, locator):
        """Defines the button

        Args:
            logger (logging.Logger): logger
            driver (webdriver.Chrome): driver
            locator (tuple): locator

        Returns:
            WebElement: button
        Raises:
            NoSuchElementException: if button not found
            Exception: if any other exception"""
        try:
            button = WebDriverWait(driver, 10).until(
                EC.element_to_be_clickable(locator))
        except selenium_exceptions.NoSuchElementException as ex:
            logger.critical("NoSuchElementException: %s", ex.__doc__)
            raise (f"NoSuchElementException: {ex.__doc__}") from ex
        except Exception as ex:
            logger.critical("Exception: %s", ex.__doc__)
            raise (f"Exception: {ex.__doc__}") from ex
        else:
            logger.debug("Returning button: %s", button)
        return button

    @staticmethod
    def __send_text(logger, text_field, text):
        """Sends text to a text field

        Args:
            logger (logging.Logger): logger
            text_field (WebElement): text field
            text (str): text to send

        Raises:
            Exception: if any exception"""
        try:
            text_field.clear()
            text_field.send_keys(text)
        except Exception as ex:
            logger.critical("Exception: %s", ex.__doc__)
            raise (f"Exception: {ex.__doc__}") from ex

    @staticmethod
    def __click_button(logger, button):
        """Clicks a button

        Args:
            logger (logging.Logger): logger
            button (WebElement): button

        Raises:
            Exception: if any exception"""
        try:
            button.click()
        except Exception as ex:
            logger.critical("Exception: %s", ex.__doc__)
            raise (f"Exception: {ex.__doc__}") from ex

    def __start_scan(self, url: str):
        """Starts the scan
            Args:
                url (str): url to scan
            Returns:
                dict: scan results
            Raises:
                Exception: if any exception"""
        self.__logger.info("Starting scan for url: %s", url)


if __name__ == "__main__":
    pass
