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


class Locators(object):
    """Defines the locator for the web elements."""
    IMMUNIWEB = "https://www.immuniweb.com/websec/"


class WebSec:
    """foo"""


if __name__ == "__main__":
    pass