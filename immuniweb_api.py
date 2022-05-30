"""foo"""
import socket
import time

import requests


class Api:
    """foo"""

    def __init__(self, website: str):
        """foo"""
        try:
            choosen_ip = str(socket.gethostbyname('goodreads.com'))
        except Exception:
            choosen_ip = "any"
        self.headers = {
            'tested_url': website,
            'dnsr': 'off',
            'recheck': 'false',
            'choosen_ip': choosen_ip
        }
        ustamp = int(time.time())
        self.api = f'https://www.immuniweb.com/websec/api/v1/chsec/{ustamp}.html'

    def __call__(self):
        result = requests.post(url=self.api, headers=self.headers).text
        return result

    def __del__(self):
        del self.api, self.headers


if __name__ == '__main__':
    api = Api('twitter.com')
    print(api.headers)
    print(api.api)
    print(api())
