from bs4 import BeautifulSoup
import requests
import re
import io
import json


class Error(Exception):
    pass


class Cronometer:
    GWT_RPC_MODULE_BASE = "https://cronometer.com/cronometer/"

    GWT_RPC_SERVICE_STRONG_NAME = "2D6A926E3729946302DC68073CB0D550"
    GWT_RPC_PERMUTATION_STRONG_NAME = "7B121DC5483BF272B1BC1916DA9FA963"

    GWT_HTTP_HEADERS = {
        "content-type": "text/x-gwt-rpc; charset=UTF-8",
        "x-gwt-module-base": GWT_RPC_MODULE_BASE,
        "x-gwt-permutation": GWT_RPC_PERMUTATION_STRONG_NAME,
    }

    GWT_RPC_SERVICE_NAME = "com.cronometer.shared.rpc.CronometerService"

    HTML_LOGIN_URL = "https://cronometer.com/login/"
    API_LOGIN_URL = "https://cronometer.com/login"

    GWT_BASE_URL = "https://cronometer.com/cronometer/app"
    GWT_USER_ID_REGEX = re.compile(r"//OK\[(?P<userid>\d+),")

    def __init__(self, username: str, password: str):
        session = requests.session()

        r = session.post(
            self.API_LOGIN_URL,
            data={
                "username": username,
                "password": password,
                "anticsrf": (
                    BeautifulSoup(session.get(self.HTML_LOGIN_URL).text, "html.parser")
                    .find("input", {"name": "anticsrf"})
                    .get("value")
                ),
            },
            headers={
                "content-type": "application/x-www-form-urlencoded",
            },
        )
        r.raise_for_status()
        r = r.json()
        if "error" in r:
            raise Error(r["error"])

        r = session.post(
            self.GWT_BASE_URL,
            data=f"7|0|5|{self.GWT_RPC_MODULE_BASE}|{self.GWT_RPC_SERVICE_STRONG_NAME}|{self.GWT_RPC_SERVICE_NAME}|authenticate|java.lang.Integer/3438268394|1|2|3|4|1|5|5|-480|",
            headers=self.GWT_HTTP_HEADERS,
        )
        r.raise_for_status()
        if not r.text.startswith("//OK"):
            raise Error(r.text)

        self.sesnonce = session.cookies["sesnonce"]
        self.user_id = json.loads(r.text[4:])[0]

    def _generate_auth_token(self):
        r = requests.post(
            self.GWT_BASE_URL,
            data=f"7|0|8|{self.GWT_RPC_MODULE_BASE}|{self.GWT_RPC_SERVICE_STRONG_NAME}|{self.GWT_RPC_SERVICE_NAME}|generateAuthorizationToken|java.lang.String/2004016611|I|com.cronometer.shared.user.AuthScope/2065601159|{self.sesnonce}|1|2|3|4|4|5|6|6|7|8|{self.user_id}|3600|7|2|",
            headers=self.GWT_HTTP_HEADERS,
        )
        r.raise_for_status()
        if not r.text.startswith("//OK"):
            raise Error(r.text)
        return json.loads(r.text[4:])[1]

    def export(self, **params):
        r = requests.get(
            "https://cronometer.com/export",
            params={"nonce": self._generate_auth_token(), **params},
            stream=True,
        )
        r.raise_for_status()
        return r.raw
