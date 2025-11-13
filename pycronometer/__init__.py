import typing
from bs4 import BeautifulSoup
import requests
import re
import io
import json

import urllib3


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

    session: typing.Tuple[int, str] | None

    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self.session = None

    @classmethod
    def _get_anticsrf_token(cls, session: requests.Session):
        soup = BeautifulSoup(session.get(cls.HTML_LOGIN_URL).text, "html.parser")
        input = soup.find("input", {"name": "anticsrf"})
        assert input is not None
        return input.get("value")

    def _login(self):
        session = requests.session()

        r = session.post(
            self.API_LOGIN_URL,
            data={
                "username": self.username,
                "password": self.password,
                "anticsrf": self._get_anticsrf_token(session),
            },
            headers={
                "content-type": "application/x-www-form-urlencoded",
            },
        )
        r.raise_for_status()
        r = r.json()
        if "error" in r:
            raise Error(r["error"])

        self.session = (
            self._gwt_call(
                session,
                [
                    7,
                    0,
                    5,
                    self.GWT_RPC_MODULE_BASE,
                    self.GWT_RPC_SERVICE_STRONG_NAME,
                    self.GWT_RPC_SERVICE_NAME,
                    "authenticate",
                    "java.lang.Integer/3438268394",
                    1,
                    2,
                    3,
                    4,
                    1,
                    5,
                    5,
                    -480,
                ],
            )[0],
            session.cookies["sesnonce"],
        )

    @classmethod
    def _gwt_call(cls, session: requests.Session, body: typing.List[str | int]):
        r = session.post(
            cls.GWT_BASE_URL,
            data="|".join(str(x) for x in body) + "|",
            headers=cls.GWT_HTTP_HEADERS,
        )
        r.raise_for_status()
        payload = json.loads(r.text[4:])

        if not r.text.startswith("//OK"):
            raise Error(*payload)

        return payload

    def _generate_auth_token(self) -> str:
        assert self.session is not None

        user_id, sesnonce = self.session
        return self._gwt_call(
            requests.Session(),
            [
                7,
                0,
                8,
                self.GWT_RPC_MODULE_BASE,
                self.GWT_RPC_SERVICE_STRONG_NAME,
                self.GWT_RPC_SERVICE_NAME,
                "generateAuthorizationToken",
                "java.lang.String/2004016611",
                "I",
                "com.cronometer.shared.user.AuthScope/2065601159",
                sesnonce,
                1,
                2,
                3,
                4,
                4,
                5,
                6,
                6,
                7,
                8,
                user_id,
                3600,
                7,
                2,
            ],
        )[1]

    def generate_auth_token_or_refresh(self) -> str:
        if self.session is None:
            self._login()

        try:
            return self._generate_auth_token()
        except Error as e:
            if e.args[2][0].startswith(
                "com.cronometer.shared.user.exceptions.NotLoggedInException/"
            ):
                self._login()

        return self._generate_auth_token()

    def export(self, **params) -> urllib3.HTTPResponse:
        r = requests.get(
            "https://cronometer.com/export",
            params={"nonce": self.generate_auth_token_or_refresh(), **params},
            stream=True,
        )
        r.raise_for_status()
        return r.raw
