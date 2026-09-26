"""Polite HTTP client shared by all pipeline stages."""
from __future__ import annotations

import time
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)


class Fetcher:
    def __init__(self, delay: float = 1.0, timeout: float = 30.0):
        self.delay = delay
        self.timeout = timeout
        self._last: dict[str, float] = {}
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": USER_AGENT,
            "Accept-Language": "en-US,en;q=0.9",
        })
        retry = Retry(total=3, backoff_factor=1.5,
                      status_forcelist=(429, 500, 502, 503, 504),
                      allowed_methods=("GET", "HEAD"))
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self._cache: dict[str, requests.Response] = {}

    def _throttle(self, url: str) -> None:
        host = urlparse(url).netloc
        wait = self._last.get(host, 0) + self.delay - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        self._last[host] = time.monotonic()

    def get(self, url: str, *, stream: bool = False, cache: bool = True) -> requests.Response | None:
        if cache and not stream and url in self._cache:
            return self._cache[url]
        self._throttle(url)
        try:
            resp = self.session.get(url, timeout=self.timeout, stream=stream, allow_redirects=True)
        except requests.RequestException as exc:
            print(f"  ! fetch failed {url}: {exc}")
            return None
        if resp.status_code >= 400:
            print(f"  ! HTTP {resp.status_code} {url}")
            return None
        if cache and not stream:
            self._cache[url] = resp
        return resp

    def get_text(self, url: str) -> str | None:
        resp = self.get(url)
        if resp is None:
            return None
        resp.encoding = resp.encoding or resp.apparent_encoding
        return resp.text

    def get_json(self, url: str):
        resp = self.get(url)
        if resp is None:
            return None
        try:
            return resp.json()
        except ValueError:
            return None
