import requests
import re
from urllib.parse import urlparse
from .utils import sleep

SAFE_IDS = ["1", "2", "9999"]

def check_cors(url):
    try:
        r = requests.get(url, headers={"Origin": "https://evil.com"}, timeout=5)
        return r.headers.get("Access-Control-Allow-Origin")
    except:
        return None

def check_auth(url, auth=None):
    try:
        r1 = requests.get(url, timeout=5)
        r2 = requests.get(url, headers={"Authorization": auth}, timeout=5) if auth else None

        if r2 and r1.status_code < 400 and abs(len(r1.text) - len(r2.text)) < 10:
            return True
    except:
        pass
    return False

def check_idor(url):
    if "{id}" not in url:
        return False

    try:
        lengths = []
        for i in SAFE_IDS:
            r = requests.get(url.format(id=i), timeout=5)
            lengths.append(len(r.text))

        return len(set(lengths)) <= 2
    except:
        return False

def scan(url, auth=None):
    result = []

    if check_cors(url) == "*":
        result.append(("CORS misconfig", "High"))

    if check_auth(url, auth):
        result.append(("Auth bypass", "High"))

    if check_idor(url):
        result.append(("IDOR suspected", "High"))

    return result
