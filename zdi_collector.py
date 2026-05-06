import argparse
import json
import sys
import time

import requests
from bs4 import BeautifulSoup

BASE_URL = "https://www.zerodayinitiative.com"
USER_AGENT = "ZDI-Collector/1.0"
MAX_RETRIES = 3


def fetch_url(url, delay=1):
    headers = {"User-Agent": USER_AGENT}
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            return response.text
        except Exception as e:
            print(f"Attempt {attempt + 1} failed for {url}: {e}", file=sys.stderr)
            if attempt < MAX_RETRIES - 1:
                time.sleep(2 ** attempt)
    return None
