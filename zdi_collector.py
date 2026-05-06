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


def scrape_listing(year):
    url = f"{BASE_URL}/advisories/published/"
    html = fetch_url(url)
    if html is None:
        return []

    soup = BeautifulSoup(html, "html.parser")
    year_prefix = f"ZDI-{str(year)[-2:]}-"
    ids = []

    for tr in soup.find_all("tr"):
        cells = tr.find_all("td")
        if cells:
            first_cell = cells[0].get_text(strip=True)
            if first_cell.startswith(year_prefix):
                ids.append(first_cell)

    return ids
