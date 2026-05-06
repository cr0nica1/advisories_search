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


def _parse_detail_table(soup):
    fields = {}
    for tr in soup.find_all("tr"):
        cells = tr.find_all("td")
        if len(cells) >= 2:
            key = cells[0].get_text(strip=True)
            value = cells[1].get_text(strip=True)
            fields[key] = value
    return fields


def _parse_cvss(raw):
    if not raw:
        return None, None
    parts = raw.split(",", 1)
    score = float(parts[0].strip())
    vector = parts[1].strip() if len(parts) > 1 else None
    return score, vector


def _parse_published_date(soup):
    import re
    for p in soup.find_all("p"):
        text = p.get_text(strip=True)
        match = re.match(
            r"([A-Z][a-z]+ \d{1,2}(?:st|nd|rd|th)?,?\s+\d{4})", text
        )
        if match:
            from datetime import datetime
            raw = match.group(1).replace("st", "").replace("nd", "").replace("rd", "").replace("th", "")
            return datetime.strptime(raw, "%B %d, %Y").strftime("%Y-%m-%d")
    return None


def scrape_detail(zdi_id):
    url = f"{BASE_URL}/advisories/{zdi_id}/"
    html = fetch_url(url)
    if html is None:
        return None

    soup = BeautifulSoup(html, "html.parser")
    fields = _parse_detail_table(soup)

    cvss_score, cvss_vector = _parse_cvss(fields.get("CVSS SCORE"))
    title_el = soup.find("h2")
    title = title_el.get_text(strip=True) if title_el else None

    return {
        "zdi_id": zdi_id,
        "vendor": fields.get("AFFECTED VENDORS"),
        "product": fields.get("AFFECTED PRODUCTS"),
        "version_affected": None,
        "cve_id": fields.get("CVE ID") or None,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "title": title,
        "published_date": _parse_published_date(soup),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Collect ZDI advisory data by year"
    )
    parser.add_argument("--year", type=int, required=True, help="Target year (e.g., 2026)")
    parser.add_argument("--output", type=str, default=None, help="Output JSON file path")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay between requests in seconds")
    args = parser.parse_args()

    output_path = args.output or f"zdi_advisories_{args.year}.json"

    print(f"Scraping ZDI advisory listing for {args.year}...")
    advisory_ids = scrape_listing(args.year)
    print(f"Found {len(advisory_ids)} advisories for {args.year}.")

    advisories = []
    for i, zdi_id in enumerate(advisory_ids, 1):
        print(f"[{i}/{len(advisory_ids)}] Scraping {zdi_id}...")
        detail = scrape_detail(zdi_id)
        if detail:
            advisories.append(detail)
        else:
            print(f"  WARNING: Failed to scrape {zdi_id}, skipping.", file=sys.stderr)
        if i < len(advisory_ids):
            time.sleep(args.delay)

    with open(output_path, "w") as f:
        json.dump(advisories, f, indent=2)

    print(f"Wrote {len(advisories)} advisories to {output_path}")


if __name__ == "__main__":
    main()
