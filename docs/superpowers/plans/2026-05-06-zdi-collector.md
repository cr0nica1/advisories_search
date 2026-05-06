# ZDI Advisory Data Collector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Python CLI tool that scrapes ZDI published advisories by year and outputs structured JSON.

**Architecture:** Single script `zdi_collector.py` with three core functions: scrape listing page to get advisory IDs, scrape each detail page for structured fields, and orchestrate via CLI. Uses `requests` + `beautifulsoup4`. Tests use `unittest` with `unittest.mock` to avoid hitting the live site.

**Tech Stack:** Python 3, requests, beautifulsoup4, unittest

---

### Task 1: Project setup and HTTP helper with retry

**Files:**
- Create: `zdi_collector.py`
- Create: `requirements.txt`
- Create: `tests/test_zdi_collector.py`

- [ ] **Step 1: Create requirements.txt**

```
requests>=2.31.0
beautifulsoup4>=4.12.0
```

- [ ] **Step 2: Write the failing test for `fetch_url` retry logic**

```python
# tests/test_zdi_collector.py
import unittest
from unittest.mock import patch, MagicMock
from zdi_collector import fetch_url


class TestFetchUrl(unittest.TestCase):
    @patch("zdi_collector.requests.get")
    def test_returns_html_on_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html>ok</html>"
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        result = fetch_url("https://example.com")
        self.assertEqual(result, "<html>ok</html>")

    @patch("zdi_collector.requests.get")
    @patch("zdi_collector.time.sleep")
    def test_retries_on_failure_then_succeeds(self, mock_sleep, mock_get):
        fail_response = MagicMock()
        fail_response.raise_for_status.side_effect = Exception("Connection error")

        success_response = MagicMock()
        success_response.status_code = 200
        success_response.text = "<html>ok</html>"
        success_response.raise_for_status = MagicMock()

        mock_get.side_effect = [fail_response, success_response]

        result = fetch_url("https://example.com")
        self.assertEqual(result, "<html>ok</html>")
        self.assertEqual(mock_get.call_count, 2)

    @patch("zdi_collector.requests.get")
    @patch("zdi_collector.time.sleep")
    def test_returns_none_after_max_retries(self, mock_sleep, mock_get):
        fail_response = MagicMock()
        fail_response.raise_for_status.side_effect = Exception("Connection error")
        mock_get.return_value = fail_response

        result = fetch_url("https://example.com")
        self.assertIsNone(result)
        self.assertEqual(mock_get.call_count, 3)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd /home/minhht21/Documents/advisory_research && python -m pytest tests/test_zdi_collector.py -v`
Expected: FAIL — `zdi_collector` module not found

- [ ] **Step 4: Write minimal `fetch_url` implementation**

```python
# zdi_collector.py
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
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd /home/minhht21/Documents/advisory_research && python -m pytest tests/test_zdi_collector.py::TestFetchUrl -v`
Expected: 3 tests PASS

- [ ] **Step 6: Commit**

```bash
cd /home/minhht21/Documents/advisory_research
git add requirements.txt zdi_collector.py tests/test_zdi_collector.py
git commit -m "feat: add project setup with fetch_url and retry logic"
```

---

### Task 2: Listing page parser — `scrape_listing`

**Files:**
- Modify: `zdi_collector.py`
- Modify: `tests/test_zdi_collector.py`

- [ ] **Step 1: Write the failing test for `scrape_listing`**

Add to `tests/test_zdi_collector.py`:

```python
from zdi_collector import scrape_listing


class TestScrapeListing(unittest.TestCase):
    LISTING_HTML = """
    <html><body><table>
    <tr><td>ZDI-26-292</td><td>ZDI-CAN-28327</td><td>QNAP</td><td>CVE-2026-22898</td><td>8.8</td><td>2026-04-15</td><td>2026-04-15</td><td>QNAP TS-453E QVRPro excpostgres Vulnerability</td></tr>
    <tr><td>ZDI-26-291</td><td>ZDI-CAN-28516</td><td>NI</td><td>CVE-2026-32861</td><td>7.8</td><td>2026-04-15</td><td>2026-04-15</td><td>NI LabVIEW LVCLASS Vulnerability</td></tr>
    <tr><td>ZDI-25-500</td><td>ZDI-CAN-12345</td><td>Foo</td><td>CVE-2025-1111</td><td>9.8</td><td>2025-12-01</td><td>2025-12-01</td><td>Foo Bar Vulnerability</td></tr>
    </table></body></html>
    """

    @patch("zdi_collector.fetch_url")
    def test_returns_ids_for_target_year(self, mock_fetch):
        mock_fetch.return_value = self.LISTING_HTML
        result = scrape_listing(2026)
        self.assertEqual(result, ["ZDI-26-292", "ZDI-26-291"])

    @patch("zdi_collector.fetch_url")
    def test_excludes_other_years(self, mock_fetch):
        mock_fetch.return_value = self.LISTING_HTML
        result = scrape_listing(2025)
        self.assertEqual(result, ["ZDI-25-500"])

    @patch("zdi_collector.fetch_url")
    def test_returns_empty_on_failure(self, mock_fetch):
        mock_fetch.return_value = None
        result = scrape_listing(2026)
        self.assertEqual(result, [])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/minhht21/Documents/advisory_research && python -m pytest tests/test_zdi_collector.py::TestScrapeListing -v`
Expected: FAIL — `scrape_listing` not defined

- [ ] **Step 3: Write `scrape_listing` implementation**

Add to `zdi_collector.py`:

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/minhht21/Documents/advisory_research && python -m pytest tests/test_zdi_collector.py::TestScrapeListing -v`
Expected: 3 tests PASS

- [ ] **Step 5: Commit**

```bash
cd /home/minhht21/Documents/advisory_research
git add zdi_collector.py tests/test_zdi_collector.py
git commit -m "feat: add scrape_listing to parse ZDI advisory listing page"
```

---

### Task 3: Detail page parser — `scrape_detail`

**Files:**
- Modify: `zdi_collector.py`
- Modify: `tests/test_zdi_collector.py`

- [ ] **Step 1: Write the failing test for `scrape_detail`**

Add to `tests/test_zdi_collector.py`:

```python
from zdi_collector import scrape_detail


class TestScrapeDetail(unittest.TestCase):
    DETAIL_HTML = """
    <html><body>
    <h2>QNAP TS-453E QVRPro excpostgres Exposed Dangerous Method Remote Code Execution Vulnerability</h2>
    <h3>ZDI-26-292 ZDI-CAN-28327</h3>
    <table>
    <tr><td>CVE ID</td><td>CVE-2026-22898</td></tr>
    <tr><td>CVSS SCORE</td><td>8.8, AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</td></tr>
    <tr><td>AFFECTED VENDORS</td><td>QNAP</td></tr>
    <tr><td>AFFECTED PRODUCTS</td><td>TS-453E</td></tr>
    <tr><td>VULNERABILITY DETAILS</td><td>This vulnerability allows network-adjacent attackers...</td></tr>
    </table>
    <p>April 15th, 2026</p>
    </body></html>
    """

    @patch("zdi_collector.fetch_url")
    def test_parses_all_fields(self, mock_fetch):
        mock_fetch.return_value = self.DETAIL_HTML
        result = scrape_detail("ZDI-26-292")
        self.assertEqual(result["zdi_id"], "ZDI-26-292")
        self.assertEqual(result["vendor"], "QNAP")
        self.assertEqual(result["product"], "TS-453E")
        self.assertEqual(result["version_affected"], None)
        self.assertEqual(result["cve_id"], "CVE-2026-22898")
        self.assertEqual(result["cvss_score"], 8.8)
        self.assertEqual(result["cvss_vector"], "AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertEqual(result["published_date"], "2026-04-15")

    @patch("zdi_collector.fetch_url")
    def test_returns_none_on_fetch_failure(self, mock_fetch):
        mock_fetch.return_value = None
        result = scrape_detail("ZDI-26-292")
        self.assertIsNone(result)

    @patch("zdi_collector.fetch_url")
    def test_handles_missing_cve(self, mock_fetch):
        html_no_cve = """
        <html><body>
        <h2>Some Title</h2>
        <h3>ZDI-26-275 ZDI-CAN-27212</h3>
        <table>
        <tr><td>CVSS SCORE</td><td>8.8</td></tr>
        <tr><td>AFFECTED VENDORS</td><td>Microsoft</td></tr>
        <tr><td>AFFECTED PRODUCTS</td><td>Qlib</td></tr>
        </table>
        <p>April 15th, 2026</p>
        </body></html>
        """
        mock_fetch.return_value = html_no_cve
        result = scrape_detail("ZDI-26-275")
        self.assertEqual(result["cve_id"], None)
        self.assertEqual(result["cvss_score"], 8.8)
        self.assertEqual(result["vendor"], "Microsoft")
        self.assertEqual(result["product"], "Qlib")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/minhht21/Documents/advisory_research && python -m pytest tests/test_zdi_collector.py::TestScrapeDetail -v`
Expected: FAIL — `scrape_detail` not defined

- [ ] **Step 3: Write `scrape_detail` implementation**

Add to `zdi_collector.py`:

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/minhht21/Documents/advisory_research && python -m pytest tests/test_zdi_collector.py::TestScrapeDetail -v`
Expected: 3 tests PASS

- [ ] **Step 5: Commit**

```bash
cd /home/minhht21/Documents/advisory_research
git add zdi_collector.py tests/test_zdi_collector.py
git commit -m "feat: add scrape_detail to parse individual ZDI advisory pages"
```

---

### Task 4: CLI orchestrator — `main()`

**Files:**
- Modify: `zdi_collector.py`

- [ ] **Step 1: Write the `main` function and `argparse` setup**

Add to `zdi_collector.py`:

```python
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
```

- [ ] **Step 2: Smoke test the CLI help**

Run: `cd /home/minhht21/Documents/advisory_research && python zdi_collector.py --help`
Expected: Shows usage with `--year`, `--output`, `--delay` arguments

- [ ] **Step 3: Run all tests to verify nothing broke**

Run: `cd /home/minhht21/Documents/advisory_research && python -m pytest tests/test_zdi_collector.py -v`
Expected: All tests PASS

- [ ] **Step 4: Commit**

```bash
cd /home/minhht21/Documents/advisory_research
git add zdi_collector.py
git commit -m "feat: add CLI orchestrator with argparse"
```

---

### Task 5: End-to-end integration test and install deps

**Files:**
- Create: `tests/__init__.py`

- [ ] **Step 1: Install dependencies**

Run: `pip install requests beautifulsoup4 pytest`

- [ ] **Step 2: Create tests/__init__.py**

Create empty file `tests/__init__.py` so pytest discovers the package.

- [ ] **Step 3: Run the full test suite**

Run: `cd /home/minhht21/Documents/advisory_research && python -m pytest tests/test_zdi_collector.py -v`
Expected: All tests PASS (9 total: 3 fetch_url + 3 listing + 3 detail)

- [ ] **Step 4: Commit**

```bash
cd /home/minhht21/Documents/advisory_research
git add tests/__init__.py
git commit -m "chore: add test package init and verify full test suite"
```
