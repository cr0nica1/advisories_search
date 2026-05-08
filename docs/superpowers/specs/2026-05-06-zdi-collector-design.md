# ZDI Advisory Data Collector — Design Spec

## Purpose

A CLI tool that scrapes Zero Day Initiative (ZDI) published advisories by year and outputs structured JSON with vendor, product, CVE, and CVSS data.

## Data Model

Each advisory record:

```json
{
  "zdi_id": "ZDI-26-292",
  "vendor": "QNAP",
  "product": "TS-453E",
  "version_affected": null,
  "cve_id": "CVE-2026-22898",
  "cvss_score": 8.8,
  "cvss_vector": "AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "title": "QNAP TS-453E QVRPro excpostgres Exposed Dangerous Method Remote Code Execution Vulnerability",
  "published_date": "2026-04-15"
}
```

## Architecture

Single Python script `zdi_collector.py` with three functions:

1. `scrape_listing(year)` — fetches `/advisories/published/`, parses the advisory table, filters rows where ZDI ID matches the target year prefix (e.g., `ZDI-26-`), returns list of advisory IDs
2. `scrape_detail(zdi_id)` — fetches `/advisories/{zdi_id}/`, extracts structured fields from the detail table (CVE ID, CVSS SCORE, AFFECTED VENDORS, AFFECTED PRODUCTS)
3. `main()` — orchestrates: parse args → scrape listing → scrape each detail page → write JSON output

## CLI Interface

```
python zdi_collector.py --year 2026 [--output advisories.json] [--delay 1]
```

- `--year` (required): target year (e.g., 2026)
- `--output`: output file path (default: `zdi_advisories_{year}.json`)
- `--delay`: seconds between detail page requests (default: 1)

## Data Source

- Listing page: `https://www.zerodayinitiative.com/advisories/published/` — contains all published advisories in a table
- Detail page: `https://www.zerodayinitiative.com/advisories/ZDI-XX-NNN/` — structured fields per advisory

## Parsing Strategy

### Listing page
- Table has columns: ZDI ID, ZDI-CAN ID, Vendor, CVE ID, CVSS Score, Published Date, Updated Date, Title
- Filter rows by ZDI ID prefix matching target year
- Extract ZDI IDs for detail page fetching

### Detail page
- Parse the key-value table with fields: CVE ID, CVSS SCORE, AFFECTED VENDORS, AFFECTED PRODUCTS, VULNERABILITY DETAILS
- CVSS SCORE field contains score and vector string (e.g., "8.8, AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
- AFFECTED PRODUCTS is the product name (e.g., "TS-453E")
- version_affected is not a structured field on ZDI; set to null

## Error Handling

- Retry failed requests up to 3 times with exponential backoff (1s, 2s, 4s)
- Skip advisories where detail page parsing fails, log warning to stderr
- Continue on individual failures — don't abort the whole run

## Dependencies

- `requests` — HTTP client
- `beautifulsoup4` — HTML parsing

## Constraints

- Polite rate limiting: 1 second delay between detail page requests (configurable)
- User-Agent header set to identify the tool
- No authentication required for ZDI public advisory pages