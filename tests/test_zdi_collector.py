import unittest
from unittest.mock import patch, MagicMock
from zdi_collector import fetch_url, scrape_listing, scrape_detail


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


if __name__ == "__main__":
    unittest.main()
