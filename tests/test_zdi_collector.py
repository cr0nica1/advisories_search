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
