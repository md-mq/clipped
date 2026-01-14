from unittest import TestCase
from unittest.mock import MagicMock, patch

from clipped.utils.requests import (
    DEFAULT_BLOCKED_HOSTS,
    DEFAULT_BLOCKED_PREFIXES,
    create_session,
    safe_request,
)


class TestCreateSession(TestCase):
    def test_creates_default_session(self):
        session = create_session()
        self.assertIsNotNone(session)

    def test_uses_provided_session(self):
        import requests

        existing_session = requests.Session()
        session = create_session(session=existing_session)
        self.assertIs(session, existing_session)

    def test_applies_session_attrs(self):
        session = create_session(
            session_attrs={
                "verify": False,
                "stream": True,
            }
        )
        self.assertFalse(session.verify)
        self.assertTrue(session.stream)


class TestDefaultBlockedLists(TestCase):
    def test_blocked_hosts_contains_localhost(self):
        self.assertIn("localhost", DEFAULT_BLOCKED_HOSTS)
        self.assertIn("127.0.0.1", DEFAULT_BLOCKED_HOSTS)
        self.assertIn("0.0.0.0", DEFAULT_BLOCKED_HOSTS)

    def test_blocked_hosts_contains_cloud_metadata(self):
        self.assertIn("169.254.169.254", DEFAULT_BLOCKED_HOSTS)
        self.assertIn("metadata.google.internal", DEFAULT_BLOCKED_HOSTS)

    def test_blocked_prefixes_contains_private_ranges(self):
        self.assertIn("10.", DEFAULT_BLOCKED_PREFIXES)
        self.assertIn("172.16.", DEFAULT_BLOCKED_PREFIXES)
        self.assertIn("192.168.", DEFAULT_BLOCKED_PREFIXES)


class TestSafeRequestSSRFProtection(TestCase):
    def test_blocks_localhost_when_validation_enabled(self):
        with self.assertRaises(ValueError) as ctx:
            safe_request("http://localhost/api", validate_url_security=True)
        self.assertIn("Invalid or blocked URL", str(ctx.exception))

    def test_blocks_127_0_0_1_when_validation_enabled(self):
        with self.assertRaises(ValueError) as ctx:
            safe_request("http://127.0.0.1/api", validate_url_security=True)
        self.assertIn("Invalid or blocked URL", str(ctx.exception))

    def test_blocks_aws_metadata_when_validation_enabled(self):
        with self.assertRaises(ValueError) as ctx:
            safe_request(
                "http://169.254.169.254/latest/meta-data", validate_url_security=True
            )
        self.assertIn("Invalid or blocked URL", str(ctx.exception))

    def test_blocks_gcp_metadata_when_validation_enabled(self):
        with self.assertRaises(ValueError) as ctx:
            safe_request(
                "http://metadata.google.internal/computeMetadata",
                validate_url_security=True,
            )
        self.assertIn("Invalid or blocked URL", str(ctx.exception))

    def test_blocks_private_ip_10_range_when_validation_enabled(self):
        with self.assertRaises(ValueError) as ctx:
            safe_request("http://10.0.0.1/api", validate_url_security=True)
        self.assertIn("Invalid or blocked URL", str(ctx.exception))

    def test_blocks_private_ip_172_range_when_validation_enabled(self):
        with self.assertRaises(ValueError) as ctx:
            safe_request("http://172.16.0.1/api", validate_url_security=True)
        self.assertIn("Invalid or blocked URL", str(ctx.exception))

    def test_blocks_private_ip_192_range_when_validation_enabled(self):
        with self.assertRaises(ValueError) as ctx:
            safe_request("http://192.168.1.1/api", validate_url_security=True)
        self.assertIn("Invalid or blocked URL", str(ctx.exception))

    def test_blocks_invalid_scheme_when_validation_enabled(self):
        with self.assertRaises(ValueError) as ctx:
            safe_request("ftp://example.com/file", validate_url_security=True)
        self.assertIn("Invalid or blocked URL", str(ctx.exception))

    def test_blocks_file_scheme_when_validation_enabled(self):
        with self.assertRaises(ValueError) as ctx:
            safe_request("file:///etc/passwd", validate_url_security=True)
        self.assertIn("Invalid or blocked URL", str(ctx.exception))

    @patch("clipped.utils.requests.create_session")
    def test_allows_valid_url_when_validation_enabled(self, mock_create_session):
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_session.request.return_value = mock_response
        mock_create_session.return_value = mock_session

        response = safe_request("https://example.com/api", validate_url_security=True)

        self.assertEqual(response.status_code, 200)
        mock_session.request.assert_called_once()

    @patch("clipped.utils.requests.create_session")
    def test_allows_blocked_url_when_validation_disabled(self, mock_create_session):
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_session.request.return_value = mock_response
        mock_create_session.return_value = mock_session

        # Should not raise when validation is disabled (default)
        response = safe_request("http://localhost/api", validate_url_security=False)

        self.assertEqual(response.status_code, 200)

    def test_uses_custom_blocked_hosts(self):
        custom_blocked = {"custom.blocked.host"}
        with self.assertRaises(ValueError) as ctx:
            safe_request(
                "http://custom.blocked.host/api",
                validate_url_security=True,
                blocked_hosts=custom_blocked,
            )
        self.assertIn("Invalid or blocked URL", str(ctx.exception))

    @patch("clipped.utils.requests.create_session")
    def test_custom_blocked_hosts_overrides_defaults(self, mock_create_session):
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_session.request.return_value = mock_response
        mock_create_session.return_value = mock_session

        # localhost is in defaults but not in custom, so should be allowed
        custom_blocked = {"only.this.host"}
        response = safe_request(
            "http://localhost/api",
            validate_url_security=True,
            blocked_hosts=custom_blocked,
            blocked_prefixes=(),  # Empty tuple to not block private ranges
        )

        mock_session.request.assert_called_once()

    def test_uses_custom_blocked_prefixes(self):
        custom_prefixes = ("99.",)
        with self.assertRaises(ValueError) as ctx:
            safe_request(
                "http://99.0.0.1/api",
                validate_url_security=True,
                blocked_prefixes=custom_prefixes,
            )
        self.assertIn("Invalid or blocked URL", str(ctx.exception))


class TestSafeRequestExecution(TestCase):
    @patch("clipped.utils.requests.create_session")
    def test_makes_get_request_by_default(self, mock_create_session):
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_session.request.return_value = mock_response
        mock_create_session.return_value = mock_session

        safe_request("https://example.com/api")

        mock_session.request.assert_called_once()
        call_kwargs = mock_session.request.call_args
        self.assertEqual(call_kwargs.kwargs["method"], "GET")

    @patch("clipped.utils.requests.create_session")
    def test_makes_post_request_when_json_provided(self, mock_create_session):
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_session.request.return_value = mock_response
        mock_create_session.return_value = mock_session

        safe_request("https://example.com/api", json={"key": "value"})

        call_kwargs = mock_session.request.call_args
        self.assertEqual(call_kwargs.kwargs["method"], "POST")

    @patch("clipped.utils.requests.create_session")
    def test_uses_specified_method(self, mock_create_session):
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_session.request.return_value = mock_response
        mock_create_session.return_value = mock_session

        safe_request("https://example.com/api", method="PUT")

        call_kwargs = mock_session.request.call_args
        self.assertEqual(call_kwargs.kwargs["method"], "PUT")

    @patch("clipped.utils.requests.create_session")
    def test_passes_headers(self, mock_create_session):
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_session.request.return_value = mock_response
        mock_create_session.return_value = mock_session

        safe_request(
            "https://example.com/api", headers={"Authorization": "Bearer token"}
        )

        call_kwargs = mock_session.request.call_args
        self.assertIn("Authorization", call_kwargs.kwargs["headers"])

    @patch("clipped.utils.requests.create_session")
    def test_passes_params(self, mock_create_session):
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_session.request.return_value = mock_response
        mock_create_session.return_value = mock_session

        safe_request("https://example.com/api", params={"q": "search"})

        call_kwargs = mock_session.request.call_args
        self.assertEqual(call_kwargs.kwargs["params"], {"q": "search"})

    @patch("clipped.utils.requests.create_session")
    def test_uses_default_timeout(self, mock_create_session):
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_session.request.return_value = mock_response
        mock_create_session.return_value = mock_session

        safe_request("https://example.com/api")

        call_kwargs = mock_session.request.call_args
        self.assertEqual(call_kwargs.kwargs["timeout"], 30)

    @patch("clipped.utils.requests.create_session")
    def test_uses_custom_timeout(self, mock_create_session):
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_session.request.return_value = mock_response
        mock_create_session.return_value = mock_session

        safe_request("https://example.com/api", timeout=60)

        call_kwargs = mock_session.request.call_args
        self.assertEqual(call_kwargs.kwargs["timeout"], 60)

    @patch("clipped.utils.requests.create_session")
    def test_disables_redirects_by_default(self, mock_create_session):
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_session.request.return_value = mock_response
        mock_create_session.return_value = mock_session

        safe_request("https://example.com/api")

        call_kwargs = mock_session.request.call_args
        self.assertFalse(call_kwargs.kwargs["allow_redirects"])
