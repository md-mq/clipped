from unittest import TestCase

from clipped.utils.urls import validate_url


class TestValidateUrl(TestCase):
    # Valid URL tests
    def test_valid_https_url(self):
        self.assertTrue(validate_url("https://example.com"))
        self.assertTrue(validate_url("https://example.com/path"))
        self.assertTrue(validate_url("https://example.com/path?query=value"))
        self.assertTrue(validate_url("https://api.example.com/v1/endpoint"))

    def test_valid_http_url(self):
        self.assertTrue(validate_url("http://example.com"))
        self.assertTrue(validate_url("http://example.com/webhook"))

    def test_valid_url_with_port(self):
        self.assertTrue(validate_url("https://example.com:8080/api"))
        self.assertTrue(validate_url("http://example.com:3000"))

    def test_valid_url_with_subdomain(self):
        self.assertTrue(validate_url("https://api.example.com"))
        self.assertTrue(validate_url("https://hooks.slack.com/services/xxx"))

    # Invalid URL tests
    def test_rejects_ftp_scheme(self):
        self.assertFalse(validate_url("ftp://example.com/file"))

    def test_rejects_file_scheme(self):
        self.assertFalse(validate_url("file:///etc/passwd"))

    def test_rejects_javascript_scheme(self):
        self.assertFalse(validate_url("javascript:alert(1)"))

    def test_rejects_data_scheme(self):
        self.assertFalse(validate_url("data:text/html,<script>alert(1)</script>"))

    def test_rejects_missing_scheme(self):
        self.assertFalse(validate_url("example.com"))
        self.assertFalse(validate_url("//example.com"))

    def test_rejects_empty_url(self):
        self.assertFalse(validate_url(""))

    def test_rejects_url_without_hostname(self):
        self.assertFalse(validate_url("http://"))
        self.assertFalse(validate_url("https://"))

    # Blocked hosts tests
    def test_blocks_specified_hosts(self):
        blocked = {"blocked.com", "evil.com"}
        self.assertFalse(validate_url("https://blocked.com/api", blocked_hosts=blocked))
        self.assertFalse(validate_url("https://evil.com/api", blocked_hosts=blocked))

    def test_allows_non_blocked_hosts(self):
        blocked = {"blocked.com"}
        self.assertTrue(validate_url("https://allowed.com/api", blocked_hosts=blocked))

    def test_blocks_localhost(self):
        blocked = {"localhost"}
        self.assertFalse(validate_url("http://localhost/api", blocked_hosts=blocked))
        self.assertFalse(
            validate_url("http://localhost:8080/api", blocked_hosts=blocked)
        )

    def test_blocks_loopback_ip(self):
        blocked = {"127.0.0.1"}
        self.assertFalse(validate_url("http://127.0.0.1/api", blocked_hosts=blocked))

    def test_blocks_aws_metadata(self):
        blocked = {"169.254.169.254"}
        self.assertFalse(
            validate_url(
                "http://169.254.169.254/latest/meta-data", blocked_hosts=blocked
            )
        )

    def test_blocks_gcp_metadata(self):
        blocked = {"metadata.google.internal"}
        self.assertFalse(
            validate_url(
                "http://metadata.google.internal/computeMetadata/v1/",
                blocked_hosts=blocked,
            )
        )

    # Blocked prefixes tests
    def test_blocks_specified_prefixes(self):
        prefixes = ("10.", "192.168.")
        self.assertFalse(validate_url("http://10.0.0.1/api", blocked_prefixes=prefixes))
        self.assertFalse(
            validate_url("http://10.255.255.255/api", blocked_prefixes=prefixes)
        )
        self.assertFalse(
            validate_url("http://192.168.1.1/api", blocked_prefixes=prefixes)
        )

    def test_blocks_172_16_range(self):
        prefixes = ("172.16.", "172.17.", "172.18.", "172.19.", "172.20.")
        self.assertFalse(
            validate_url("http://172.16.0.1/api", blocked_prefixes=prefixes)
        )
        self.assertFalse(
            validate_url("http://172.17.0.1/api", blocked_prefixes=prefixes)
        )

    def test_allows_non_blocked_prefixes(self):
        prefixes = ("10.", "192.168.")
        self.assertTrue(validate_url("https://8.8.8.8/api", blocked_prefixes=prefixes))
        self.assertTrue(
            validate_url("https://172.217.0.1/api", blocked_prefixes=prefixes)
        )

    # Combined blocked hosts and prefixes
    def test_blocks_with_both_hosts_and_prefixes(self):
        blocked_hosts = {"localhost", "127.0.0.1"}
        blocked_prefixes = ("10.", "192.168.")

        self.assertFalse(
            validate_url(
                "http://localhost/api",
                blocked_hosts=blocked_hosts,
                blocked_prefixes=blocked_prefixes,
            )
        )
        self.assertFalse(
            validate_url(
                "http://10.0.0.1/api",
                blocked_hosts=blocked_hosts,
                blocked_prefixes=blocked_prefixes,
            )
        )
        self.assertTrue(
            validate_url(
                "https://example.com/api",
                blocked_hosts=blocked_hosts,
                blocked_prefixes=blocked_prefixes,
            )
        )

    # Edge cases
    def test_empty_blocked_hosts_allows_all(self):
        self.assertTrue(validate_url("http://localhost/api", blocked_hosts=set()))

    def test_empty_blocked_prefixes_allows_all(self):
        self.assertTrue(validate_url("http://10.0.0.1/api", blocked_prefixes=()))

    def test_none_blocked_hosts_allows_all(self):
        self.assertTrue(validate_url("http://localhost/api", blocked_hosts=None))

    def test_none_blocked_prefixes_allows_all(self):
        self.assertTrue(validate_url("http://10.0.0.1/api", blocked_prefixes=None))

    def test_blocked_hosts_accepts_list(self):
        blocked = ["localhost", "127.0.0.1"]
        self.assertFalse(validate_url("http://localhost/api", blocked_hosts=blocked))

    def test_blocked_prefixes_accepts_list(self):
        prefixes = ["10.", "192.168."]
        self.assertFalse(validate_url("http://10.0.0.1/api", blocked_prefixes=prefixes))

    def test_case_sensitive_hostname_matching(self):
        blocked = {"LOCALHOST"}
        # URL parsing lowercases hostnames, so this should not match
        self.assertTrue(validate_url("http://localhost/api", blocked_hosts=blocked))

    def test_blocked_host_with_different_path(self):
        blocked = {"blocked.com"}
        self.assertFalse(validate_url("https://blocked.com/", blocked_hosts=blocked))
        self.assertFalse(
            validate_url("https://blocked.com/any/path", blocked_hosts=blocked)
        )
        self.assertFalse(
            validate_url("https://blocked.com/path?query=1", blocked_hosts=blocked)
        )
