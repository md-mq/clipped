from unittest import TestCase

from clipped.utils.http import absolute_uri, to_ws_url


class HttpTest(TestCase):
    def test_absolute_uri_with_empty_url(self):
        assert absolute_uri("") is None

    def test_absolute_uri_with_no_host(self):
        assert absolute_uri("test_url") == "test_url"

    def test_absolute_uri_with_http_in_host(self):
        assert (
            absolute_uri("test_url", "http://test_host") == "http://test_host/test_url"
        )

    def test_absolute_uri_with_no_protocol(self):
        assert absolute_uri("test_url", "test_host") == "http://test_host/test_url"
        assert (
            absolute_uri("test_url", "localhost:8000")
            == "http://localhost:8000/test_url"
        )
        assert absolute_uri("test_url", "foo.bar") == "http://foo.bar/test_url"

    def test_absolute_uri_with_https_protocol(self):
        assert (
            absolute_uri("test_url", "test_host", "https")
            == "https://test_host/test_url"
        )

    def test_absolute_uri_with_none_protocol(self):
        assert (
            absolute_uri("test_url", "test_host", None) == "http://test_host/test_url"
        )

    def test_absolute_uri_with_special_characters_in_url(self):
        assert (
            absolute_uri("test_url/with?special=characters", "test_host")
            == "http://test_host/test_url/with?special=characters"
        )

    def test_to_ws_url(self):
        assert to_ws_url("") is None
        assert to_ws_url("http://host/path") == "ws://host/path"
        assert (
            to_ws_url("https://host/path?replay_bytes=20")
            == "wss://host/path?replay_bytes=20"
        )
        assert to_ws_url("ws://host/path") == "ws://host/path"
        assert to_ws_url("wss://host/path") == "wss://host/path"
