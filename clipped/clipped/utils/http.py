from typing import Any, Optional
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse


def clean_verify_ssl(host: str, verify_ssl: Optional[bool] = None):
    if verify_ssl is None and "https" in host:
        return True
    return verify_ssl


def clean_host(host: str):
    return host.rstrip("/")


def absolute_uri(
    url: str, host: Optional[str] = None, protocol: Optional[str] = None
) -> Optional[str]:
    if not url:
        return None

    if not host:
        return url

    host = clean_host(host)

    if "http" in host:
        return urljoin(clean_host(host) + "/", url.lstrip("/"))

    protocol = protocol or "http"
    host = f"{protocol}://{host}"

    return urljoin(clean_host(host) + "/", url.lstrip("/"))


def to_ws_url(url: str) -> Optional[str]:
    if not url:
        return None
    if url.startswith("https://"):
        return "wss://" + url[len("https://") :]
    if url.startswith("http://"):
        return "ws://" + url[len("http://") :]
    return url


def add_notification_referrer_param(
    url: str, provider: str, is_absolute: bool = True
) -> Optional[Any]:
    if not is_absolute:
        url = absolute_uri(url)
    if not url:
        return None
    parsed_url = urlparse(url)
    query = parse_qs(parsed_url.query)
    query["referrer"] = provider
    url_list = list(parsed_url)
    url_list[4] = urlencode(query, doseq=True)
    return urlunparse(url_list)
