from typing import Iterable, Optional
from urllib.parse import urlparse


def validate_url(
    url: str,
    blocked_hosts: Optional[Iterable[str]] = None,
    blocked_prefixes: Optional[Iterable[str]] = None,
) -> bool:
    """
    Validate URL format and optionally check against blocked hosts.

    Args:
        url: URL to validate
        blocked_hosts: Hostnames to block (e.g., {"localhost", "127.0.0.1"})
        blocked_prefixes: Hostname prefixes to block (e.g., ("10.", "192.168."))

    Returns:
        True if URL is valid and not blocked, False otherwise
    """
    if not url.startswith(("http://", "https://")):
        return False
    parsed = urlparse(url)
    if not parsed.hostname:
        return False

    hostname = parsed.hostname
    if blocked_hosts and hostname in blocked_hosts:
        return False

    if blocked_prefixes and any(
        hostname.startswith(prefix) for prefix in blocked_prefixes
    ):
        return False

    return True


URL_FORMAT = "{protocol}://{domain}{path}"
