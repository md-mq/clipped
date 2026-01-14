from typing import Dict, Optional, Set, Tuple

try:
    import requests
except ImportError:
    raise ImportError("This module depends on requests.")

from clipped.utils.urls import validate_url

# Default SSRF protection lists
DEFAULT_BLOCKED_HOSTS: Set[str] = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "169.254.169.254",  # AWS metadata
    "metadata.google.internal",  # GCP metadata
}
DEFAULT_BLOCKED_PREFIXES: Tuple[str, ...] = (
    "10.",
    "172.16.",
    "192.168.",
)  # Private IP ranges


def create_session(
    session: Optional[requests.Session] = None,
    session_attrs: Optional[Dict] = None,
) -> requests.Session:
    session = session or requests.Session()
    if not session_attrs:
        return session
    if "proxies" in session_attrs:
        session.proxies = session_attrs.pop("proxies")
    elif "proxy" in session_attrs:
        session.proxies = session_attrs.pop("proxy")
    if "stream" in session_attrs:
        session.stream = session_attrs.pop("stream")
    if "verify" in session_attrs or "verify_ssl" in session_attrs:
        session.verify = session_attrs.pop(
            "verify", session_attrs.pop("verify_ssl", True)
        )
    if "cert" in session_attrs:
        session.cert = session_attrs.pop("cert")
    if "max_redirects" in session_attrs:
        session.max_redirects = session_attrs.pop("max_redirects")
    if "trust_env" in session_attrs:
        session.trust_env = session_attrs.pop("trust_env")

    return session


def safe_request(
    url: str,
    method: str = None,
    params: Optional[Dict] = None,
    data: Optional[Dict] = None,
    json: Optional[Dict] = None,
    headers: Optional[Dict] = None,
    allow_redirects: bool = False,
    timeout: int = 30,
    verify_ssl: bool = True,
    session: Optional[requests.Session] = None,
    session_attrs: Optional[Dict] = None,
    validate_url_security: bool = False,
    blocked_hosts: Optional[Set[str]] = None,
    blocked_prefixes: Optional[Tuple[str, ...]] = None,
) -> requests.Response:
    """A slightly safer version of `request`.

    Args:
        validate_url_security: If True, validates URL against SSRF attacks.
        blocked_hosts: Set of blocked hostnames. Uses DEFAULT_BLOCKED_HOSTS if None
            and validate_url_security is True.
        blocked_prefixes: Tuple of blocked IP prefixes. Uses DEFAULT_BLOCKED_PREFIXES
            if None and validate_url_security is True.
    """
    if validate_url_security:
        hosts = blocked_hosts if blocked_hosts is not None else DEFAULT_BLOCKED_HOSTS
        prefixes = (
            blocked_prefixes
            if blocked_prefixes is not None
            else DEFAULT_BLOCKED_PREFIXES
        )
        if not validate_url(url, blocked_hosts=hosts, blocked_prefixes=prefixes):
            raise ValueError(f"Invalid or blocked URL: {url}")

    session = create_session(session, session_attrs)

    kwargs = {}

    if json:
        kwargs["json"] = json
        if not headers:
            headers = {}
        headers.setdefault("Content-Type", "application/json")

    if data:
        kwargs["data"] = data

    if params:
        kwargs["params"] = params

    if headers:
        kwargs["headers"] = headers

    method = method or ("POST" if (data or json) else "GET")

    response = session.request(
        method=method,
        url=url,
        allow_redirects=allow_redirects,
        timeout=timeout,
        verify=verify_ssl,
        **kwargs,
    )

    return response
