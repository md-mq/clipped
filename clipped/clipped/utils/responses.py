from typing import Any, Dict
import urllib.parse as urlparse
from urllib.parse import parse_qs


def get_meta_response(response: Any):
    def get_pagination(url: str) -> str:
        parsed = urlparse.urlparse(url)
        parsed_query: Dict[str, list] = parse_qs(parsed.query)
        limit = parsed_query.get("limit")
        offset = parsed_query.get("offset")
        res = []
        if limit is not None:
            res.append("--limit={}".format(limit[0]))
        if offset is not None:
            res.append("--offset={}".format(offset[0]))
        return " ".join(res)

    results = {}
    if response.next:
        try:
            results["next"] = get_pagination(response.next)
        except Exception:  # noqa
            results["next"] = response.next
    if response.previous:
        try:
            results["previous"] = get_pagination(response.previous)
        except Exception:  # noqa
            results["previous"] = response.previous
    if response.count:
        results["count"] = response.count
    return results
