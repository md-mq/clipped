from typing import Dict, Optional


def get_query_params(
    limit: Optional[int] = None,
    offset: Optional[int] = None,
    query: Optional[str] = None,
    sort: Optional[str] = None,
) -> Dict:
    params = {}
    if limit:
        params["limit"] = limit
    if offset:
        params["offset"] = offset
    if query:
        params["query"] = query
    if sort:
        params["sort"] = sort

    return params


def get_logs_params(
    last_time: Optional[str] = None,
    last_file: Optional[str] = None,
    connection: Optional[str] = None,
    kind: Optional[str] = None,
) -> Dict:
    params = {}
    if kind:
        params["kind"] = kind
    if last_file:
        params["last_file"] = last_file
    if last_time:
        params["last_time"] = last_time
    if connection:
        params["connection"] = connection

    return params


def get_streams_params(
    connection: Optional[str] = None,
    status: Optional[str] = None,
    force: Optional[bool] = None,
) -> Dict:
    params = {}
    if connection:
        params["connection"] = connection
    if status:
        params["status"] = status
    if force:
        params["force"] = True

    return params
