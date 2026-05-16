import re
from typing import Any, Dict
from urllib.parse import urlparse

from clipped.types.base_url import BaseUrl


class WasbPath(BaseUrl):
    allowed_schemes = ["https", "wasb", "wasbs", "https", "az", "abfs"]

    @classmethod
    def _validate(cls, value: Any):
        if isinstance(value, Dict):
            _value = value.get("container")
            if not _value:
                raise ValueError("Received a wrong bucket definition: %s", value)
            if "://" not in _value:
                _value = "wasbs://{}".format(_value)
            storage_account = value.get("storage_account") or value.get(
                "storageAccount"
            )
            if storage_account:
                _value = "{}@{}".format(_value, storage_account)
            path = value.get("path")
            if path:
                _value = "{}/{}".format(_value, path)
            value = _value
        cls.get_structured_value(value)
        return value

    def to_param(self):
        return str(self)

    @staticmethod
    def get_structured_value(value):
        value = str(value)
        try:
            parsed_url = urlparse(value)
        except Exception as e:
            raise ValueError("Received a wrong url definition: %s" % e)
        if parsed_url.scheme in {"wasb", "wasbs"}:
            match = re.match(
                "([^@]+)@([^.]+)\\.blob\\.core\\.windows\\.net", parsed_url.netloc
            )
            if match is None:
                raise ValueError(
                    "wasbs url must be of the form <container>@<account>.blob.core.windows.net"
                )
            container = match.group(1)
            storage_account = match.group(2)
            path = parsed_url.path
            path = path.strip("/")
        elif parsed_url.scheme == "https":
            match = re.match("([^@]+)\\.blob\\.core\\.windows\\.net", parsed_url.netloc)
            if match is None:
                raise ValueError(
                    "wasbs url must be of the form <container>.blob.core.windows.net"
                )
            storage_account = match.group(1)
            path = parsed_url.path
            path = path.strip("/")
            if "/" not in path:
                # this means path is the container_name
                container, path = path, ""
            else:
                container, path = path.split("/", 1)
        else:
            storage_account = None
            container = parsed_url.netloc
            path = parsed_url.path or ""
            path = path.strip("/")
        return dict(
            container=container, storage_account=storage_account, path=path.strip("/")
        )

    def get_container_path(self) -> str:
        structured = self.get_structured_value(self)
        if structured.get("path"):
            return f"{structured['container']}/{structured['path']}"
        return structured["container"]
