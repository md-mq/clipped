import os
import sys
import yaml

from collections.abc import Mapping
from requests import HTTPError
from typing import Any, Dict
from yaml.parser import ParserError
from yaml.scanner import ScannerError

from clipped.config.exceptions import SchemaError
from clipped.utils.dicts import deep_update
from clipped.utils.json import orjson_loads
from clipped.utils.lists import to_list


class ConfigSpec:
    _SCHEMA_EXCEPTION = SchemaError

    def __init__(
        self, value: Any, config_type: str = None, check_if_exists: bool = True
    ):
        self.value = value
        self.config_type = config_type
        self.check_if_exists = check_if_exists

    @classmethod
    def get_from(cls, value: Any, config_type: str = None) -> "ConfigSpec":
        if isinstance(value, ConfigSpec):
            return value

        return cls(value=value, config_type=config_type)

    def check_type(self):
        type_check = self.config_type is None and not isinstance(
            self.value, (Mapping, str)
        )
        if type_check:
            raise self._SCHEMA_EXCEPTION(
                "Expects Mapping, string, or list of Mapping/string instances, "
                "received {} instead".format(type(self.value))
            )

    def read(self) -> Dict:
        if isinstance(self.value, Mapping):
            return self.value

        # try a python file
        if isinstance(self.value, str) and (
            self.config_type == ".py" or ".py" in self.value
        ):
            _f_path, _f_module = self.get_python_file_def(self.value)
            if _f_path and _f_module:
                return self.read_from_python(_f_path, _f_module)

        if os.path.isfile(self.value):
            return self.read_from_file(self.value, self.config_type)

        # try reading a stream of yaml or json
        if not self.config_type or self.config_type in (".json", ".yml", ".yaml"):
            try:
                return self.read_from_stream(self.value)
            except (ScannerError, ParserError):
                raise self._SCHEMA_EXCEPTION(
                    "Received an invalid yaml stream: `{}`".format(self.value)
                )

        if self.config_type == "url":
            return self.read_from_url(self.value)

        if self.config_type == "hub":
            public_hub = self.get_public_registry()
            if public_hub:
                return self.read_from_public_hub(self.value, public_hub)
            return self.read_from_custom_hub(self.value)

        raise self._SCHEMA_EXCEPTION(
            "Received an invalid configuration: `{}`".format(self.value)
        )

    @classmethod
    def read_from(cls, config_values: Any, config_type: str = None) -> Dict:
        """
        Reads an ordered list of configuration values and
        deep merge the values in reverse order.
        """
        if not config_values:
            raise cls._SCHEMA_EXCEPTION(
                "Cannot read config_value: `{}`".format(config_values)
            )

        config_values = to_list(config_values, check_none=True)

        config = {}
        for config_value in config_values:
            config_value = cls.get_from(value=config_value, config_type=config_type)
            config_value.check_type()
            config_results = config_value.read()
            if config_results and isinstance(config_results, Mapping):
                config = deep_update(config, config_results)
            elif config_value.check_if_exists:
                raise cls._SCHEMA_EXCEPTION(
                    "Cannot read config_value: `{}`".format(config_value.value)
                )

        return config

    @classmethod
    def read_from_url(cls, url: str) -> Dict:
        from clipped.utils.requests import safe_request

        resp = safe_request(url)
        resp.raise_for_status()
        return cls.read_from_stream(resp.content.decode())

    @classmethod
    def get_public_registry(cls) -> str:
        return ""

    @classmethod
    def read_from_public_hub(cls, hub: str, public_hub: str) -> Dict:
        hub_values = hub.split(":")
        if len(hub_values) > 2:
            raise cls._SCHEMA_EXCEPTION(
                "Received an invalid hub reference: `{}`".format(hub)
            )
        if len(hub_values) == 2:
            hub_name, version = hub_values
        else:
            hub_name, version = hub_values[0], "latest"
        version = version or "latest"
        url = "{}/{}/{}.yaml".format(public_hub, hub_name, version)
        try:
            return cls.read_from_url(url)
        except HTTPError as e:
            if e.response.status_code == 404:
                raise cls._SCHEMA_EXCEPTION(
                    "Config `{}` was not found, "
                    "please check that the name and tag are valid".format(hub)
                )
            raise cls._SCHEMA_EXCEPTION(
                "Config `{}` could not be fetched, an error was encountered {}".format(
                    hub, e
                )
            )

    @classmethod
    def read_from_custom_hub(cls, hub: str) -> Dict:
        raise cls._SCHEMA_EXCEPTION(
            "Config `{}` could not be loaded, "
            "please set a valid registry to load the configs from".format(hub)
        )

    @classmethod
    def read_from_stream(cls, stream) -> Dict:
        results = cls.read_from_yml(stream, is_stream=True)
        if not results:
            results = cls.read_from_json(stream, is_stream=True)
        return results

    @classmethod
    def get_python_file_def(cls, f_path):
        if not isinstance(f_path, str) or ".py" not in f_path:
            return None, None
        results = f_path.split(":")

        if len(results) == 1:  # Default case
            return f_path, "main"

        if len(results) != 2 or not results[1]:
            return None, None

        _f_path = results[0].strip("")
        _module_name = results[1].strip("")
        if not os.path.exists(_f_path):
            raise cls._SCHEMA_EXCEPTION(
                "Received non existing python file: `{}`".format(f_path)
            )
        if not _module_name:
            raise cls._SCHEMA_EXCEPTION(
                "Received an invalid python module: `{}`".format(f_path)
            )
        return _f_path, _module_name

    @classmethod
    def import_py_module(cls, f_path, f_module):
        import importlib.util

        spec = importlib.util.spec_from_file_location(f_module, f_path)
        if sys.modules.get(spec.name) and sys.modules[
            spec.name
        ].__file__ == os.path.abspath(spec.origin):
            module = sys.modules[spec.name]
        else:
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
        return module

    @classmethod
    def read_from_python(cls, f_path, f_module):
        f_path = os.path.abspath(f_path)
        file_directory = os.path.dirname(f_path)
        if file_directory not in sys.path:
            sys.path.append(file_directory)

        module_name = os.path.splitext(os.path.basename(f_path))[0]
        module = cls.import_py_module(f_path, module_name)
        return getattr(module, f_module)

    @classmethod
    def read_from_file(cls, f_path, file_type):
        _, ext = os.path.splitext(f_path)
        if ext in (".yml", ".yaml") or file_type in (None, ".yml", ".yaml"):
            return cls.read_from_yml(f_path)
        elif ext == ".json" or file_type == ".json":
            return cls.read_from_json(f_path)
        elif ext == ".py" or file_type == ".py":
            _f_path, _f_module = cls.get_python_file_def(f_path)
            if _f_path and _f_module:
                return cls.read_from_python(_f_path, _f_module)
        raise cls._SCHEMA_EXCEPTION(
            "Expects a file with extension: `.yml`, `.yaml`, `.py`, or `json`, "
            "received instead `{}`".format(ext)
        )

    @classmethod
    def read_from_yml(cls, f_path, is_stream=False):
        try:
            if is_stream:
                return yaml.safe_load(f_path)
            with open(f_path) as f:
                return yaml.safe_load(f)
        except (ScannerError, ParserError) as e:
            raise cls._SCHEMA_EXCEPTION(
                "Received non valid yaml: `%s`.\nYaml error %s" % (f_path, e)
            ) from e

    @classmethod
    def read_from_json(cls, f_path, is_stream=False):
        if is_stream:
            try:
                return orjson_loads(f_path)
            except ValueError as e:
                raise cls._SCHEMA_EXCEPTION("Json error: %s" % e) from e
        try:
            with open(f_path) as f:
                return orjson_loads(f.read())
        except ValueError as e:
            raise cls._SCHEMA_EXCEPTION(
                "Received non valid json: `%s`.\nJson error %s" % (f_path, e)
            ) from e
