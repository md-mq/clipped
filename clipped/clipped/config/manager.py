from collections.abc import Mapping
import logging
import os
from typing import Any, Dict, Literal, Optional, Type
import yaml

from clipped.config.contexts import get_project_path, get_temp_path
from clipped.config.reader import ConfigReader
from clipped.config.schema import BaseSchemaModel
from clipped.utils.enums import PEnum
from clipped.utils.json import orjson_dumps, orjson_loads
from clipped.utils.paths import check_or_create_path


_logger = logging.getLogger("clipped.config.manager")


class ConfigManager:
    """Base class for managing a configuration file."""

    class Visibility(str, PEnum):
        GLOBAL = "global"
        LOCAL = "local"
        ALL = "all"

    VISIBILITY: Visibility = None
    IN_PROJECT_DIR = False
    CONFIG_PATH: Optional[str] = None
    CONFIG_FILE_NAME: Optional[str] = None
    ALTERNATE_CONFIG_FILE_NAME: Optional[str] = None
    CONFIG: Type[BaseSchemaModel] = None
    PERSIST_FORMAT: Literal["json", "yaml"] = "json"
    _CONFIG_READER: Type[ConfigReader] = ConfigReader
    _LOGGER = _logger
    _PROJECT = ".clipped"
    _PROJECT_PATH: str = None
    _TEMP_PATH: str = None

    @classmethod
    def _get_project_path(cls) -> str:
        if cls._PROJECT_PATH:
            return cls._PROJECT_PATH

        cls._PROJECT_PATH = get_project_path(cls._PROJECT)
        return cls._PROJECT_PATH

    @classmethod
    def _get_temp_path(cls) -> str:
        if cls._TEMP_PATH:
            return cls._TEMP_PATH

        cls._TEMP_PATH = get_temp_path(cls._PROJECT)
        return cls._TEMP_PATH

    @classmethod
    def is_global(cls, visibility: Optional[Visibility] = None) -> bool:
        visibility = visibility or cls.VISIBILITY
        return visibility == cls.Visibility.GLOBAL

    @classmethod
    def is_local(cls, visibility=None) -> bool:
        visibility = visibility or cls.VISIBILITY
        return visibility == cls.Visibility.LOCAL

    @classmethod
    def is_all_visibility(cls, visibility=None) -> bool:
        visibility = visibility or cls.VISIBILITY
        return visibility == cls.Visibility.ALL

    @classmethod
    def get_visibility(cls) -> str:
        if cls.is_all_visibility():
            return (
                cls.Visibility.LOCAL
                if cls.is_locally_initialized()
                else cls.Visibility.GLOBAL
            )
        return cls.VISIBILITY

    @classmethod
    def set_config_path(cls, config_path: Optional[str]):
        cls.CONFIG_PATH = config_path

    @classmethod
    def _create_dir(cls, config_file_path):
        try:
            check_or_create_path(config_file_path, is_dir=False)
        except OSError:
            # Except permission denied and potential race conditions
            # in multi-threaded environments.
            cls._LOGGER.error(
                "Could not create config context directory for file `%s`",
                config_file_path,
            )

    @staticmethod
    def _get_and_check_path(config_path: str) -> Optional[str]:
        if config_path and os.path.isfile(config_path):
            return config_path
        return None

    @classmethod
    def get_local_config_path(cls) -> str:
        # local to this directory
        base_path = os.path.join(".")
        if cls.IN_PROJECT_DIR:
            # Add it to the current ".project" path
            base_path = os.path.join(base_path, cls._PROJECT)
        config_path = os.path.join(base_path, cls.CONFIG_FILE_NAME)
        if cls.ALTERNATE_CONFIG_FILE_NAME and not os.path.isfile(config_path):
            alternate_config_path = os.path.join(
                base_path, cls.ALTERNATE_CONFIG_FILE_NAME
            )
            if os.path.isfile(alternate_config_path):
                config_path = alternate_config_path
        return config_path

    @classmethod
    def check_local_config_path(cls) -> Optional[str]:
        return cls._get_and_check_path(cls.get_local_config_path())

    @classmethod
    def get_global_config_path(cls) -> str:
        if cls.CONFIG_PATH:
            base_path = os.path.join(cls.CONFIG_PATH, cls._PROJECT)
        else:
            base_path = cls._get_project_path()
        config_path = os.path.join(base_path, cls.CONFIG_FILE_NAME)
        if cls.ALTERNATE_CONFIG_FILE_NAME and not os.path.isfile(config_path):
            alternate_config_path = os.path.join(
                base_path, cls.ALTERNATE_CONFIG_FILE_NAME
            )
            if os.path.isfile(alternate_config_path):
                config_path = alternate_config_path
        return config_path

    @classmethod
    def check_global_config_path(cls) -> Optional[str]:
        return cls._get_and_check_path(cls.get_global_config_path())

    @classmethod
    def get_tmp_config_path(cls) -> str:
        base_path = cls._get_temp_path()
        config_path = os.path.join(base_path, cls.CONFIG_FILE_NAME)
        return config_path

    @classmethod
    def get_config_filepath(
        cls, create: bool = True, visibility: Optional[str] = None
    ) -> str:
        config_path = None
        if cls.is_local(visibility):
            config_path = cls.get_local_config_path()
        elif cls.is_global(visibility):
            config_path = cls.get_global_config_path()
        elif cls.is_all_visibility(visibility):
            config_path = cls.check_local_config_path()
            if not config_path:
                config_path = cls.get_global_config_path()

        if create and config_path:
            cls._create_dir(config_path)
        return config_path

    @classmethod
    def init_config(cls, visibility: Optional[str] = None):
        config = cls.get_config()
        cls.set_config(config, init=True, visibility=visibility)

    @classmethod
    def is_locally_initialized(cls) -> Optional[str]:
        return cls.check_local_config_path()

    @classmethod
    def is_initialized(cls) -> Optional[str]:
        return cls._get_and_check_path(cls.get_config_filepath(create=False))

    @classmethod
    def set_config(
        cls, config: Any, init: bool = False, visibility: Optional[str] = None
    ):
        config_filepath = cls.get_config_filepath(visibility=visibility)

        if os.path.isfile(config_filepath) and init:
            cls._LOGGER.debug(
                "%s file already present at %s\n", cls.CONFIG_FILE_NAME, config_filepath
            )
            return

        with open(config_filepath, "w") as config_file:
            if hasattr(config, "to_json"):
                cls._LOGGER.debug(
                    "Setting %s in the file %s\n",
                    config.to_dict(),
                    cls.CONFIG_FILE_NAME,
                )
                if cls.PERSIST_FORMAT == "yaml" and hasattr(config, "to_yaml"):
                    config_file.write(config.to_yaml())
                else:
                    config_file.write(config.to_json())
            elif hasattr(config, "to_dict"):
                cls._LOGGER.debug(
                    "Setting %s in the file %s\n",
                    config.to_dict(),
                    cls.CONFIG_FILE_NAME,
                )
                dict_config = config.to_dict()
                if cls.PERSIST_FORMAT == "yaml":
                    config_file.write(
                        yaml.safe_dump(dict_config, sort_keys=True, indent=2)
                    )
                else:
                    config_file.write(dict_config)
            elif isinstance(config, Mapping):
                if cls.PERSIST_FORMAT == "yaml":
                    config_file.write(yaml.safe_dump(config, sort_keys=True, indent=2))
                else:
                    config_file.write(orjson_dumps(config))
            else:
                cls._LOGGER.debug(
                    "Setting %s in the file %s\n", config, cls.CONFIG_FILE_NAME
                )
                config_file.write(config)

    @classmethod
    def get_config(cls, check: bool = True) -> Optional[Any]:
        if check and not cls.is_initialized():
            return None

        config_filepath = cls.get_config_filepath()
        cls._LOGGER.debug(
            "Reading config `%s` from path: %s\n", cls.__name__, config_filepath
        )
        return cls.read_from_path(config_filepath)

    @classmethod
    def read_from_path(cls, config_filepath: str) -> Optional[Any]:
        if issubclass(cls.CONFIG, BaseSchemaModel):
            return cls.CONFIG.read(config_filepath)
        with open(config_filepath, "r") as config_file:
            config_str = config_file.read()
        return cls.CONFIG(**orjson_loads(config_str))

    @classmethod
    def get_config_defaults(cls) -> Dict:
        return {}

    @classmethod
    def get_config_or_default(cls) -> Any:
        if not cls.is_initialized():
            return cls.CONFIG(**cls.get_config_defaults())  # pylint:disable=not-callable

        return cls.get_config(check=False)

    @classmethod
    def get_config_from_env(cls, **kwargs) -> Any:
        raise NotImplementedError

    @classmethod
    def get_value(cls, key) -> Optional[Any]:
        config = cls.get_config()
        if config:
            if hasattr(config, key):
                return getattr(config, key)
            else:
                cls._LOGGER.warning(
                    "Config `%s` has no key `%s`", cls.CONFIG.__name__, key
                )

        return None

    @classmethod
    def purge(cls, visibility: Optional[str] = None):
        def _purge():
            if config_filepath and os.path.isfile(config_filepath):
                os.remove(config_filepath)

        if cls.is_all_visibility():
            if visibility:
                config_filepath = cls.get_config_filepath(
                    create=False, visibility=visibility
                )
                _purge()
            else:
                config_filepath = cls.get_config_filepath(
                    create=False, visibility=cls.Visibility.LOCAL
                )
                _purge()
                config_filepath = cls.get_config_filepath(
                    create=False, visibility=cls.Visibility.GLOBAL
                )
                _purge()
        else:
            config_filepath = cls.get_config_filepath(create=False)
            _purge()
