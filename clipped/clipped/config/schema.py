import functools
import os
import pprint
import yaml

from collections.abc import Mapping
from typing import Any, ClassVar, Dict, List, Optional, Set, Type, Union

from clipped.compact.pydantic import BaseModel, PydanticAllowConfig, PydanticConfig
from clipped.compact.pydantic import RootModel as BaseRootModel
from clipped.compact.pydantic import create_model
from clipped.config.exceptions import SchemaError
from clipped.config.patch_strategy import PatchStrategy
from clipped.config.spec import ConfigSpec
from clipped.utils.dicts import deep_update
from clipped.utils.humanize import humanize_timesince
from clipped.utils.json import orjson_dumps
from clipped.utils.strings import to_camel_case
from clipped.utils.units import to_percentage, to_unit_memory


class BaseSchemaMixin:
    _IDENTIFIER: ClassVar[str] = None
    _DEFAULT_INCLUDE_ATTRIBUTES: ClassVar = []
    _DEFAULT_EXCLUDE_ATTRIBUTES: ClassVar = []
    _DATETIME_ATTRIBUTES: ClassVar = []
    _MEM_SIZE_ATTRIBUTES: ClassVar = []
    _PERCENT_ATTRIBUTES: ClassVar = []
    _ROUNDING: ClassVar = 2
    _WRITE_MODE: ClassVar = 0o777
    _FIELDS_MANUAL_PATCH: ClassVar = []
    _FIELDS_SAME_KIND_PATCH: ClassVar = []
    _FIELDS_DICT_PATCH: ClassVar = []
    _CUSTOM_DUMP_FIELDS: ClassVar = []
    _SWAGGER_FIELDS: ClassVar = []
    _SWAGGER_FIELDS_LISTS: ClassVar = ["tolerations", "host_aliases", "hostAliases"]
    _PARTIAL: ClassVar = False
    _VERSION: ClassVar = None
    _CONFIG_SPEC: ClassVar = ConfigSpec
    _SCHEMA_EXCEPTION: ClassVar = SchemaError
    _USE_DISCRIMINATOR: ClassVar = False

    @classmethod
    def get_model_fields(cls):
        # For pydantic v1/v2
        if isinstance(cls.model_fields, Mapping):
            return cls.model_fields
        elif hasattr(cls, "__fields__"):
            return cls.__fields__
        return {}

    @classmethod
    def get_aliases(cls):
        items = cls.get_model_fields()
        return {
            field_name: field_info.alias for field_name, field_info in items.items()
        }

    @classmethod
    def get_field_name(cls, field):
        return field.alias if hasattr(field, "alias") else field.field_name

    @classmethod
    def get_alias_for_field(cls, field):
        key = cls.get_field_name(field)
        return cls.get_aliases().get(key)

    @classmethod
    def get_value_for_key(cls, key, obj):
        if isinstance(obj, dict):
            return obj.get(key)
        return getattr(obj, key, None)

    @classmethod
    def get_data_from_values(cls, values):
        if hasattr(values, "data"):  # Pydantic v2
            return values.data
        return values

    @classmethod
    def get_identifier(cls):
        return cls._IDENTIFIER

    def to_light_dict(
        self,
        humanize_values: bool = False,
        include_attrs: List[str] = None,
        exclude_attrs: List[str] = None,
    ) -> Dict[str, Any]:
        obj_dict = self.to_dict(humanize_values=humanize_values)
        if all([include_attrs, exclude_attrs]):
            raise self._SCHEMA_EXCEPTION(
                "Only one value `include_attrs` or `exclude_attrs` is allowed."
            )
        if not any([include_attrs, exclude_attrs]):  # Use Default setup attrs
            include_attrs = self._DEFAULT_INCLUDE_ATTRIBUTES
            exclude_attrs = self._DEFAULT_EXCLUDE_ATTRIBUTES

        if include_attrs:
            exclude_attrs = set(obj_dict.keys()) - set(include_attrs)
        for attr in exclude_attrs:
            obj_dict.pop(attr, None)
        return obj_dict

    def to_dict(
        self,
        humanize_values: bool = False,
        include_kind: bool = False,
        include_version: bool = False,
        exclude_unset: bool = True,
        exclude_none: bool = True,
        exclude_defaults: bool = False,
    ) -> Dict[str, Any]:
        obj = self.obj_to_dict(
            self,
            humanize_values=humanize_values,
            include_kind=include_kind,
            include_version=include_version,
            exclude_unset=exclude_unset,
            exclude_none=exclude_none,
            exclude_defaults=exclude_defaults,
        )
        return obj

    def to_yaml(
        self,
        humanize_values: bool = False,
        include_kind: bool = False,
        include_version: bool = False,
        exclude_unset: bool = True,
        exclude_none: bool = True,
        exclude_defaults: bool = False,
    ):
        obj = self.to_dict(
            humanize_values=humanize_values,
            include_kind=include_kind,
            include_version=include_version,
            exclude_unset=exclude_unset,
            exclude_none=exclude_none,
            exclude_defaults=exclude_defaults,
        )
        return yaml.safe_dump(obj, sort_keys=True, indent=2)

    def to_json(
        self,
        humanize_values: bool = False,
        include_kind: bool = False,
        include_version: bool = False,
        exclude_unset: bool = True,
        exclude_none: bool = True,
        exclude_defaults: bool = False,
    ) -> str:
        obj = self.to_dict(
            humanize_values=humanize_values,
            include_kind=include_kind,
            include_version=include_version,
            exclude_unset=exclude_unset,
            exclude_none=exclude_none,
            exclude_defaults=exclude_defaults,
        )
        return orjson_dumps(obj)

    def to_str(self) -> str:
        model_dump_fct = self.model_dump if hasattr(self, "model_dump") else self.dict
        return pprint.pformat(model_dump_fct(by_alias=True))

    def to_schema(self) -> Dict:
        return self.obj_to_schema(self)

    @classmethod
    def humanize_attrs(cls, obj) -> Dict:
        humanized_attrs = {}
        for attr in cls._DATETIME_ATTRIBUTES:
            humanized_attrs[attr] = humanize_timesince(getattr(obj, attr))
        for attr in cls._PERCENT_ATTRIBUTES:
            humanized_attrs[attr] = to_percentage(getattr(obj, attr), cls._ROUNDING)
        for attr in cls._MEM_SIZE_ATTRIBUTES:
            humanized_attrs[attr] = to_unit_memory(getattr(obj, attr))
        return humanized_attrs

    @staticmethod
    def swagger_to_dict(fdata: Any) -> Union[Dict, List[Dict]]:
        def _field_to_dict(fvalue: Any):
            if hasattr(fvalue, "to_dict"):
                fvalue = fvalue.to_dict()
                keys = set(fvalue.keys())
                for k in keys:
                    if fvalue[k] is None:
                        del fvalue[k]
                return {to_camel_case(k): fvalue[k] for k in fvalue}
            return fvalue

        if not fdata:
            return fdata
        elif fdata and isinstance(fdata, list):
            return [_field_to_dict(v) for v in fdata]
        else:
            return _field_to_dict(fdata)

    def _dump_obj(self, data: Dict) -> Dict:
        # Handle swagger fields and perform `to_dict`
        for field in self._SWAGGER_FIELDS:
            if field in data:
                data[field] = self.swagger_to_dict(data[field])
        return data

    @classmethod
    def obj_to_dict(
        cls,
        obj: "BaseSchemaModel",
        humanize_values: bool = False,
        include_kind: bool = False,
        include_version: bool = False,
        exclude_unset: bool = True,
        exclude_none: bool = True,
        exclude_defaults: bool = False,
    ) -> Dict:
        humanized_attrs = cls.humanize_attrs(obj) if humanize_values else {}
        model_dump_fct = obj.model_dump if hasattr(obj, "model_dump") else obj.dict
        data_dict = model_dump_fct(
            by_alias=True,
            exclude_unset=exclude_unset,
            exclude_defaults=exclude_defaults,
            exclude_none=exclude_none,
        )
        # Handle custom fields
        for field in cls._CUSTOM_DUMP_FIELDS:
            _field = getattr(obj, field, None)
            if _field:
                if isinstance(_field, list):
                    data_dict.update({field: [f.obj_to_dict(f) for f in _field]})
                elif isinstance(_field, Mapping):
                    data_dict.update(
                        {field: {k: v.obj_to_dict(v) for k, v in _field.items()}}
                    )
                else:
                    data_dict.update({field: _field.obj_to_dict(_field)})

        if include_kind and "kind" not in data_dict and hasattr(obj, "kind"):
            data_dict["kind"] = (
                obj._IDENTIFIER.value
                if hasattr(obj._IDENTIFIER, "value")
                else obj._IDENTIFIER
            )

        if include_version and "version" not in data_dict:
            data_dict["version"] = cls._VERSION

        for k, v in humanized_attrs.items():
            data_dict[k] = v
        return data_dict

    @classmethod
    def obj_to_schema(cls, obj: "BaseSchemaModel") -> Dict:
        return {cls._IDENTIFIER: cls.obj_to_dict(obj)}

    @classmethod
    def from_dict(cls, value: Any, partial: bool = False) -> "BaseSchemaModel":
        model_validate_fct = (
            cls.model_validate if hasattr(cls, "model_validate") else cls.parse_obj
        )
        return model_validate_fct(value)

    @classmethod
    def read(
        cls, values: Any, partial: bool = False, config_type: str = None
    ) -> "BaseSchemaModel":
        values = cls._CONFIG_SPEC.read_from(values, config_type=config_type)
        return cls.from_dict(values, partial=partial)

    @classmethod
    def init_file(cls, filepath: str, config: Optional["BaseSchemaModel"] = None):
        if not os.path.exists(filepath):
            cls.write(config or cls(), filepath=filepath, mode=cls._WRITE_MODE)

    def write(self, filepath: str, mode: Optional[int] = None):
        with open(filepath, "w") as config_file:
            config_file.write(self.to_json())
            if mode is not None:
                os.chmod(filepath, mode)

    def clone(self):
        return self.from_dict(self.to_dict())

    @staticmethod
    def patch_normal_merge(
        current_value: Any, value: Any, strategy: Optional[PatchStrategy] = None
    ) -> Any:
        strategy = strategy or PatchStrategy.POST_MERGE

        if isinstance(current_value, dict):
            if PatchStrategy.is_post_merge(strategy):
                return deep_update(current_value, value)
            elif PatchStrategy.is_pre_merge(strategy):
                return deep_update(value, current_value)
        elif isinstance(current_value, list):
            if PatchStrategy.is_post_merge(strategy):
                return current_value + [i for i in value if i not in current_value]
            elif PatchStrategy.is_pre_merge(strategy):
                return value + [i for i in current_value if i not in value]
        elif isinstance(current_value, BaseSchemaModel):
            return current_value.patch(value, strategy=strategy)
        elif hasattr(current_value, "to_dict"):
            if PatchStrategy.is_post_merge(strategy):
                return deep_update(current_value.to_dict(), value.to_dict())
            elif PatchStrategy.is_pre_merge(strategy):
                return deep_update(value.to_dict(), current_value.to_dict())
        else:
            if PatchStrategy.is_post_merge(strategy):
                return value
            elif PatchStrategy.is_pre_merge(strategy):
                return current_value

    @classmethod
    def patch_swagger_field(
        cls,
        config: "BaseSchemaModel",
        values: Dict,
        strategy: Optional[PatchStrategy] = None,
    ):
        strategy = strategy or PatchStrategy.POST_MERGE

        openapi_types = getattr(config, "openapi_types", {})
        for key in openapi_types:
            value = getattr(values, key, None)
            if value is None:
                continue

            current_value = getattr(config, key, None)
            if current_value is None:
                setattr(
                    config, key, value
                )  # handles also PatchStrategy.ISNULL implicitly
                continue

            if PatchStrategy.is_null(strategy):
                continue
            if PatchStrategy.is_replace(strategy):
                setattr(config, key, value)
                continue

            setattr(config, key, cls.patch_normal_merge(current_value, value, strategy))

    @classmethod
    def patch_swagger_field_list(
        cls, current_value: Any, value: any, strategy: Optional[PatchStrategy] = None
    ) -> Any:
        strategy = strategy or PatchStrategy.POST_MERGE

        if PatchStrategy.is_null(strategy):
            return current_value
        if PatchStrategy.is_replace(strategy):
            return value

        return cls.patch_normal_merge(current_value, value, strategy)

    @classmethod
    def patch_obj(
        cls,
        config: Union[Dict, "BaseSchemaModel"],
        values: Union[Dict, "BaseSchemaModel"],
        strategy: Optional[PatchStrategy] = None,
    ):
        strategy = strategy or PatchStrategy.POST_MERGE

        for key in config.model_fields.keys():
            if key in cls._FIELDS_MANUAL_PATCH:
                continue

            value = getattr(values, key, None)
            if value is None:
                should_continue = True
                if isinstance(values, Mapping) and key in values:
                    should_continue = False
                elif (
                    isinstance(values, BaseSchemaModel)
                    and key in values.model_fields_set
                ):
                    should_continue = False

                if should_continue:
                    continue

            current_value = getattr(config, key, None)
            if current_value is None:
                setattr(
                    config, key, value
                )  # handles also PatchStrategy.ISNULL implicitly
                continue

            if (
                isinstance(current_value, BaseSchemaModel)
                and key not in cls._FIELDS_SAME_KIND_PATCH
            ):
                current_value.patch(value, strategy=strategy)
                continue

            if isinstance(current_value, Mapping) and key in cls._FIELDS_DICT_PATCH:
                for k, v in current_value.items():
                    v.patch(value.get(k, {}), strategy=strategy)
                continue
            if not isinstance(current_value, BaseSchemaModel) and (
                hasattr(current_value, "openapi_types") or key in cls._SWAGGER_FIELDS
            ):
                if key in cls._SWAGGER_FIELDS_LISTS:  # Special case for lists
                    setattr(
                        config,
                        key,
                        cls.patch_swagger_field_list(current_value, value, strategy),
                    )
                else:
                    cls.patch_swagger_field(current_value, value, strategy)
                continue

            if PatchStrategy.is_null(strategy):
                continue
            if PatchStrategy.is_replace(strategy):
                setattr(config, key, value)
                continue

            # We only handle merge strategies
            def normal_merge():
                setattr(
                    config, key, cls.patch_normal_merge(current_value, value, strategy)
                )

            def same_kind_merge():
                # If the same kind resume merge patch using base logic
                if value and current_value.kind == value.kind:
                    normal_merge()
                # Not same kind use post/pre replace
                else:
                    if PatchStrategy.is_post_merge(strategy):
                        setattr(config, key, value)
                    elif PatchStrategy.is_pre_merge(strategy):
                        setattr(config, key, current_value)

            if key in cls._FIELDS_SAME_KIND_PATCH or value is None:
                same_kind_merge()
            else:
                normal_merge()

        return config

    def patch(
        self,
        values: Union[Dict, "BaseSchemaModel"],
        strategy: Optional[PatchStrategy] = None,
    ):
        strategy = strategy or PatchStrategy.POST_MERGE
        return self.patch_obj(self, values, strategy)

    @classmethod
    def get_keys_and_aliases(cls) -> Dict[str, str]:
        return {key: field.alias for key, field in cls.model_fields.items()}

    @classmethod
    def get_all_possible_keys(cls) -> Set[str]:
        keys_and_aliases = cls.get_keys_and_aliases()
        all_keys = {key for key, value in keys_and_aliases.items()}
        all_aliases = {value for key, value in keys_and_aliases.items()}
        return all_keys | all_aliases


class BaseSchemaModel(BaseModel, BaseSchemaMixin):
    class Config(PydanticConfig):
        pass


class RootModel(BaseRootModel, BaseSchemaMixin):
    pass


class BaseAllowSchemaModel(BaseSchemaModel):
    class Config(PydanticAllowConfig):
        pass


def base_schema(cls, new_cls: Type[BaseSchemaModel]):
    """
    `base_schema` is a decorator to add the `BaseSchemaModel` to a class.

    usage example:
        @base_schema
        class MySchema:
            ...
    """

    if not issubclass(cls, BaseModel):
        raise TypeError("Class must be a subclass of pydantic.BaseModel")

    return functools.wraps(cls, updated=())(
        create_model(
            cls.__name__,
            __base__=(cls, new_cls),
        )
    )  # type: ignore


def to_partial(cls):
    class NewCls(cls):
        _PARTIAL: ClassVar = True

    NewCls.__name__ = f"Partial{cls.__name__}"

    # import pdb; pdb.set_trace()
    # for field in NewCls.model_fields.values():
    #     if hasattr(field.type_, "__base__") and issubclass(
    #         field.type_.__base__, BaseModel
    #     ):
    #         field.type_ = to_partial(field.type_)

    return NewCls


def skip_partial(f):
    """
    `skip_partial` is a decorator to skip validation when `_PARTIAL = True` and return the data as is.

    usage example:
        @model_validator(**validation_after)
        @skip_partial
        def my_custom_check(cls, values):
            ...
            return ...
    """

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        cls_arg = None
        v_args = None
        if args:
            cls_arg = args[0]
            if len(args) > 1:
                v_args = args[1]
        partial_property = getattr(cls_arg, "_PARTIAL", None)
        if partial_property:
            return v_args
        return f(*args, **kwargs)

    return wrapper
