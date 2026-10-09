import json
from typing import Any, Dict, List, Optional
from unittest import TestCase
import yaml

from clipped.compact.pydantic import Field
from clipped.config.patch_strategy import PatchStrategy
from clipped.config.schema import BaseSchemaModel


class ChildSchema(BaseSchemaModel):
    value: Optional[str] = None


class ParentSchema(BaseSchemaModel):
    _CUSTOM_DUMP_FIELDS = {"child", "children", "mapping"}

    child: Optional[ChildSchema] = None
    children: Optional[List[ChildSchema]] = None
    mapping: Optional[Dict[str, ChildSchema]] = None


class AliasedParentSchema(BaseSchemaModel):
    _CUSTOM_DUMP_FIELDS = {"nested_child"}

    nested_child: Optional[ChildSchema] = Field(alias="nestedChild", default=None)


class MappingSchema(BaseSchemaModel):
    _CUSTOM_DUMP_FIELDS = {"mapping"}

    mapping: Dict[str, Any]


class PatchSchema(BaseSchemaModel):
    _FIELDS_MANUAL_PATCH = ["protected"]

    value: Optional[str] = None
    tags: Optional[List[str]] = None
    child: Optional[ChildSchema] = None
    untouched: Optional[str] = None
    protected: Optional[str] = None


class TestSchemaPatch(TestCase):
    def test_selected_fields_keep_existing_patch_strategies(self):
        for strategy in PatchStrategy:
            with self.subTest(strategy=strategy):
                target = PatchSchema(
                    value="base",
                    tags=["base"],
                    child=ChildSchema(value="base"),
                    protected="base",
                )
                patch = PatchSchema(
                    value="local",
                    tags=["local"],
                    child=ChildSchema(value="local"),
                    untouched="local",
                    protected="local",
                )

                result = PatchSchema.patch_obj(
                    target,
                    patch,
                    strategy=strategy,
                    fields={"value", "tags", "child", "protected"},
                )

                assert result is target
                local_wins = strategy in (
                    PatchStrategy.POST_MERGE,
                    PatchStrategy.REPLACE,
                )
                assert result.value == ("local" if local_wins else "base")
                assert result.child.value == ("local" if local_wins else "base")
                expected_tags = {
                    PatchStrategy.POST_MERGE: ["base", "local"],
                    PatchStrategy.PRE_MERGE: ["local", "base"],
                    PatchStrategy.REPLACE: ["local"],
                    PatchStrategy.ISNULL: ["base"],
                }[strategy]
                assert result.tags == expected_tags
                assert result.untouched is None
                assert "untouched" not in result.model_fields_set
                assert result.protected == "base"

    def test_selected_fields_distinguish_null_empty_and_omitted_values(self):
        for strategy in PatchStrategy:
            for values in ({}, {"value": None, "tags": []}):
                with self.subTest(strategy=strategy, values=values):
                    target = PatchSchema(value="base", tags=["base"])

                    result = PatchSchema.patch_obj(
                        target,
                        PatchSchema(**values),
                        strategy=strategy,
                        fields={"value", "tags"},
                    )

                    clears = bool(values) and strategy in (
                        PatchStrategy.POST_MERGE,
                        PatchStrategy.REPLACE,
                    )
                    assert result.value == (None if clears else "base")
                    assert result.tags == (
                        [] if values and strategy == PatchStrategy.REPLACE else ["base"]
                    )

    def test_empty_or_unknown_field_selection_does_not_patch(self):
        for fields in (set(), {"unknown"}):
            target = PatchSchema(value="base")
            before = target.to_dict(exclude_none=False)

            result = PatchSchema.patch_obj(
                target, PatchSchema(value="local", untouched="local"), fields=fields
            )

            assert result is target
            assert result.to_dict(exclude_none=False) == before

    def test_omitting_field_selection_keeps_full_patch_behavior(self):
        target = PatchSchema(value="base")

        result = PatchSchema.patch_obj(
            target, PatchSchema(value="local", untouched="local")
        )

        assert result.value == "local"
        assert result.untouched == "local"


class TestSchemaDump(TestCase):
    def test_explicit_null_custom_fields_are_distinct_from_unset_fields(self):
        assert ParentSchema().to_dict(exclude_none=False) == {}
        parent = ParentSchema(child=None)

        assert parent.to_dict() == {}
        assert parent.to_dict(exclude_none=False) == {"child": None}
        assert json.loads(parent.to_json(exclude_none=False)) == {"child": None}
        assert parent.to_dict(exclude_none=False, exclude_defaults=True) == {}
        assert AliasedParentSchema(nested_child=None).to_dict(exclude_none=False) == {
            "nestedChild": None
        }

    def test_nested_custom_fields_preserve_explicit_nulls(self):
        parent = ParentSchema(
            child=ChildSchema(value=None),
            children=[ChildSchema(value=None), ChildSchema()],
            mapping={"explicit": ChildSchema(value=None), "unset": ChildSchema()},
        )

        assert parent.to_dict(exclude_none=False) == {
            "child": {"value": None},
            "children": [{"value": None}, {}],
            "mapping": {"explicit": {"value": None}, "unset": {}},
        }
        assert parent.to_dict() == {
            "child": {},
            "children": [{}, {}],
            "mapping": {"explicit": {}, "unset": {}},
        }

    def test_explicit_empty_custom_fields_remain_present(self):
        parent = ParentSchema(children=[], mapping={})

        assert parent.to_dict(exclude_none=False) == {"children": [], "mapping": {}}

    def test_plain_custom_mapping_does_not_share_nested_values_with_source(self):
        source = {
            "container": {"image": "busybox:1.37", "args": ["echo hello"]},
            "ports": [8080],
            "disabled": False,
            "missing": None,
        }
        parent = MappingSchema(mapping=source)

        payload = parent.to_dict(exclude_none=False)

        assert payload == {"mapping": source}
        payload["mapping"]["container"]["image"] = "changed:v2"
        payload["mapping"]["container"]["args"].append("echo changed")
        payload["mapping"]["ports"].append(9090)
        assert parent.mapping["container"] == {
            "image": "busybox:1.37",
            "args": ["echo hello"],
        }
        assert parent.mapping["ports"] == [8080]

    def test_custom_mapping_can_mix_schema_and_plain_values(self):
        parent = MappingSchema(
            mapping={
                "schema": ChildSchema(value=None),
                "plain": {"value": None},
                "missing": None,
            }
        )

        assert parent.to_dict(exclude_none=False) == {
            "mapping": {
                "schema": {"value": None},
                "plain": {"value": None},
                "missing": None,
            }
        }
        assert parent.to_dict() == {
            "mapping": {
                "schema": {},
                "plain": {"value": None},
                "missing": None,
            }
        }


class TestKeepNone(TestCase):
    def test_keep_none_class_keeps_nulls_and_passes_them_to_custom_children(self):
        class Schema(ParentSchema):
            _KEEP_NONE = True

        schema = Schema(
            child=None,
            children=[ChildSchema(value=None), ChildSchema()],
            mapping={},
        )
        expected = {
            "child": None,
            "children": [{"value": None}, {}],
            "mapping": {},
        }

        assert schema.to_dict() == expected
        assert schema.to_dict(exclude_none=True) == expected
        assert json.loads(schema.to_json()) == expected
        assert yaml.safe_load(schema.to_yaml()) == expected
        assert Schema().to_dict() == {}
        assert ParentSchema(child=None).to_dict() == {}
        assert BaseSchemaModel._KEEP_NONE is False
