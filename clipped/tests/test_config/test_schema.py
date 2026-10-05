from copy import deepcopy
import json
from typing import Any, Dict, List, Optional
from unittest import TestCase
from unittest.mock import patch
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


class TestDumpPolicy(TestCase):
    def test_default_null_rule_preserves_omissions_and_filters(self):
        class Schema(ParentSchema):
            _DUMP_POLICY = {"default": {"exclude_none": False}}

        schema = Schema(child=None, children=[], mapping={})
        expected = {"child": None, "children": [], "mapping": {}}

        assert schema.to_dict() == expected
        assert json.loads(schema.to_json()) == expected
        assert yaml.safe_load(schema.to_yaml()) == expected
        assert Schema().to_dict() == {}
        assert Schema().to_dict(exclude_unset=False) == {
            "child": None,
            "children": None,
            "mapping": None,
        }
        assert schema.to_dict(exclude_defaults=True) == {"children": [], "mapping": {}}

    def test_policies_are_class_owned_and_named_purposes_ignore_defaults(self):
        class Schema(ChildSchema):
            _IDENTIFIER = "shared"
            _DUMP_POLICY = {
                "default": {"exclude_none": True},
                "component_state": {"exclude_none": False},
            }

        class InheritedSchema(Schema):
            pass

        class CompactSchema(Schema):
            _DUMP_POLICY = {"component_state": {"exclude_none": True}}

        before = deepcopy(Schema._DUMP_POLICY)
        for model in (Schema, InheritedSchema):
            with self.subTest(model=model):
                schema = model(value=None)
                assert schema.to_dict(exclude_none=False) == {}
                assert schema.to_dict(purpose="component_state") == {"value": None}
                assert schema.to_dict(purpose="source") == {}
                assert schema.to_dict(exclude_none=False, purpose="source") == {
                    "value": None
                }
        assert (
            CompactSchema(value=None).to_dict(
                exclude_none=False, purpose="component_state"
            )
            == {}
        )
        assert Schema._DUMP_POLICY == before
        assert BaseSchemaModel._DUMP_POLICY == {}

    def test_purpose_reaches_custom_children_once_without_mutation(self):
        class Schema(ChildSchema):
            _DUMP_POLICY = {"component_state": {"exclude_none": False}}

        child = Schema(value=None)
        unset = Schema()
        parent = ParentSchema(
            child=child,
            children=[child, unset],
            mapping={"explicit": child, "unset": unset},
        )
        before_policy = deepcopy(Schema._DUMP_POLICY)
        models = (parent, child, unset)
        fields_sets = [model.model_fields_set.copy() for model in models]
        expected = {
            "child": {"value": None},
            "children": [{"value": None}, {}],
            "mapping": {"explicit": {"value": None}, "unset": {}},
        }

        for method in ("to_dict", "to_json"):
            with self.subTest(method=method):
                with patch.object(
                    Schema, "obj_to_dict", wraps=Schema.obj_to_dict
                ) as dump:
                    payload = getattr(parent, method)(
                        purpose="component_state",
                        exclude_unset=False,
                        exclude_defaults=True,
                    )
                if method == "to_json":
                    payload = json.loads(payload)
                assert payload == expected
                assert dump.call_count == 5
                dump.assert_any_call(
                    child, exclude_none=True, purpose="component_state"
                )
                dump.assert_any_call(
                    unset, exclude_none=True, purpose="component_state"
                )
                payload["child"]["value"] = "changed"
                assert child.value is None
                assert parent.to_dict() == {
                    "child": {},
                    "children": [{}, {}],
                    "mapping": {"explicit": {}, "unset": {}},
                }
                assert [model.model_fields_set for model in models] == fields_sets
                assert Schema._DUMP_POLICY == before_policy

    def test_no_purpose_keeps_legacy_root_arguments(self):
        schema = ChildSchema(value=None)
        for method in ("to_dict", "to_json", "to_yaml"):
            with self.subTest(method=method):
                with patch.object(
                    ChildSchema, "obj_to_dict", wraps=ChildSchema.obj_to_dict
                ) as dump:
                    getattr(schema, method)()

                dump.assert_called_once_with(
                    schema,
                    humanize_values=False,
                    include_kind=False,
                    include_version=False,
                    exclude_unset=True,
                    exclude_none=True,
                    exclude_defaults=False,
                )
