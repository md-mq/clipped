import json
from typing import Dict, List, Optional
from unittest import TestCase

from clipped.compact.pydantic import Field
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
