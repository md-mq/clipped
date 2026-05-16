import os
from unittest import TestCase

from clipped import types
from clipped.compact.pydantic import PYDANTIC_VERSION, StrictInt, StrictStr
from clipped.config.exceptions import SchemaError
from clipped.config.reader import ConfigReader
from clipped.types.lists import ListStr


class TestConfigReader(TestCase):
    def setUp(self):
        super().setUp()
        os.environ["FOO_BAR_KEY"] = "foo_bar"
        self.config = ConfigReader.read_configs(
            [os.environ, "tests/fixtures/parsing/configs/config_tests.json"]
        )

    def test_get_from_os_env(self):
        assert self.config.get("FOO_BAR_KEY", "str") == "foo_bar"

    def test_reading_invalid_json_config_raises_error(self):
        with self.assertRaises(SchemaError):
            ConfigReader.read_configs(
                ["tests/fixtures/parsing/configs/invalid_config_tests.json"]
            )

    def test_reading_invalid_yaml_config_raises_error(self):
        with self.assertRaises(SchemaError):
            ConfigReader.read_configs(
                ["tests/fixtures/parsing/configs/invalid_config_tests.yaml"]
            )

    def test_get_boolean(self):
        value = self.config.get("bool_key_1", "bool")
        self.assertEqual(value, True)

        value = self.config.get("bool_key_2", "bool")
        self.assertEqual(value, True)

        value = self.config.get("bool_key_3", "bool")
        self.assertEqual(value, False)

        value = self.config.get("bool_key_4", "bool")
        self.assertEqual(value, False)

        value = self.config.get("bool_key_5", "bool")
        self.assertEqual(value, False)

        value = self.config.get("bool_key_6", "bool")
        self.assertEqual(value, True)

        value = self.config.get("bool_list_key_1", "bool", is_list=True)
        self.assertEqual(value, [False, False, True, True, True, False])

        value = self.config.get("bool_list_key_2", "bool", is_list=True)
        self.assertEqual(value, [False, True, False])

        with self.assertRaises(SchemaError):
            self.config.get("bool_error_key_1", "bool")

        with self.assertRaises(SchemaError):
            self.config.get("bool_error_key_2", "bool")

        with self.assertRaises(SchemaError):
            self.config.get("bool_error_key_5", "bool")

        with self.assertRaises(SchemaError):
            self.config.get("bool_list_key_1", "bool")

        with self.assertRaises(SchemaError):
            self.config.get("bool_list_error_key_1", "bool", is_list=True)

        with self.assertRaises(SchemaError):
            self.config.get("bool_key_1", "bool", is_list=True)

        with self.assertRaises(SchemaError):
            self.config.get("bool_key_2", "bool", is_list=True)

        with self.assertRaises(SchemaError):
            self.config.get("bool_non_existing_key", "bool")

        with self.assertRaises(SchemaError):
            self.config.get("bool_non_existing_key", "bool", is_list=True)

        self.assertEqual(
            self.config.get("bool_non_existing_key", "bool", is_optional=True), None
        )
        self.assertEqual(
            self.config.get(
                "bool_non_existing_key", "bool", is_optional=True, default=True
            ),
            True,
        )

        self.assertEqual(
            self.config.get(
                "bool_non_existing_key", "bool", is_list=True, is_optional=True
            ),
            None,
        )
        self.assertEqual(
            self.config.get(
                "bool_non_existing_key",
                "bool",
                is_list=True,
                is_optional=True,
                default=[True, False],
            ),
            [True, False],
        )

    def test_get_int(self):
        value = self.config.get("int_key_1", "int")
        self.assertEqual(value, 123)

        value = self.config.get("int_key_2", "int")
        self.assertEqual(value, 123)

        value = self.config.get(key="float_int_key_1", key_type="int")
        self.assertEqual(value, 12)

        value = self.config.get("int_list_key_1", "int", is_list=True)
        self.assertEqual(value, [123, 124, 125, 125])

        with self.assertRaises(SchemaError):
            self.config.get(key="float_int_key_2", key_type="int")

        with self.assertRaises(SchemaError):
            self.config.get("int_error_key_1", key_type="int")

        with self.assertRaises(SchemaError):
            self.config.get("int_error_key_2", key_type="int")

        if PYDANTIC_VERSION.startswith("2."):
            with self.assertRaises(SchemaError):
                self.config.get(key="float_key_1", key_type="int")
        else:
            value = self.config.get(key="float_key_1", key_type="int")
            assert value == 1

        with self.assertRaises(SchemaError):
            self.config.get(key="float_key_1", key_type=StrictInt)

        if PYDANTIC_VERSION.startswith("2."):
            with self.assertRaises(SchemaError):
                self.config.get(key="float_key_2", key_type="int")
        else:
            value = self.config.get(key="float_key_2", key_type="int")
            assert value == 1

        with self.assertRaises(SchemaError):
            self.config.get(key="float_key_2", key_type=StrictInt)

        with self.assertRaises(SchemaError):
            self.config.get("int_error_key_3", key_type="int")

        with self.assertRaises(SchemaError):
            self.config.get("int_list_key_1", key_type="int")

        with self.assertRaises(SchemaError):
            self.config.get("int_list_error_key_1", key_type="int", is_list=True)

        value = self.config.get(
            key="int_list_error_key_2", key_type="int", is_list=True
        )
        assert value == [123, 1, 125, 125]

        with self.assertRaises(SchemaError):
            self.config.get("int_list_error_key_2", key_type=StrictInt, is_list=True)

        with self.assertRaises(SchemaError):
            self.config.get("int_list_error_key_3", key_type="int", is_list=True)

        with self.assertRaises(SchemaError):
            self.config.get("int_key_1", key_type="int", is_list=True)

        with self.assertRaises(SchemaError):
            self.config.get("int_key_2", key_type="int", is_list=True)

        with self.assertRaises(SchemaError):
            self.config.get("int_non_existing_key", key_type="int")

        with self.assertRaises(SchemaError):
            self.config.get("int_non_existing_key", key_type="int", is_list=True)

        self.assertEqual(
            self.config.get("int_non_existing_key", key_type="int", is_optional=True),
            None,
        )
        self.assertEqual(
            self.config.get(
                "int_non_existing_key", key_type="int", is_optional=True, default=34
            ),
            34,
        )

        self.assertEqual(
            self.config.get(
                "int_non_existing_key",
                key_type="int",
                is_list=True,
                is_optional=True,
            ),
            None,
        )
        self.assertEqual(
            self.config.get(
                "int_non_existing_key",
                key_type="int",
                is_list=True,
                is_optional=True,
                default=[34, 1],
            ),
            [34, 1],
        )

    def test_get_float(self):
        value = self.config.get("float_key_1", "float")
        self.assertEqual(value, 1.23)

        value = self.config.get("float_key_2", "float")
        self.assertEqual(value, 1.23)

        value = self.config.get("float_key_3", "float")
        self.assertEqual(value, 123)

        value = self.config.get("float_key_4", "float")
        self.assertEqual(value, 123.0)

        value = self.config.get("float_list_key_1", "float", is_list=True)
        self.assertEqual(value, [1.23, 13.3, 4.4, 555.0, 66.0])

        value = self.config.get("float_list_key_2", "float", is_list=True)
        self.assertEqual(value, [1.23, 13.3, 66])

        with self.assertRaises(SchemaError):
            self.config.get("float_error_key_1", "float")

        with self.assertRaises(SchemaError):
            self.config.get("float_error_key_2", "float")

        with self.assertRaises(SchemaError):
            self.config.get("float_error_key_3", "float")

        with self.assertRaises(SchemaError):
            self.config.get("float_list_key_1", "float")

        with self.assertRaises(SchemaError):
            self.config.get("float_list_error_key_2", "float", is_list=True)

        with self.assertRaises(SchemaError):
            self.config.get("float_list_error_key_3", "float", is_list=True)

        with self.assertRaises(SchemaError):
            self.config.get("float_key_1", "float", is_list=True)

        with self.assertRaises(SchemaError):
            self.config.get("float_key_2", "float", is_list=True)

        with self.assertRaises(SchemaError):
            self.config.get("float_non_existing_key", "float")

        with self.assertRaises(SchemaError):
            self.config.get("float_non_existing_key", "float", is_list=True)

        self.assertEqual(
            self.config.get("float_non_existing_key", "float", is_optional=True),
            None,
        )
        self.assertEqual(
            self.config.get(
                "float_non_existing_key", "float", is_optional=True, default=3.4
            ),
            3.4,
        )

        self.assertEqual(
            self.config.get(
                "float_non_existing_key", "float", is_list=True, is_optional=True
            ),
            None,
        )
        self.assertEqual(
            self.config.get(
                "float_non_existing_key",
                "float",
                is_list=True,
                is_optional=True,
                default=[3.4, 1.2],
            ),
            [3.4, 1.2],
        )

    def test_get_string(self):
        value = self.config.get("string_key_1", "str")
        self.assertEqual(value, "123")

        value = self.config.get("string_key_2", "str")
        self.assertEqual(value, "1.23")

        value = self.config.get("string_key_3", "str")
        self.assertEqual(value, "foo")

        value = self.config.get("string_key_4", "str")
        self.assertEqual(value, "")

        value = self.config.get("string_list_key_1", "str", is_list=True)
        self.assertEqual(value, ["123", "1.23", "foo", ""])

        with self.assertRaises(SchemaError):
            self.config.get("string_error_key_1", "str")

        value = self.config.get("string_error_key_2", "str")
        assert value == "123"
        with self.assertRaises(SchemaError):
            self.config.get("string_error_key_2", StrictStr)

        value = self.config.get("string_error_key_3", "str")
        assert value == "1.23"
        with self.assertRaises(SchemaError):
            self.config.get("string_error_key_3", StrictStr)

        value = self.config.get("string_error_key_4", "str")
        assert value == "true"
        with self.assertRaises(SchemaError):
            self.config.get("string_error_key_4", StrictStr)

        value = self.config.get("string_list_key_1", "str")
        assert value == '["123","1.23","foo",""]'
        with self.assertRaises(SchemaError):
            self.config.get("string_list_key_1", StrictStr)

        value = self.config.get("string_list_error_key_1", "str", is_list=True)
        assert value == ["123", "123"]
        with self.assertRaises(SchemaError):
            self.config.get("string_list_error_key_1", StrictStr, is_list=True)

        value = self.config.get("string_list_error_key_2", "str", is_list=True)
        assert value == ["123", "12.3"]
        with self.assertRaises(SchemaError):
            self.config.get("string_list_error_key_2", StrictStr, is_list=True)

        with self.assertRaises(SchemaError):
            self.config.get("string_list_error_key_3", "str", is_list=True)

        value = self.config.get("string_list_error_key_4", "str", is_list=True)
        assert value == ["123", "false"]
        with self.assertRaises(SchemaError):
            self.config.get("string_list_error_key_4", StrictStr, is_list=True)

        with self.assertRaises(SchemaError):
            self.config.get("string_key_4", "str", is_list=True)

        with self.assertRaises(SchemaError):
            self.config.get("string_non_existing_key", "str")

        with self.assertRaises(SchemaError):
            self.config.get("string_non_existing_key", "str", is_list=True)

        with self.assertRaises(SchemaError):
            self.config.get("string_key_3", "str", is_list=True)

        self.assertEqual(
            self.config.get("string_non_existing_key", "str", is_optional=True),
            None,
        )
        self.assertEqual(
            self.config.get(
                "string_non_existing_key", "str", is_optional=True, default="foo"
            ),
            "foo",
        )

        self.assertEqual(
            self.config.get(
                "string_non_existing_key", "str", is_list=True, is_optional=True
            ),
            None,
        )
        self.assertEqual(
            self.config.get(
                "string_non_existing_key",
                "str",
                is_list=True,
                is_optional=True,
                default=["foo", "bar"],
            ),
            ["foo", "bar"],
        )

    def test_get_dict(self):
        value = self.config.get("dict_key_1", "dict")
        self.assertEqual(value, {"key1": "foo", "key2": 2, "key3": False, "key4": "1"})

        value = self.config.get("dict_list_key_1", "dict", is_list=True)
        self.assertEqual(
            value,
            [
                {"key1": "foo", "key2": 2, "key3": False, "key4": "1"},
                {"key3": True, "key4": "2"},
                {"key1": False, "key2": "3"},
            ],
        )

        with self.assertRaises(SchemaError):
            self.config.get("dict_error_key_1", "dict")

        with self.assertRaises(SchemaError):
            self.config.get("dict_error_key_2", "dict")

        with self.assertRaises(SchemaError):
            self.config.get("dict_error_key_3", "dict")

        with self.assertRaises(SchemaError):
            self.config.get("dict_error_key_4", "dict")

        with self.assertRaises(SchemaError):
            self.config.get("dict_list_key_1", "dict")

        with self.assertRaises(SchemaError):
            self.config.get("dict_list_error_key_1", "dict", is_list=True)

        with self.assertRaises(SchemaError):
            self.config.get("dict_list_error_key_2", "dict", is_list=True)

        with self.assertRaises(SchemaError):
            self.config.get("dict_list_error_key_3", "dict", is_list=True)

        with self.assertRaises(SchemaError):
            self.config.get("dict_list_error_key_4", "dict", is_list=True)

        with self.assertRaises(SchemaError):
            self.config.get("dict_key_1", "dict", is_list=True)

        with self.assertRaises(SchemaError):
            self.config.get("dict_non_existing_key", "dict")

        with self.assertRaises(SchemaError):
            self.config.get("dict_non_existing_key", "dict", is_list=True)

        self.assertEqual(
            self.config.get("dict_non_existing_key", "dict", is_optional=True), None
        )
        self.assertEqual(
            self.config.get(
                "dict_non_existing_key",
                "dict",
                is_optional=True,
                default={"foo": "bar"},
            ),
            {"foo": "bar"},
        )

        self.assertEqual(
            self.config.get(
                "dict_non_existing_key", "dict", is_list=True, is_optional=True
            ),
            None,
        )
        self.assertEqual(
            self.config.get(
                "dict_non_existing_key",
                "dict",
                is_list=True,
                is_optional=True,
                default=[{"foo": "bar"}, {"foo": "boo"}],
            ),
            [{"foo": "bar"}, {"foo": "boo"}],
        )

    def test_get_uri(self):
        value = self.config.get("uri_key_1", types.URI)
        self.assertEqual(str(value), "https://user:pass@siteweb.ca/")

        value = self.config.get("uri_key_2", types.URI)
        self.assertEqual(str(value), "http://user2:pass@localhost:8080/")

        value = self.config.get("uri_key_3", types.URI)
        self.assertEqual(str(value), "https://user2:pass@quay.io/")

        value = self.config.get("uri_list_key_1", types.URI, is_list=True)
        self.assertEqual(
            [str(v) for v in value],
            [
                "https://user:pass@siteweb.ca/",
                "http://user2:pass@localhost:8080/",
                "https://user2:pass@quay.io/",
            ],
        )

        with self.assertRaises(SchemaError):
            self.config.get("uri_error_key_1", types.URI)

        with self.assertRaises(SchemaError):
            self.config.get("uri_error_key_2", types.URI)

        with self.assertRaises(SchemaError):
            self.config.get("uri_error_key_3", types.URI)

        with self.assertRaises(SchemaError):
            self.config.get("uri_error_key_4", types.URI)

        with self.assertRaises(SchemaError):
            self.config.get("uri_list_key_1", types.URI)

        with self.assertRaises(SchemaError):
            self.config.get("uri_list_error_key_1", types.URI, is_list=True)

        with self.assertRaises(SchemaError):
            self.config.get("uri_list_error_key_2", types.URI, is_list=True)

        with self.assertRaises(SchemaError):
            self.config.get("uri_list_error_key_3", types.URI, is_list=True)

        with self.assertRaises(SchemaError):
            self.config.get("uri_list_error_key_4", types.URI, is_list=True)

        with self.assertRaises(SchemaError):
            self.config.get("uri_non_existing_key", types.URI)

        with self.assertRaises(SchemaError):
            self.config.get("uri_non_existing_key", types.URI, is_list=True)

        with self.assertRaises(SchemaError):
            self.config.get("uri_key_1", types.URI, is_list=True)

        self.assertEqual(
            self.config.get("uri_non_existing_key", types.URI, is_optional=True), None
        )
        self.assertEqual(
            self.config.get(
                "uri_non_existing_key",
                types.URI,
                is_optional=True,
                default="http://user2:pass@localhost:8080",
            ),
            "http://user2:pass@localhost:8080",
        )

        self.assertEqual(
            self.config.get(
                "uri_non_existing_key", types.URI, is_list=True, is_optional=True
            ),
            None,
        )

        self.assertEqual(
            self.config.get(
                "uri_non_existing_key",
                types.URI,
                is_list=True,
                is_optional=True,
                default=[
                    "https://user:pass@siteweb.ca",
                    "https://user2:pass@quay.io",
                ],
            ),
            [
                "https://user:pass@siteweb.ca",
                "https://user2:pass@quay.io",
            ],
        )

    def test_get_list(self):
        with self.assertRaises(SchemaError):
            self.config.get("list_key_1", "list")
        value = self.config.get("list_key_1", ListStr)
        self.assertEqual(value, ["user:pass@siteweb.ca", "'pp'", "0.1", "'foo'"])

        with self.assertRaises(SchemaError):
            self.config.get("list_key_2", "list")
        value = self.config.get("list_key_2", ListStr)
        self.assertEqual(value, ["user1", "user2", "user3", "user4", "user5"])

        value = self.config.get("list_key_3", "list")
        self.assertEqual(value, [False])

        with self.assertRaises(SchemaError):
            self.config.get("list_key_4", "list")
        value = self.config.get("list_key_4", ListStr)
        self.assertEqual(value, ["foo"])

        with self.assertRaises(SchemaError):
            self.config.get("list_key_5", "list")
        value = self.config.get("list_key_5", ListStr)
        self.assertEqual(value, [])

        with self.assertRaises(SchemaError):
            self.config.get("list_error_key_1", "list")

        with self.assertRaises(SchemaError):
            self.config.get("list_error_key_2", "list")

        with self.assertRaises(SchemaError):
            self.config.get("list_error_key_3", "list")

        with self.assertRaises(SchemaError):
            self.config.get("list_error_key_4", "list")

        with self.assertRaises(SchemaError):
            self.config.get("list_non_existing_key", "list")

        self.assertEqual(
            self.config.get("list_non_existing_key", "list", is_optional=True), None
        )
        self.assertEqual(
            self.config.get(
                "list_non_existing_key", "list", is_optional=True, default=["foo"]
            ),
            ["foo"],
        )
