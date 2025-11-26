import datetime
import uuid

from typing import Dict, List
from unittest import TestCase

from dateutil.tz import tzutc

from clipped.compact.pydantic import PYDANTIC_VERSION, StrictInt, StrictStr
from clipped.config.constants import NO_VALUE_FOUND
from clipped.config.exceptions import SchemaError
from clipped.config.parser import ConfigParser
from clipped.types import GcsPath, S3Path, Uri, WasbPath
from clipped.types.docker_image import ImageStr
from clipped.types.lists import ListStr
from clipped.types.uuids import UUIDStr


class TestConfigParser(TestCase):
    def test_get_boolean(self):
        get_boolean = ConfigParser.parse(bool)
        value = get_boolean(key="bool_key", value="1")
        self.assertEqual(value, True)

        value = get_boolean(key="bool_key", value=1)
        self.assertEqual(value, True)

        value = get_boolean(key="bool_key", value="true")
        self.assertEqual(value, True)

        value = get_boolean(key="bool_key", value="t")
        self.assertEqual(value, True)

        value = get_boolean(key="bool_key", value=True)
        self.assertEqual(value, True)

        value = get_boolean(key="bool_key", value="0")
        self.assertEqual(value, False)

        value = get_boolean(key="bool_key", value=0)
        self.assertEqual(value, False)

        value = get_boolean(key="bool_key", value="false")
        self.assertEqual(value, False)

        value = get_boolean(key="bool_key", value="f")
        self.assertEqual(value, False)

        value = get_boolean(key="bool_key", value=False)
        self.assertEqual(value, False)

        value = get_boolean(
            key="bool_list_key_1",
            value=[False, "false", True, "true", "1", "0", 1, 0],
            is_list=True,
        )
        self.assertEqual(value, [False, False, True, True, True, False, True, False])

        with self.assertRaises(SchemaError):
            get_boolean(key="bool_error_key_1", value="null")

        with self.assertRaises(SchemaError):
            get_boolean(key="bool_error_key_1", value=None)

        with self.assertRaises(SchemaError):
            get_boolean(key="bool_error_key_2", value="foo")

        with self.assertRaises(SchemaError):
            get_boolean(key="bool_error_key_5", value="")

        with self.assertRaises(SchemaError):
            get_boolean(
                key="bool_list_key_1", value=[False, "false", True, "true", "1", "0"]
            )

        with self.assertRaises(SchemaError):
            get_boolean(
                key="bool_list_error_key_1",
                value=[False, "false", True, "true", "1", "0", 1, 0, "foo"],
                is_list=True,
            )

        with self.assertRaises(SchemaError):
            get_boolean(key="bool_key_1", value="1", is_list=True)

        with self.assertRaises(SchemaError):
            get_boolean(key="bool_key_2", value=True, is_list=True)

        with self.assertRaises(SchemaError):
            get_boolean(key="bool_non_existing_key", value=None)

        with self.assertRaises(SchemaError):
            get_boolean(key="bool_non_existing_key", value=NO_VALUE_FOUND)

        with self.assertRaises(SchemaError):
            get_boolean(key="bool_non_existing_key", value=None, is_list=True)

        self.assertEqual(
            get_boolean(key="bool_non_existing_key", value=None, is_optional=True),
            None,
        )
        self.assertEqual(
            get_boolean(
                key="bool_non_existing_key", value=None, is_optional=True, default=True
            ),
            True,
        )

        self.assertEqual(
            get_boolean(
                key="bool_non_existing_key", value=None, is_list=True, is_optional=True
            ),
            None,
        )
        self.assertEqual(
            get_boolean(
                key="bool_non_existing_key",
                value=None,
                is_list=True,
                is_optional=True,
                default=[True, False],
            ),
            [True, False],
        )

    def test_get_int(self):
        get_int = ConfigParser.parse(int)
        get_strict_int = ConfigParser.parse(StrictInt)
        value = get_int(key="int_key_1", value=123)
        self.assertEqual(value, 123)

        value = get_int(key="int_key_2", value="123")
        self.assertEqual(value, 123)

        value = get_int(key="float_key_1", value=12.0)
        self.assertEqual(value, 12)

        value = get_int(key="float_key_1", value=12.0)
        self.assertEqual(value, 12)

        value = get_int(key="float_key_1", value="12.0")
        self.assertEqual(value, 12)

        value = get_int(
            key="int_list_key_1", value=["123", 124, 125, "125"], is_list=True
        )
        self.assertEqual(value, [123, 124, 125, 125])

        value = get_int(
            key="int_list_key_1", value='["123", 124, 125, "125"]', is_list=True
        )
        self.assertEqual(value, [123, 124, 125, 125])

        with self.assertRaises(SchemaError):
            get_int(key="float_key_1", value="12.")

        with self.assertRaises(SchemaError):
            get_int(key="int_error_key_1", value="null")

        with self.assertRaises(SchemaError):
            get_int(key="int_error_key_1", value=None)

        with self.assertRaises(SchemaError):
            get_int(key="int_error_key_2", value="")

        if PYDANTIC_VERSION.startswith("2."):
            with self.assertRaises(SchemaError):
                get_int(key="k", value=12.1)
        else:
            value = get_int(key="float_error_key_1", value=12.1)
            assert value == 12
        with self.assertRaises(SchemaError):
            get_strict_int(key="float_error_key_3", value=12.1)

        with self.assertRaises(SchemaError):
            get_strict_int(key="float_error_key_3", value="12.1")
        with self.assertRaises(SchemaError):
            get_strict_int(key="float_error_key_3", value="12.1")

        with self.assertRaises(SchemaError):
            get_int(key="int_error_key_3", value="foo")

        with self.assertRaises(SchemaError):
            get_int(key="int_list_key_1", value=["123", 124, 125, "125"])

        with self.assertRaises(SchemaError):
            get_int(
                key="int_list_error_key_1",
                value=["123", 124, 125, "125", None],
                is_list=True,
            )

        value = get_int(
            key="int_list_error_key_2",
            value=["123", 1.00, 125, "125"],
            is_list=True,
        )
        assert value == [123, 1, 125, 125]
        with self.assertRaises(SchemaError):
            get_strict_int(
                key="int_list_error_key_2",
                value=["123", 1.00, 125, "125"],
                is_list=True,
            )

        with self.assertRaises(SchemaError):
            get_int(
                key="int_list_error_key_3",
                value=["123", 1.24, 125, "foo"],
                is_list=True,
            )

        with self.assertRaises(SchemaError):
            get_int(key="int_key_1", value=125, is_list=True)

        with self.assertRaises(SchemaError):
            get_int(key="int_key_2", value="125", is_list=True)

        with self.assertRaises(SchemaError):
            get_int(key="int_non_existing_key", value=None)

        with self.assertRaises(SchemaError):
            get_int(key="int_non_existing_key", value=NO_VALUE_FOUND)

        self.assertEqual(
            get_int(key="int_non_existing_key", value=None, is_optional=True),
            None,
        )
        self.assertEqual(
            get_int(
                key="int_non_existing_key", value=None, is_optional=True, default=34
            ),
            34,
        )

        self.assertEqual(
            get_int(
                key="int_non_existing_key", value=None, is_list=True, is_optional=True
            ),
            None,
        )
        self.assertEqual(
            get_int(
                key="int_non_existing_key",
                value=None,
                is_list=True,
                is_optional=True,
                default=[34, 1],
            ),
            [34, 1],
        )

    def test_get_float(self):
        get_float = ConfigParser.parse(float)
        value = get_float(key="float_key_1", value=1.23)
        self.assertEqual(value, 1.23)

        value = get_float(key="float_key_2", value="1.23")
        self.assertEqual(value, 1.23)

        value = get_float(key="float_key_3", value="123")
        self.assertEqual(value, 123)

        value = get_float(
            key="float_list_key_1", value=[1.23, 13.3, "4.4", "555", 66.0], is_list=True
        )
        self.assertEqual(value, [1.23, 13.3, 4.4, 555.0, 66.0])

        value = get_float(
            key="float_list_key_1",
            value='[1.23, 13.3, "4.4", "555", 66.0]',
            is_list=True,
        )
        self.assertEqual(value, [1.23, 13.3, 4.4, 555.0, 66.0])

        value = get_float(key="float_from_int", value=123)
        self.assertEqual(value, 123.0)

        value = get_float(key="float_key_2", value=[1.23, 13.3, 66], is_list=True)
        self.assertEqual(value, [1.23, 13.3, 66])

        with self.assertRaises(SchemaError):
            get_float(key="float_error_key_1", value=None)

        with self.assertRaises(SchemaError):
            get_float(key="float_error_key_1", value="null")

        with self.assertRaises(SchemaError):
            get_float(key="float_error_key_2", value="")

        with self.assertRaises(SchemaError):
            get_float(key="float_error_key_3", value="foo")

        with self.assertRaises(SchemaError):
            get_float(key="float_list_key_1", value=[1.23, 13.3, "4.4", "555", 66.0])

        with self.assertRaises(SchemaError):
            get_float(key="float_list_error_key_1", value=None, is_list=True)

        with self.assertRaises(SchemaError):
            get_float(key="float_list_error_key_2", value="", is_list=True)

        with self.assertRaises(SchemaError):
            get_float(key="float_list_error_key_3", value="foo", is_list=True)

        with self.assertRaises(SchemaError):
            get_float(key="float_key_1", value=213, is_list=True)

        with self.assertRaises(SchemaError):
            get_float(key="float_non_existing_key", value=NO_VALUE_FOUND)

        with self.assertRaises(SchemaError):
            get_float(key="float_non_existing_key", value=[1.23, 13.3, "foo"])

        with self.assertRaises(SchemaError):
            get_float(
                key="float_non_existing_key", value=[1.23, 13.3, None], is_list=True
            )

        self.assertEqual(
            get_float(key="float_non_existing_key", value=None, is_optional=True),
            None,
        )
        self.assertEqual(
            get_float(
                key="float_non_existing_key", value=None, is_optional=True, default=3.4
            ),
            3.4,
        )

        with self.assertRaises(SchemaError):
            get_float(
                key="float_non_existing_key",
                value="null",
                is_list=True,
                is_optional=True,
            )

        self.assertEqual(
            get_float(
                key="float_non_existing_key",
                value=None,
                is_list=True,
                is_optional=True,
                default=[3.4, 1.2],
            ),
            [3.4, 1.2],
        )

    def test_get_string(self):
        get_string = ConfigParser.parse(str)
        get_strict_string = ConfigParser.parse(StrictStr)
        value = get_string(key="string_key_1", value="123")
        self.assertEqual(value, "123")

        value = get_string(key="string_key_2", value="1.23")
        self.assertEqual(value, "1.23")

        value = get_string(key="string_key_3", value="foo")
        self.assertEqual(value, "foo")

        value = get_string(key="string_key_4", value="")
        self.assertEqual(value, "")

        value = get_string(
            key="string_list_key_1", value=["123", "1.23", "foo", ""], is_list=True
        )
        self.assertEqual(value, ["123", "1.23", "foo", ""])

        value = get_string(
            key="string_list_key_1", value='["123", "1.23", "foo", ""]', is_list=True
        )
        self.assertEqual(value, ["123", "1.23", "foo", ""])

        with self.assertRaises(SchemaError):
            get_string(key="string_error_key_1", value=None)

        if PYDANTIC_VERSION.startswith("2."):
            with self.assertRaises(SchemaError):
                get_string(key="string_error_key_1", value=123)
        else:
            assert get_string(key="string_error_key_2", value=123) == "123"
        with self.assertRaises(SchemaError):
            get_strict_string(key="string_error_key_2", value=123)

        if PYDANTIC_VERSION.startswith("2."):
            with self.assertRaises(SchemaError):
                get_string(key="string_error_key_3", value=1.23)
        else:
            assert get_string(key="string_error_key_3", value=1.23) == "1.23"
        with self.assertRaises(SchemaError):
            get_strict_string(key="string_error_key_3", value=1.23)

        if PYDANTIC_VERSION.startswith("2."):
            with self.assertRaises(SchemaError):
                get_string(key="string_error_key_4", value=True)
        else:
            assert get_string(key="string_error_key_4", value=True) == "True"
        with self.assertRaises(SchemaError):
            get_strict_string(key="string_error_key_4", value=True)

        with self.assertRaises(SchemaError):
            get_string(key="string_list_key_1", value=["123", "1.23", "foo", ""])
        with self.assertRaises(SchemaError):
            get_strict_string(
                key="string_list_key_1",
                value=["123", "1.23", "foo", ""],
            )

        if PYDANTIC_VERSION.startswith("2."):
            with self.assertRaises(SchemaError):
                get_string(
                    key="string_list_error_key_1", value=["123", 123], is_list=True
                )
        else:
            assert get_string(
                key="string_list_error_key_1", value=["123", 123], is_list=True
            ) == ["123", "123"]
        with self.assertRaises(SchemaError):
            get_strict_string(
                key="string_list_error_key_1",
                value=["123", 123],
                is_list=True,
            )

        if PYDANTIC_VERSION.startswith("2."):
            with self.assertRaises(SchemaError):
                get_string(
                    key="string_list_error_key_2", value=["123", 12.3], is_list=True
                )
        else:
            assert get_string(
                key="string_list_error_key_2",
                value=["123", 12.3],
                is_list=True,
            ) == ["123", "12.3"]
        with self.assertRaises(SchemaError):
            get_strict_string(
                key="string_list_error_key_2",
                value=["123", 12.3],
                is_list=True,
            )

        with self.assertRaises(SchemaError):
            get_string(
                key="string_list_error_key_3",
                value=["123", None],
                is_list=True,
            )
        with self.assertRaises(SchemaError):
            get_strict_string(
                key="string_list_error_key_3",
                value=["123", None],
                is_list=True,
            )

        if PYDANTIC_VERSION.startswith("2."):
            with self.assertRaises(SchemaError):
                get_string(
                    key="string_list_error_key_4", value=["123", False], is_list=True
                )
        else:
            assert get_string(
                key="string_list_error_key_4",
                value=["123", False],
                is_list=True,
            ) == ["123", "False"]
        with self.assertRaises(SchemaError):
            get_strict_string(
                key="string_list_error_key_4",
                value=["123", False],
                is_list=True,
            )

        with self.assertRaises(SchemaError):
            get_string(key="string_key_4", value="", is_list=True)

        with self.assertRaises(SchemaError):
            get_string(key="string_non_existing_key", value=None)

        with self.assertRaises(SchemaError):
            get_string(key="string_non_existing_key", value=NO_VALUE_FOUND)

        with self.assertRaises(SchemaError):
            get_string(key="string_non_existing_key", value=None, is_list=True)

        self.assertEqual(
            get_string(key="string_non_existing_key", value=None, is_optional=True),
            None,
        )
        self.assertEqual(
            get_string(
                key="string_non_existing_key",
                value=None,
                is_optional=True,
                default="foo",
            ),
            "foo",
        )

        self.assertEqual(
            get_string(
                key="string_non_existing_key",
                value=None,
                is_list=True,
                is_optional=True,
            ),
            None,
        )
        self.assertEqual(
            get_string(
                key="string_non_existing_key",
                value=None,
                is_list=True,
                is_optional=True,
                default=["foo", "bar"],
            ),
            ["foo", "bar"],
        )

    def test_get_dict(self):
        get_dict = ConfigParser.parse(Dict)
        value = get_dict(
            key="dict_key_1",
            value={"key1": "foo", "key2": 2, "key3": False, "key4": "1"},
        )
        self.assertEqual(value, {"key1": "foo", "key2": 2, "key3": False, "key4": "1"})

        value = get_dict(
            key="dict_key_1",
            value='{"key1": "foo", "key2": 2, "key3": false, "key4": "1"}',
        )
        self.assertEqual(value, {"key1": "foo", "key2": 2, "key3": False, "key4": "1"})

        value = get_dict(
            key="dict_key_1",
            value='{"key1": "foo", "key2": 2, "key3": false, "key4": "1"}',
        )
        self.assertEqual(value, {"key1": "foo", "key2": 2, "key3": False, "key4": "1"})

        value = get_dict(
            key="dict_list_key_1",
            value=[
                {"key1": "foo", "key2": 2, "key3": False, "key4": "1"},
                {"key3": True, "key4": "2"},
                {"key1": False, "key2": "3"},
            ],
            is_list=True,
        )
        self.assertEqual(
            value,
            [
                {"key1": "foo", "key2": 2, "key3": False, "key4": "1"},
                {"key3": True, "key4": "2"},
                {"key1": False, "key2": "3"},
            ],
        )

        with self.assertRaises(SchemaError):
            get_dict(key="dict_error_key_1", value="foo")

        with self.assertRaises(SchemaError):
            get_dict(key="dict_error_key_2", value=1)

        with self.assertRaises(SchemaError):
            get_dict(key="dict_error_key_3", value=False)

        with self.assertRaises(SchemaError):
            get_dict(key="dict_error_key_4", value=["1", "foo"])

        with self.assertRaises(SchemaError):
            get_dict(key="dict_list_key_1", value=["123", {"key3": True}])

        with self.assertRaises(SchemaError):
            get_dict(
                key="dict_list_error_key_1", value=["123", {"key3": True}], is_list=True
            )

        with self.assertRaises(SchemaError):
            get_dict(
                key="dict_list_error_key_2", value=[{"key3": True}, 12.3], is_list=True
            )

        with self.assertRaises(SchemaError):
            get_dict(
                key="dict_list_error_key_3", value=[{"key3": True}, None], is_list=True
            )

        with self.assertRaises(SchemaError):
            get_dict(
                key="dict_list_error_key_4",
                value=[{"key3": True}, "123", False],
                is_list=True,
            )

        with self.assertRaises(SchemaError):
            get_dict(
                key="dict_key_1",
                value={"key1": "foo", "key2": 2, "key3": False, "key4": "1"},
                is_list=True,
            )

        with self.assertRaises(SchemaError):
            get_dict(key="dict_non_existing_key", value=None)

        with self.assertRaises(SchemaError):
            get_dict(key="dict_non_existing_key", value=NO_VALUE_FOUND)

        with self.assertRaises(SchemaError):
            get_dict(key="dict_non_existing_key", value=None, is_list=True)

        self.assertEqual(
            get_dict(key="dict_non_existing_key", value=None, is_optional=True),
            None,
        )
        self.assertEqual(
            get_dict(
                key="dict_non_existing_key",
                value=None,
                is_optional=True,
                default={"foo": "bar"},
            ),
            {"foo": "bar"},
        )

        self.assertEqual(
            get_dict(
                key="dict_non_existing_key", value=None, is_list=True, is_optional=True
            ),
            None,
        )
        self.assertEqual(
            get_dict(
                key="dict_non_existing_key",
                value=None,
                is_list=True,
                is_optional=True,
                default=[{"foo": "bar"}, {"foo": "boo"}],
            ),
            [{"foo": "bar"}, {"foo": "boo"}],
        )

    def test_get_uri(self):
        get_uri = ConfigParser.parse(Uri)
        value = get_uri(key="uri_key_1", value="https://user:pass@siteweb.ca/")
        assert str(value) == "https://user:pass@siteweb.ca/"
        if PYDANTIC_VERSION.startswith("2."):
            assert value.username == "user"
        else:
            assert value.user == "user"
        assert value.password == "pass"
        assert value.host == "siteweb.ca"
        if PYDANTIC_VERSION.startswith("2."):
            assert value.host_port == "https://siteweb.ca:443"
        else:
            assert value.host_port == "https://siteweb.ca"

        value = get_uri(key="uri_key_2", value="http://user2:pass@localhost:8080/")
        assert str(value) == "http://user2:pass@localhost:8080/"
        if PYDANTIC_VERSION.startswith("2."):
            assert value.username == "user2"
        else:
            assert value.user == "user2"
        assert value.password == "pass"
        assert value.host == "localhost"
        assert value.host_port == "http://localhost:8080"

        value = get_uri(key="uri_key_3", value="https://user2:pass@quay.io/")
        assert str(value) == "https://user2:pass@quay.io/"

        value = get_uri(
            key="uri_list_key_1",
            value=[
                "https://user:pass@siteweb.ca/",
                "http://user2:pass@localhost:8080/",
                "https://user2:pass@quay.io/",
            ],
            is_list=True,
        )
        self.assertEqual(
            [str(v) for v in value],
            [
                "https://user:pass@siteweb.ca/",
                "http://user2:pass@localhost:8080/",
                "https://user2:pass@quay.io/",
            ],
        )

        with self.assertRaises(SchemaError):
            get_uri(key="uri_error_key_1", value="foo")

        with self.assertRaises(SchemaError):
            get_uri(key="uri_error_key_2", value=1)

        with self.assertRaises(SchemaError):
            get_uri(key="uri_error_key_3", value=False)

        with self.assertRaises(SchemaError):
            get_uri(key="uri_error_key_4", value=["1", "foo"])

        with self.assertRaises(SchemaError):
            get_uri(
                key="uri_list_key_1",
                value=[
                    "user:pass@siteweb.ca",
                    "user2:pass@localhost:8080",
                    "user2:pass@https://quay.io",
                ],
            )

        with self.assertRaises(SchemaError):
            get_uri(
                key="uri_list_error_key_1",
                value=["123", "user:pass@siteweb.ca"],
                is_list=True,
            )

        with self.assertRaises(SchemaError):
            get_uri(
                key="uri_list_error_key_2",
                value=["user:pass@siteweb.ca", 12.3],
                is_list=True,
            )

        with self.assertRaises(SchemaError):
            get_uri(
                key="uri_list_error_key_3",
                value=["user:pass@siteweb.ca", None],
                is_list=True,
            )

        with self.assertRaises(SchemaError):
            get_uri(
                key="uri_list_error_key_4",
                value=["user:pass@siteweb.ca", "123", False],
                is_list=True,
            )

        with self.assertRaises(SchemaError):
            get_uri(key="uri_key_1", value="", is_list=True)

        with self.assertRaises(SchemaError):
            get_uri(key="uri_non_existing_key", value=None)

        with self.assertRaises(SchemaError):
            get_uri(key="uri_non_existing_key", value=NO_VALUE_FOUND)

        with self.assertRaises(SchemaError):
            get_uri(key="uri_non_existing_key", value=None, is_list=True)

        self.assertEqual(
            get_uri(key="uri_non_existing_key", value=None, is_optional=True),
            None,
        )
        with self.assertRaises(SchemaError):
            get_uri(key="uri_key_1", value="Https://user:pass@siteweb.ca", is_list=True)

        self.assertEqual(
            str(
                get_uri(
                    key="uri_non_existing_key",
                    value=None,
                    is_optional=True,
                    default="user2:pass@localhost:8080",
                )
            ),
            "user2:pass@localhost:8080",
        )

        self.assertEqual(
            get_uri(
                key="uri_non_existing_key", value=None, is_list=True, is_optional=True
            ),
            None,
        )
        self.assertEqual(
            [
                str(v)
                for v in get_uri(
                    key="uri_non_existing_key",
                    value=None,
                    is_list=True,
                    is_optional=True,
                    default=[
                        "Https://user:pass@siteweb.causer2:pass@localhost:8080",
                    ],
                )
            ],
            [
                "Https://user:pass@siteweb.causer2:pass@localhost:8080",
            ],
        )

    def test_get_list(self):
        get_list = ConfigParser.parse(List)
        get_list_str = ConfigParser.parse(ListStr)

        value = get_list(
            key="list_key_1", value='["user:pass@siteweb.ca", "pp", "0.1", "foo"]'
        )
        self.assertEqual(value, ["user:pass@siteweb.ca", "pp", "0.1", "foo"])

        with self.assertRaises(SchemaError):
            get_list(
                key="list_key_2", value="user1,user2 , user3,     user4    , user5"
            )
        value = get_list_str(
            key="list_key_2", value="user1,user2 , user3,     user4    , user5"
        )
        self.assertEqual(value, ["user1", "user2", "user3", "user4", "user5"])

        value = get_list(key="list_key_3", value=[False])
        self.assertEqual(value, [False])

        value = get_list(key="list_key_3", value=["false"])
        self.assertEqual(value, ["false"])

        with self.assertRaises(SchemaError):
            get_list(key="list_key_4", value="foo")
        value = get_list_str(key="list_key_4", value="foo")
        self.assertEqual(value, ["foo"])

        with self.assertRaises(SchemaError):
            get_list(key="list_key_5", value="")
        value = get_list_str(key="list_key_5", value="")
        self.assertEqual(value, [])

        with self.assertRaises(SchemaError):
            get_list(key="list_error_key_3", value="null")
        value = get_list_str(key="list_error_key_3", value="null")
        self.assertEqual(value, ["null"])

        with self.assertRaises(SchemaError):
            get_list(key="list_error_key_1", value=True)

        with self.assertRaises(SchemaError):
            get_list(key="list_error_key_2", value={"key": "value"})

        with self.assertRaises(SchemaError):
            get_list(key="list_error_key_4", value=123)

        with self.assertRaises(SchemaError):
            get_list(key="list_non_existing_key", value=None)

        with self.assertRaises(SchemaError):
            get_list(key="list_non_existing_key", value=NO_VALUE_FOUND)

        self.assertEqual(
            get_list(key="list_non_existing_key", value=None, is_optional=True),
            None,
        )
        self.assertEqual(
            get_list(
                key="list_non_existing_key",
                value=None,
                is_optional=True,
                default=["foo"],
            ),
            ["foo"],
        )

    def test_get_wasbs_path(self):
        parse_wasbs_path = ConfigParser.parse(WasbPath)
        # Correct url
        wasbs_path = "wasbs://container@user.blob.core.windows.net/path"
        expected = parse_wasbs_path(key="path", value=wasbs_path)
        assert str(expected) == wasbs_path
        structured = WasbPath.get_structured_value(wasbs_path)
        assert structured == dict(
            container="container", storage_account="user", path="path"
        )

        wasbs_path = "wasbs://container@user.blob.core.windows.net/"
        assert str(parse_wasbs_path(key="path", value=wasbs_path)) == wasbs_path

        wasbs_path = "wasbs://container@user.blob.core.windows.net"
        assert str(parse_wasbs_path(key="path", value=wasbs_path)) == wasbs_path

        wasbs_path = "wasbs://container@user.blob.core.windows.net/path/to/file"
        assert str(parse_wasbs_path(key="path", value=wasbs_path)) == wasbs_path

        # Wrong url
        wasbs_path = "wasbs://container@user.foo.bar.windows.net/path/to/file"
        with self.assertRaises(SchemaError):
            parse_wasbs_path(key="path", value=wasbs_path)

        wasbs_path = "wasbs://container@user.blob.core.foo.net/path/to/file"
        with self.assertRaises(SchemaError):
            parse_wasbs_path(key="path", value=wasbs_path)

        wasbs_path = "wasbs://container@user.blob.windows.net/path/to/file"
        with self.assertRaises(SchemaError):
            parse_wasbs_path(key="path", value=wasbs_path)

    def test_parse_gcs_path(self):
        # Correct url
        gcs_path = "gs://bucket/path/to/blob"
        parse_gcs_path = ConfigParser.parse(GcsPath)
        expected = parse_gcs_path(key="path", value=gcs_path)
        assert str(expected) == gcs_path
        assert GcsPath.get_structured_value(gcs_path) == dict(
            bucket="bucket", blob="path/to/blob"
        )

        # Wrong url
        gcs_path = "gs:/bucket/path/to/blob"
        with self.assertRaises(SchemaError):
            parse_gcs_path(key="path", value=gcs_path)

        # Trailing slash
        gcs_path = "gs://bucket/path/to/blob/"
        expected = parse_gcs_path(key="path", value=gcs_path)
        assert str(expected) == gcs_path

        # Bucket only
        gcs_path = "gs://bucket/"
        expected = parse_gcs_path(key="path", value=gcs_path)
        assert str(expected) == gcs_path

    def test_parse_s3_path(self):
        s3_path = "s3://test/this/is/bad/key.txt"
        parse_s3_path = ConfigParser.parse(S3Path)
        expected = parse_s3_path(key="path", value=s3_path)
        assert str(expected) == s3_path
        assert S3Path.get_structured_value(s3_path) == dict(
            bucket="test", key="this/is/bad/key.txt"
        )

    def test_parse_date(self):
        value = "2010-12-12"
        get_date = ConfigParser.parse(datetime.date)
        parsed_url = get_date(key="date_key", value=value)
        assert parsed_url == datetime.date(2010, 12, 12)

        value = datetime.date(2010, 12, 12)
        parsed_url = get_date(key="date_key", value=value)
        assert parsed_url == value

        value = "2010-12-12-12"
        with self.assertRaises(SchemaError):
            get_date(key="date_key", value=value)

    def test_parse_datetime(self):
        value = "2010-12-12 10:10"
        get_datetime = ConfigParser.parse(datetime.datetime)
        parsed_url = get_datetime(key="date_key", value=value)
        assert parsed_url == datetime.datetime(2010, 12, 12, 10, 10)

        value = "2010-12-12 01:00"
        parsed_url = get_datetime(key="date_key", value=value)
        assert parsed_url == datetime.datetime(2010, 12, 12, 1, 0)

        value = "2010-12-12 01:53:12"
        parsed_url = get_datetime(key="date_key", value=value)
        assert parsed_url == datetime.datetime(2010, 12, 12, 1, 53, 12)

        value = "2014-12-22T03:12:58.019077+00:00"
        parsed_url = get_datetime(key="date_key", value=value)
        assert parsed_url == datetime.datetime(
            2014, 12, 22, 3, 12, 58, 19077, tzinfo=tzutc()
        )

        value = datetime.datetime(2010, 12, 12, 0, 0, 0)
        parsed_url = get_datetime(key="date_key", value=value)
        assert parsed_url == value

        value = datetime.datetime(2010, 12, 12, 0, 0, 0, tzinfo=tzutc())
        parsed_url = get_datetime(key="date_key", value=value)
        assert parsed_url == value

        # Dates are not validate by datetime
        value = "2010-12-12"
        if PYDANTIC_VERSION.startswith("2."):
            value = get_datetime(key="date_key", value=value)
            assert value == datetime.datetime(2010, 12, 12)
        else:
            with self.assertRaises(SchemaError):
                get_datetime(key="date_key", value=value)

    def test_parse_uuid(self):
        value = uuid.uuid4()
        get_uuid = ConfigParser.parse(UUIDStr)
        parsed_uid = get_uuid(key="uuid_key", value=value)
        assert parsed_uid == value.hex

        parsed_uid = get_uuid(key="uuid_key", value=value.hex)
        assert parsed_uid == value.hex

        value = "2sd2"
        with self.assertRaises(SchemaError):
            get_uuid(key="uuid_key", value=value)

        value = "2sd2-sdf"
        with self.assertRaises(SchemaError):
            get_uuid(key="uuid_key", value=value)

    def test_get_image_init(self):
        get_image_init = ConfigParser.parse(ImageStr)
        value = get_image_init(key="dict_key_1", value="foo")
        self.assertEqual(value, "foo")

        value = get_image_init(key="dict_key_1", value={"name": "foo"})
        self.assertEqual(value, "foo")

        value = get_image_init(key="dict_key_1", value="foo:bar")
        self.assertEqual(value, "foo:bar")

        value = get_image_init(
            key="dict_key_1", value={"name": "foo:bar", "connection": "foo"}
        )
        self.assertEqual(value, "foo:bar")

        value = get_image_init(key="dict_key_1", value="https://registry.com/foo:bar")
        self.assertEqual(value, "https://registry.com/foo:bar")

        with self.assertRaises(SchemaError):
            get_image_init(
                key="dict_key_1", value='{"name": "https://registry.com/foo:bar"}'
            )

        value = get_image_init(
            key="dict_list_key_1",
            value=[
                {"name": "https://registry.com/foo:bar"},
                {"name": "test", "connection": "registry"},
                "foo:bar",
            ],
            is_list=True,
        )
        self.assertEqual(
            value,
            [
                "https://registry.com/foo:bar",
                "test",
                "foo:bar",
            ],
        )

        with self.assertRaises(SchemaError):
            get_image_init(key="dict_error_key_2", value=1)

        with self.assertRaises(SchemaError):
            get_image_init(key="dict_error_key_3", value=False)

        with self.assertRaises(SchemaError):
            get_image_init(key="dict_error_key_4", value=["1", "foo"])

        with self.assertRaises(SchemaError):
            get_image_init(key="dict_list_key_1", value=["123", {"key3": True}])

        with self.assertRaises(SchemaError):
            get_image_init(
                key="dict_list_error_key_1", value=["123", {"key3": True}], is_list=True
            )

        with self.assertRaises(SchemaError):
            get_image_init(
                key="dict_list_error_key_2", value=[{"key3": True}, 12.3], is_list=True
            )

        with self.assertRaises(SchemaError):
            get_image_init(
                key="dict_list_error_key_3", value=[{"key3": True}, None], is_list=True
            )

        with self.assertRaises(SchemaError):
            get_image_init(
                key="dict_list_error_key_4",
                value=[{"key3": True}, "123", False],
                is_list=True,
            )

        with self.assertRaises(SchemaError):
            get_image_init(
                key="dict_key_1",
                value={"key1": "foo", "key2": 2, "key3": False, "key4": "1"},
                is_list=True,
            )

        with self.assertRaises(SchemaError):
            get_image_init(key="dict_non_existing_key", value=None)

        with self.assertRaises(SchemaError):
            get_image_init(key="dict_non_existing_key", value=NO_VALUE_FOUND)

        with self.assertRaises(SchemaError):
            get_image_init(key="dict_non_existing_key", value=None, is_list=True)

        self.assertEqual(
            get_image_init(key="dict_non_existing_key", value=None, is_optional=True),
            None,
        )
