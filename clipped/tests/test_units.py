from unittest import TestCase

from clipped.utils.units import (
    format_sizeof,
    is_cpu_value,
    is_memory_value,
    number_percentage_format,
    to_cpu_value,
    to_memory_bytes,
    to_percentage,
    to_unit_memory,
)


class ToPercentageTest(TestCase):
    """A test case for the `to_percentage`."""

    def test_number_format_works_as_expected(self):
        float_nums = [
            (123.123, "123.12"),
            (123.1243453, "123.12"),
            (213213213.123, "213,213,213.12"),
        ]
        int_nums = [(213214, "213,214"), (123213.00, "123,213")]

        for num, expected in float_nums:
            self.assertEqual(
                number_percentage_format(num, precision=2, use_comma=True), expected
            )

        for num, expected in int_nums:
            self.assertEqual(
                number_percentage_format(num, precision=2, use_comma=True), expected
            )

    def test_number_percentage_format_simple(self):
        self.assertEqual(number_percentage_format(50), 50)
        self.assertEqual(number_percentage_format(50.55, 2), "50.55")
        self.assertEqual(number_percentage_format(50.555, 2), "50.55")
        self.assertEqual(number_percentage_format(50.555, 4, True), "50.5550")

    def test_get_percentage_works_as_expected(self):
        float_nums = [
            (0.123, "12.30%"),
            (3.1243453, "312.43%"),
            (213.12312, "21,312.31%"),
        ]

        int_nums = [(0.14, "14%"), (1.300, "130%")]

        for num, expected in float_nums:
            self.assertEqual(
                to_percentage(num, rounding=2, precision=2, use_comma=True), expected
            )

        for num, expected in int_nums:
            self.assertEqual(
                to_percentage(num, rounding=2, precision=2, use_comma=True), expected
            )

    def test_to_percentage_simple(self):
        self.assertEqual(to_percentage(0.5), "50%")
        self.assertEqual(to_percentage(0.555, 2), "55.5%")
        self.assertEqual(to_percentage(0.555, 3), "55.5%")
        self.assertEqual(to_percentage(0.5555, 3), "55.55%")
        self.assertEqual(to_percentage(0.5558, 5), "55.58%")

    def test_works_as_expected_for_valid_values(self):
        test_data = [
            (0, "0%"),
            (0.25, "25%"),
            (-0.25, "-25%"),
            (12, "1200%"),
            (0.123, "12.3%"),
            (0.12345, "12.35%"),
            (0.12001, "12%"),
            (0.12101, "12.1%"),
            ("0", "0%"),
            ("0.25", "25%"),
            (3.1243453, "312.43%"),
            (213.12312, "21312.31%"),
            (0.14, "14%"),
            (1.300, "130%"),
        ]
        for value, expected in test_data:
            result = to_percentage(value)
            self.assertEqual(result, expected)

    def test_works_as_expected_for_precision(self):
        test_data = [
            (0, "0%"),
            (0.25, "25%"),
            (-0.25, "-25%"),
            (12, "1200%"),
            (0.123, "12.300%"),
            (0.12345, "12.345%"),
            (0.12001, "12.001%"),
            (0.12101, "12.101%"),
            ("0", "0%"),
            ("0.25", "25%"),
            (3.1243453, "312.435%"),
            (213.12312, "21,312.312%"),
            (0.14, "14%"),
            (1.300, "130%"),
        ]
        for value, expected in test_data:
            result = to_percentage(value, rounding=3, precision=3, use_comma=True)
            self.assertEqual(result, expected)

    def test_raises_value_error_for_invalid_types(self):
        with self.assertRaises(ValueError):
            to_percentage("foo")

    def test_format_sizeof(self):
        assert format_sizeof(10) == "10.0B"
        assert format_sizeof(10000) == "9.8KiB"
        assert format_sizeof(100000) == "97.7KiB"
        assert format_sizeof(10000000) == "9.5MiB"
        assert format_sizeof(10000000000) == "9.3GiB"

        self.assertEqual(format_sizeof(500), "500.0B")
        self.assertEqual(format_sizeof(1500), "1.5KiB")
        self.assertEqual(format_sizeof(1_500_000), "1.4MiB")
        self.assertEqual(format_sizeof(1_500_000_000), "1.4GiB")

    def test_to_cpu_value(self):
        self.assertEqual(to_cpu_value(0.5), 0.5)
        self.assertEqual(to_cpu_value("0.5"), 0.5)
        self.assertEqual(to_cpu_value("500m"), 0.5)
        self.assertEqual(to_cpu_value("500u"), 0.0005)
        self.assertEqual(to_cpu_value("500n"), 5e-07)

    def test_to_memory_bytes(self):
        self.assertEqual(to_memory_bytes(1500), 1500)
        self.assertEqual(to_memory_bytes("1k"), 1000)
        self.assertEqual(to_memory_bytes("1m"), 1000000)
        self.assertEqual(to_memory_bytes("1g"), 1000000000)
        self.assertEqual(to_memory_bytes("1ki"), 1024)
        self.assertEqual(to_memory_bytes("1mi"), 1048576)
        self.assertEqual(to_memory_bytes("1gi"), 1073741824)

    def test_is_cpu_value(self):
        for value in ("2", "0.5", ".5", "2.", "500m", "500u", "500n"):
            assert is_cpu_value(value), value
            to_cpu_value(value)
        for value in ("", "m", "1k", "1M", "1e3", "1_000", "nan", "-1", "1 ", "١"):
            assert not is_cpu_value(value), value

    def test_is_memory_value(self):
        for value in ("512", "1.5Gi", "1Ki", "1Ei", "1k", "1M", "1G", "1E"):
            assert is_memory_value(value), value
            assert to_memory_bytes(value) > 0
        for value in ("", "Gi", "400m", "1mi", "1K", "1e3", "1_000", "-1", "١Gi"):
            assert not is_memory_value(value), value

    def test_to_unit_memory(self):
        def validate(use_i: bool):
            suffix = "i" if use_i else ""
            self.assertEqual(
                to_unit_memory(500, use_i=use_i), "0.49 K{}".format(suffix)
            )
            self.assertEqual(
                to_unit_memory(1500000, use_i=use_i), "1.43 M{}".format(suffix)
            )
            self.assertEqual(
                to_unit_memory(1500000000, use_i=use_i), "1.4 G{}".format(suffix)
            )
            self.assertEqual(
                to_unit_memory(1500000000000, use_i=use_i), "1.36 T{}".format(suffix)
            )

        validate(use_i=True)
        validate(use_i=False)
