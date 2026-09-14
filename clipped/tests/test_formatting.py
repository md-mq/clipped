from io import StringIO
import pytest
from unittest.mock import patch

from rich.console import Console
from rich.text import Text
from rich.theme import Theme

from clipped.formatting import Printer
from clipped.utils.json import orjson_loads


UUIDS = (
    "8aac02e3a62a4f0aaa257c59da5eab80",
    "85f07474-715c-4f04-b801-dbd0466d749e",
)


def render_table(rows, width, color=False, **kwargs):
    output = StringIO()
    console = Console(
        file=output,
        width=width,
        force_terminal=color,
        color_system="standard" if color else None,
        theme=Theme({"success": "green"}),
    )
    with patch.object(Printer, "console", console):
        Printer.dict_tabulate(rows, is_list_dict=True, **kwargs)
    return output.getvalue()


@pytest.mark.parametrize("width", [20, 80, 160])
def test_full_width_columns_preserve_longest_uuid(width):
    rows = [
        {
            "UUID": uuid,
            "name": "long-operation-name-" * 20,
            "in.parameter": "long-input-value-" * 20,
            "out.result": "long-output-value-" * 20,
        }
        for uuid in UUIDS
    ]

    output = render_table(rows, width, full_width_columns=["UUID"])

    for uuid in UUIDS:
        assert uuid in output


@pytest.mark.parametrize("width", [1, 80])
def test_full_width_columns_survive_many_adjacent_columns(width):
    rows = [
        {
            **{f"in.parameter_{index}": "x" * 200 for index in range(20)},
            "UUID": uuid,
        }
        for uuid in UUIDS
    ]

    output = render_table(rows, width, full_width_columns=["UUID"])

    for uuid in UUIDS:
        assert uuid in output
    assert any(len(line) > width for line in output.splitlines())


def test_table_without_full_width_columns_keeps_terminal_width():
    rows = [{"UUID": UUIDS[0]}]

    output = render_table(rows, 20)

    assert UUIDS[0] not in output
    assert max(map(len, output.splitlines())) <= 20
    assert render_table(rows, 20, full_width_columns=[]) == output


def test_full_width_columns_do_not_add_missing_columns():
    rows = [{"name": "long-operation-name-" * 20}]

    output = render_table(rows, 20, full_width_columns=["UUID"])

    assert "UUID" not in output
    assert output == render_table(rows, 20)


def test_full_width_columns_preserve_empty_table_output():
    assert render_table([], 20, full_width_columns=["UUID"]) == render_table([], 20)


def test_full_width_columns_preserve_status_color():
    rows = [Printer.add_status_color({"UUID": UUIDS[1], "status": "succeeded"})]

    output = render_table(rows, 80, color=True, full_width_columns=["UUID"])

    assert UUIDS[1] in output
    assert "\x1b[32msucceeded\x1b[0m" in output


@pytest.mark.parametrize("is_list_dict", [False, True])
def test_stderr_sections_preserve_json_stdout(is_list_dict, capsys):
    Printer.pprint({"results": []})
    Printer.heading("Context:", err=True)
    fields = {"Owner": "owner", "Project": "project-a"}
    Printer.dict_tabulate(
        [fields] if is_list_dict else fields, is_list_dict=is_list_dict, err=True
    )

    captured = capsys.readouterr()
    assert orjson_loads(captured.out) == {"results": []}
    assert "Context:" in captured.err
    assert "Owner" in captured.err
    assert "owner" in captured.err
    assert "Project" in captured.err
    assert "project-a" in captured.err


def test_sections_still_default_to_stdout(capsys):
    Printer.heading("Run info:")
    Printer.dict_tabulate({"uuid": "run-uuid"})

    captured = capsys.readouterr()
    assert captured.err == ""
    assert "Run info:" in captured.out
    assert "uuid" in captured.out
    assert "run-uuid" in captured.out


def test_dict_tabulate_preserves_styled_literal_values(capsys):
    path = "/work/[red]/:rocket:/.polyaxon/.project"
    Printer.dict_tabulate({"Source": Text(path, style="dim")}, err=True)

    captured = capsys.readouterr()
    assert captured.out == ""
    assert path in captured.err
