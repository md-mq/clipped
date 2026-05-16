import sys
from typing import Dict, List, Optional, Union
import yaml

import click
from rich import box
from rich.console import Console
from rich.live import Live
from rich.markdown import Markdown
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)
from rich.syntax import Syntax
from rich.table import Column, Table
from rich.theme import Theme

from clipped.utils.humanize import humanize_attrs
from clipped.utils.json import orjson_dumps, orjson_loads, orjson_pprint_option
from clipped.utils.lists import to_list
from clipped.utils.units import to_unit_memory


class Printer:
    COLORS = ["yellow", "blue", "magenta", "green", "cyan", "red", "white"]
    console = Console(
        theme=Theme(
            {
                "header": "yellow",
                "success": "green",
                "info": "cyan",
                "warning": "magenta",
                "error": "red",
                "white": "white",
            }
        ),
        markup=True,
    )

    @staticmethod
    def get_progress():
        return Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            DownloadColumn(),
            TransferSpeedColumn(),
            TaskProgressColumn(),
            TextColumn("eta"),
            TimeRemainingColumn(),
            TextColumn("elapsed"),
            TimeElapsedColumn(),
        )

    @classmethod
    def get_live(cls):
        return Live(console=cls.console)

    @staticmethod
    def get_table(*args, **kwargs):
        return Table(*[Column(header=h, no_wrap=True) for h in args], **kwargs)

    @staticmethod
    def pprint(value):
        """Prints as formatted JSON"""
        click.echo(orjson_dumps(value, option=orjson_pprint_option))

    @classmethod
    def print_md(cls, md: str):
        cls.console.print(Markdown(md))

    @classmethod
    def print_text(cls, value: str):
        syntax = Syntax(value, "txt", theme="dracula", line_numbers=False)
        cls.console.print(syntax)

    @classmethod
    def print_yaml(cls, value: any):
        if isinstance(value, str):
            value = yaml.safe_load(value)
        value = yaml.safe_dump(value, sort_keys=True, indent=2)
        syntax = Syntax(value, "yaml", theme="dracula", line_numbers=False)
        cls.console.print(syntax)

    @classmethod
    def print_json(cls, value: any):
        if isinstance(value, str):
            value = orjson_loads(value)
        value = orjson_dumps(value, option=orjson_pprint_option)
        syntax = Syntax(value, "json", theme="dracula", line_numbers=False)
        cls.console.print(syntax)

    @classmethod
    def print(cls, text: str):
        cls.console.print(text)

    @classmethod
    def help(cls, command_help: Optional[str] = None):
        if command_help:
            cls.console.print(
                "Please run [white]`{} --help`[/white] for more details".format(
                    command_help
                ),
                style="info",
            )

    @classmethod
    def heading(cls, text: str):
        cls.header("\n{}\n".format(text))

    @classmethod
    def header(cls, text: str):
        cls.console.print(text, style="header")

    @classmethod
    def warning(cls, text: str, command_help: Optional[str] = None):
        cls.console.print(text, style="warning")
        if command_help:
            cls.help(command_help=command_help)

    @classmethod
    def success(cls, text: str):
        cls.console.print(text, style="success")

    @classmethod
    def error(
        cls,
        text: str,
        sys_exit: bool = False,
        command_help: Optional[str] = None,
        **kwargs,
    ):
        cls.console.print(text, style="error")
        if command_help:
            cls.help(command_help)
        if sys_exit:
            sys.exit(1)

    @classmethod
    def tip(cls, text: str):
        cls.console.print(text, style="white")

    @classmethod
    def info(cls, text: str):
        cls.console.print(text, style="info")

    @staticmethod
    def add_log_color(value, color):
        return click.style("{}".format(value), fg=color)

    @classmethod
    def add_color(cls, value, style):
        return "[{style}]{value}[/{style}]".format(value=value, style=style)

    @classmethod
    def get_colored_status(cls, status):
        if status == "created":
            return cls.add_color(status, "info")
        elif status == "succeeded":
            return cls.add_color(status, style="success")
        elif status in ["failed", "stopped", "upstream_failed"]:
            return cls.add_color(status, style="error")
        elif status == "done":
            return cls.add_color(status, style="white")

        return cls.add_color(status, style="header")

    @classmethod
    def add_status_color(cls, obj_dict, status_key="status"):
        if obj_dict.get(status_key) is None:
            return obj_dict

        obj_dict[status_key] = cls.get_colored_status(obj_dict[status_key])
        return obj_dict

    @classmethod
    def add_memory_unit(cls, obj_dict, keys):
        keys = to_list(keys)
        for key in keys:
            obj_dict[key] = to_unit_memory(obj_dict[key])
        return obj_dict

    @classmethod
    def decorate_format_value(
        cls, text_format: str, values: Union[List[str], str], color: str
    ):
        values = to_list(values)
        values = [cls.add_color(value, color) for value in values]
        click.echo(text_format.format(*values))

    @staticmethod
    def log(value, nl=False):
        click.echo(value, nl=nl)

    @classmethod
    def dict_tabulate(cls, dict_value: Dict, is_list_dict: bool = False):
        if is_list_dict:
            headers = dict_value[0].keys() if dict_value else []
            table = cls.get_table(*headers)
            for d in dict_value:
                table.add_row(*d.values())
            cls.print(table)
        else:
            table = cls.get_table(show_header=False, padding=0, box=box.SIMPLE)
            for k, v in dict_value.items():
                table.add_row(k, humanize_attrs(k, v))
            cls.print(table)
