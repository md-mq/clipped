import pytest

import click
from click.testing import CliRunner

from clipped.utils.click import AliasGroup


def test_help_groups_aliases_and_preserves_visible_commands():
    group = AliasGroup("cli")
    project = click.Command("project", help="Commands for projects.")
    group.add_command(project, name="projects")
    group.add_command(project, name="pr")
    group.add_command(project)
    group.add_command(click.Command("status", help="Show status."))
    group.add_command(click.Command("hidden", hidden=True))

    result = CliRunner().invoke(group, ["--help"])

    assert result.exit_code == 0
    commands = result.output.split("Commands:\n", 1)[1]
    assert "project (aliases: pr, projects)" in commands
    assert commands.count("Commands for projects.") == 1
    assert commands.index("project (aliases: pr, projects)") < commands.index("status")
    assert "Show status." in commands
    assert "hidden" not in commands


@pytest.mark.parametrize("command_name", ["project", "projects"])
def test_alias_preserves_arguments_options_and_help(command_name):
    calls = []

    @click.group(cls=AliasGroup)
    def group():
        pass

    @group.command()
    @click.argument("name")
    @click.option("--count", type=int)
    def project(name, count):
        """Commands for projects."""
        calls.append((name, count))

    group.add_command(project, name="projects")
    runner = CliRunner()

    result = runner.invoke(group, [command_name, "owner/project", "--count", "2"])

    assert result.exit_code == 0
    assert calls == [("owner/project", 2)]

    result = runner.invoke(group, [command_name, "--help"])

    assert result.exit_code == 0
    assert "Commands for projects." in result.output
    assert "--count INTEGER" in result.output
    assert calls == [("owner/project", 2)]


def test_help_keeps_distinct_commands_with_the_same_callback():
    def callback():
        pass

    group = AliasGroup("cli")
    group.add_command(click.Command("first", callback=callback, help="Run command."))
    group.add_command(click.Command("second", callback=callback, help="Run command."))

    result = CliRunner().invoke(group, ["--help"])

    assert result.exit_code == 0
    assert "first" in result.output
    assert "second" in result.output
    assert "aliases:" not in result.output


def test_help_uses_first_registration_when_command_name_is_not_registered():
    group = AliasGroup("cli")
    command = click.Command("original")
    group.add_command(command, name="second")
    group.add_command(command, name="first")

    result = CliRunner().invoke(group, ["--help"])

    assert result.exit_code == 0
    assert "second (aliases: first)" in result.output


@pytest.mark.skipif(
    not hasattr(click.Group, "shell_complete"), reason="Requires Click 8 or later"
)
def test_completion_preserves_aliases():
    group = AliasGroup("cli")
    project = click.Command("project")
    group.add_command(project)
    group.add_command(project, name="projects")

    completions = group.shell_complete(click.Context(group), "proj")

    assert [completion.value for completion in completions] == ["project", "projects"]
