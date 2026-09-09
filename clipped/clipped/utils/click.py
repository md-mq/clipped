import click


def apply_click_params(command, *click_params):
    for click_param in click_params:
        command = click_param(command)
    return command


class AliasGroup(click.Group):
    def format_commands(self, ctx, formatter):
        names_by_command = {}
        for name, command in self.commands.items():
            if not command.hidden:
                names_by_command.setdefault(command, []).append(name)

        commands = []
        for command, names in names_by_command.items():
            name = command.name if command.name in names else names[0]
            aliases = sorted(alias for alias in names if alias != name)
            if aliases:
                name = f"{name} (aliases: {', '.join(aliases)})"
            commands.append((name, command))

        if not commands:
            return

        commands.sort(key=lambda item: item[0])
        limit = formatter.width - 6 - max(len(name) for name, _ in commands)
        rows = [(name, command.get_short_help_str(limit)) for name, command in commands]
        with formatter.section("Commands"):
            formatter.write_dl(rows)
