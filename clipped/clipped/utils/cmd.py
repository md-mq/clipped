import os
import shlex
from subprocess import PIPE

from psutil import Popen


def run_command(cmd, data, location, chw, env=None):
    cmd_env = None
    if env:
        cmd_env = os.environ.copy()
        cmd_env.update(env)
    cwd = os.getcwd()
    if location is not None and chw is True:
        cwd = location
    elif location is not None and chw is False:
        cmd = "{0} {1}".format(cmd, location)
    r = Popen(
        shlex.split(cmd), stdout=PIPE, stdin=PIPE, stderr=PIPE, cwd=cwd, env=cmd_env
    )
    if data is None:
        output = r.communicate()[0].decode("utf-8")
    else:
        output = r.communicate(input=data)[0]
    return output
