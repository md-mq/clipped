import getpass
import logging
import os
import platform
import socket
import sys
from typing import List, Tuple


_logger = logging.getLogger("clipped.utils.env")


def is_notebook():
    return "ipykernel" in sys.modules


def get_filename():
    if is_notebook():
        return "notebook"
    try:
        return os.path.basename(__file__)
    except Exception as e:
        _logger.debug("Could not detect filename, %s", e)
        return "not found"


def get_module_path():
    try:
        return os.path.dirname(os.path.realpath("__file__"))
    except Exception as e:
        _logger.debug("Could not detect module path, %s", e)
        return "not found"


def get_user():
    try:
        return getpass.getuser()
    except Exception as e:
        _logger.debug("Could not detect installed packages, %s", e)
        return "unknown"


def get_py_packages(packages: List[str]) -> Tuple[List[Tuple[str, str]], dict]:
    def get_from_importlib_metadata():
        try:
            import importlib.metadata as importlib_metadata

            return {
                package.name.lower(): package.version
                for package in importlib_metadata.distributions()
            }
        except ImportError:
            return None

    def get_from_pkg_resources():
        try:
            import pkg_resources

            return {
                package.key: package.version for package in pkg_resources.working_set
            }
        except ImportError:
            return None

    results = get_from_pkg_resources()
    if not results:
        results = get_from_importlib_metadata()

    packages_results = {}
    if packages:
        packages_results = {
            name.lower(): version
            for name, version in results.items()
            if name.lower() in packages
        }

    sorted_results = sorted(results.items())
    return sorted_results, packages_results


def get_run_env(packages: List[str]):
    py_packages, packages_results = get_py_packages(packages)
    data = {
        "pid": os.getpid(),
        "hostname": socket.gethostname(),
        "os": platform.platform(aliased=True),
        "system": platform.system(),
        "python_version_verbose": sys.version,
        "python_version": platform.python_version(),
        "user": get_user(),
        "sys.argv": sys.argv,
        "is_notebook": is_notebook(),
        "filename": get_filename(),
        "module_path": get_module_path(),
        "packages": py_packages,
    }

    for package in packages_results:
        data[f"{package}_version"] = packages_results[package]
    return data
